"""Do the analysers actually find anything? Asked of a live target.

Every other test in this suite exercises a pure function. That is how a run
could finish with 2600 tests green and an empty Findings page: each piece was
right and nothing ever ran the chain against a server.

This starts a deliberately weak API on localhost, seeds the traffic the proxy
would have captured, runs all seven analysers we added for real against a real
Postgres, and then validates the result - the whole path from a request to the
row the Findings page reads.

It SKIPS when no database is reachable, so the ordinary unit run is unaffected:

    DATABASE_URL=postgresql://syphax:syphax@127.0.0.1:5432/syphax \
        python -m pytest tests/live -q

or inside the stack, where the variable is already set:

    docker compose exec -T worker python -m pytest tests/live -q
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import threading
import time
import uuid

import pytest

HOST = "127.0.0.1"


def _free_port() -> int:
    """A port nothing else holds.

    Hardcoding one produced a false green the first time this ran: another
    server was already on 8899, uvicorn exited with STARTUP_FAILURE, the
    readiness check saw something listening and every assertion below passed
    against a server the test did not start.
    """
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def _reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    # conftest sets a placeholder so imports work; it points at nothing.
    return "" if (not url or "test:test@" in url) else url


pytestmark = pytest.mark.skipif(
    not _database_url(),
    reason="needs a real DATABASE_URL; see this module's docstring")


# --------------------------------------------------------------------------
# the target


@pytest.fixture(scope="module")
def target():
    """The weak API, served on localhost for the length of the module."""
    import uvicorn

    from tests.live.weak_target import app

    port = _free_port()
    assert not _reachable(HOST, port, 0.2), "the chosen port is not free"
    config = uvicorn.Config(app, host=HOST, port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://{HOST}:{port}"
    for _ in range(100):
        if server.started:
            break
        if not thread.is_alive():
            pytest.fail("the weak target's server thread died on startup")
        time.sleep(0.1)
    else:
        server.should_exit = True
        pytest.fail(f"the weak target never came up on {base}")
    _BASE["url"] = base
    _BASE["port"] = port
    yield base
    server.should_exit = True
    thread.join(timeout=5)


# Set by the fixture; the helpers below need the port it actually bound.
_BASE: dict = {"url": "", "port": 0}


# --------------------------------------------------------------------------
# the run


async def _seed_flows(conn, spec_body: str):
    """The traffic the capture proxy would have recorded."""
    base, port = _BASE["url"], _BASE["port"]

    async def flow(method, path, *, status=200, req=None, req_ct=None,
                   resp=None, resp_ct="application/json"):
        await conn.execute(
            'INSERT INTO flows (id, "timestamp", method, scheme, host, port,'
            ' path, url, request_body, request_content_type, status_code,'
            ' response_body, response_content_type, response_size)'
            ' VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)',
            uuid.uuid4().hex, time.time(), method, "http", HOST, port,
            path.split("?")[0], base + path,
            req.encode() if req else None, req_ct, status,
            resp.encode() if resp else None, resp_ct, len(resp or ""))

    await flow("GET", "/", resp="<html>..</html>", resp_ct="text/html")
    await flow("GET", "/api/v2/users/42", status=401,
               resp='{"error":"authentication required"}')
    await flow("GET", "/api/items?q=a&page=1", resp='{"items":[],"page":1}')
    await flow("POST", "/api/notes", status=201, req='{"title":"ma note"}',
               req_ct="application/json",
               resp='{"id":4820,"title":"ma note"}')
    await flow("GET", "/openapi.json", resp=spec_body)


async def _run_everything(spec_body: str):
    import app.audit  # noqa: F401
    import app.auth.storage  # noqa: F401
    import app.engagements.storage  # noqa: F401
    import app.events  # noqa: F401
    import app.llm.usage  # noqa: F401
    import app.memory  # noqa: F401
    import app.network.shared_state  # noqa: F401
    import app.orchestrator.approvals  # noqa: F401
    import app.orchestrator.runs  # noqa: F401
    import app.orchestrator.state  # noqa: F401
    import app.proxy.storage  # noqa: F401
    import app.sandbox.staging  # noqa: F401
    import app.scans.storage  # noqa: F401
    import app.validation.storage  # noqa: F401
    from app import db
    from app.engagements import EngagementRepository
    from app.engagements.models import Engagement, EngagementStatus

    await db.init_db()

    eng = Engagement.create(_BASE["url"], title="live-suite", scope_hosts=[HOST],
                            attested=True, allow_active_exploit=True,
                            allow_data_proof=True)
    eng.status = EngagementStatus.AUTHORIZED
    repo = EngagementRepository()
    await repo.create(eng)
    await repo.update(eng)

    async with db.acquire() as conn:
        await conn.execute("TRUNCATE flows")
        await _seed_flows(conn, spec_body)

    from app.analysis.api_inventory import analyze_api_inventory
    from app.analysis.api_sequences import analyze_api_sequences
    from app.analysis.graphql import analyze_graphql
    from app.analysis.mass_assignment import analyze_mass_assignment
    from app.analysis.openapi_synth import synthesise
    from app.analysis.rate_limit import analyze_rate_limit
    from app.analysis.schema_audit import analyze_schema

    summary = {
        "openapi_synth": await synthesise(eng.id),
        "api_inventory": await analyze_api_inventory(eng.id),
        "schema_audit": await analyze_schema(eng.id),
        "graphql": await analyze_graphql(eng.id),
        "mass_assignment": await analyze_mass_assignment(eng.id),
        "rate_limit": await analyze_rate_limit(eng.id),
        "api_sequences": await analyze_api_sequences(eng.id),
    }

    async with db.acquire() as conn:
        rows = await conn.fetch(
            "SELECT tool, findings_json FROM jobs WHERE engagement_id=$1",
            eng.id)
    raw = []
    for row in rows:
        for item in json.loads(row["findings_json"] or "[]"):
            item["_tool"] = row["tool"]
            raw.append(item)

    from app.validation import validate_engagement
    stats = await validate_engagement(eng.id)
    async with db.acquire() as conn:
        validated = [dict(r) for r in await conn.fetch(
            "SELECT severity, status, vuln_class, tool, title "
            "FROM validated_findings WHERE engagement_id=$1", eng.id)]

    await db.close_pool()
    return summary, raw, stats, validated


@pytest.fixture(scope="module")
def outcome(target):
    import urllib.request
    spec_body = urllib.request.urlopen(
        target + "/openapi.json", timeout=5).read().decode()
    return asyncio.run(_run_everything(spec_body))


def _classes(raw):
    return {(f["_tool"], (f.get("metadata") or {}).get("vuln_class"))
            for f in raw}


# --------------------------------------------------------------------------
# what each analyser must find


def test_the_target_really_is_weak(target):
    """Guard the fixture. If the target stopped being vulnerable, every
    assertion below would pass for the wrong reason."""
    import urllib.request
    with urllib.request.urlopen(target + "/api/v1/users/42", timeout=5) as r:
        assert r.status == 200          # the forgotten version answers
    try:
        urllib.request.urlopen(target + "/api/v2/users/42", timeout=5)
        pytest.fail("/api/v2 should require authentication")
    except urllib.error.HTTPError as exc:
        assert exc.code == 401


def test_a_schema_is_synthesised_from_the_captured_traffic(outcome):
    summary, _raw, _stats, _vf = outcome
    assert summary["openapi_synth"]["operations"] >= 3
    assert summary["openapi_synth"]["path"].endswith("observed.json")


def test_the_forgotten_version_is_found_and_rated_as_a_break(outcome):
    """/api/v2 answers 401 and /api/v1 answers 200: an authentication bypass
    with a version number, not an inventory note."""
    _summary, raw, _stats, _vf = outcome
    hits = [f for f in raw if f["_tool"] == "api_inventory"]
    assert hits, "the shadow API hunt found nothing"
    assert any(f["severity"] == "high"
               and (f.get("metadata") or {}).get("vuln_class")
               == "broken_access_control" for f in hits)
    assert any("/api/v1/users" in f["target"] for f in hits)


def test_the_published_contract_is_audited(outcome):
    _summary, raw, _stats, _vf = outcome
    kinds = {(f.get("metadata") or {}).get("kind")
             for f in raw if f["_tool"] == "schema_audit"}
    for expected in ("security_opt_out", "weak_scheme",
                     "no_throttling_documented", "open_request_body",
                     "unbounded_input"):
        assert expected in kinds, f"schema_audit missed {expected}: {kinds}"


def test_graphql_is_taken_past_introspection(outcome):
    """The five checks that matter, on one endpoint."""
    _summary, raw, _stats, _vf = outcome
    kinds = {(f.get("metadata") or {}).get("kind")
             for f in raw if f["_tool"] == "graphql"}
    for expected in ("introspection", "suggestions", "aliases",
                     "duplicate_directives", "console"):
        assert expected in kinds, f"graphql missed {expected}: {kinds}"


def test_mass_assignment_is_confirmed_by_the_echo(outcome):
    _summary, raw, _stats, _vf = outcome
    hits = [f for f in raw if f["_tool"] == "mass_assignment"]
    assert hits, "nothing was injected"
    confirmed = [f for f in hits
                 if (f.get("metadata") or {}).get("status") == "confirmed"]
    assert confirmed, f"the echo was not recognised: {hits}"
    assert confirmed[0]["severity"] == "high"
    assert (confirmed[0].get("metadata") or {}).get("property") == "is_admin"


def test_the_missing_rate_limit_is_measured_not_asserted(outcome):
    _summary, raw, _stats, _vf = outcome
    hits = [f for f in raw if f["_tool"] == "rate_limit"]
    assert hits
    assert "20 requests" in hits[0]["title"]
    assert hits[0]["metadata"]["requests_sent"] == 20


def test_the_stateful_sequence_proves_object_access(outcome):
    """Create, learn the id, read it back with no credential, recognise our
    own marker. The strongest oracle in the suite."""
    _summary, raw, _stats, _vf = outcome
    hits = [f for f in raw if f["_tool"] == "api_sequences"]
    classes = {(f.get("metadata") or {}).get("vuln_class") for f in hits}
    assert "broken_access_control" in classes, hits
    assert "idor" in classes, "the neighbouring identifier was not probed"
    assert all(f["severity"] == "high" for f in hits)


def test_every_analyser_produced_something(outcome):
    _summary, raw, _stats, _vf = outcome
    tools = {f["_tool"] for f in raw}
    for tool in ("api_inventory", "schema_audit", "graphql", "mass_assignment",
                 "rate_limit", "api_sequences"):
        assert tool in tools, f"{tool} found nothing on a target built for it"


# --------------------------------------------------------------------------
# and it all reaches the Findings page


def test_nothing_is_lost_between_the_scan_and_the_findings_page(outcome):
    """The screenshot that started this: 206 jobs, zero findings. The page
    reads validated_findings, so every link in the chain has to hold."""
    _summary, raw, _stats, validated = outcome
    assert len(validated) == len(raw), (
        f"{len(raw)} findings became {len(validated)} rows")


def test_they_are_confirmed_rather_than_guessed(outcome):
    """These analysers hold the response that proves each claim, so the
    validator must keep their verdict instead of re-deriving a weaker one."""
    _summary, _raw, stats, validated = outcome
    assert stats["confirmed"] >= 15
    assert stats["false_positive"] == 0
    assert {v["status"] for v in validated} == {"confirmed"}


def test_the_high_severity_findings_are_the_access_control_ones(outcome):
    _summary, _raw, _stats, validated = outcome
    high = {v["vuln_class"] for v in validated if v["severity"] == "high"}
    assert "broken_access_control" in high
    assert "mass_assignment" in high
    assert "idor" in high
