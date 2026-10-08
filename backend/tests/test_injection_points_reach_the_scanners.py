"""Why a target full of SQLi reported nothing above "info".

Seven catalog items - sqlmap (EXP-SQLI), commix (EXP-CMDI) and the nuclei
-dast runs for SSRF, SSTI, LFI, XXE, open redirect and CRLF - carry
`applies_when={"requires_params": True}`. That is true only of an endpoint
ASSET whose URL already carries a query string, and `has_params` is derived
from the literal `?a=b` in the asset's value.

So the whole injection half of the methodology hangs on one thing: something
has to create a parameterised endpoint asset. Three separate defects meant
nothing ever did, and the consequence was not "fewer findings" but "no
injection test was planned at all" - and then zero exploitation, because
strategy.is_exploitable discards `severity == "info"`.
"""
from __future__ import annotations

import asyncio
import inspect as _inspect
from types import SimpleNamespace

import pytest

from app.orchestrator.executor import Executor


class _FakeState:
    """Records assets instead of writing them, and derives has_params the way
    EngagementState.add_asset does."""

    def __init__(self, engagement_id="eng_1"):
        self.engagement_id = engagement_id
        self.assets_added = []
        self.fingerprints = []

    async def add_asset(self, kind, value, *, source=None):
        from urllib.parse import parse_qs, urlparse
        self.assets_added.append({
            "kind": kind, "value": value, "source": source,
            "has_params": bool(parse_qs(urlparse(value).query)),
        })

    async def add_fingerprint(self, tech, *, source=None):
        self.fingerprints.append(tech)


def _executor(scope=("testfire.net",), monkeypatch=None):
    import app.orchestrator.executor as ex

    if monkeypatch is not None:
        monkeypatch.setattr(ex, "get_runner", lambda: None)
    state = _FakeState()
    e = Executor.__new__(Executor)
    e.state = state
    e.runner = None
    e._eng = SimpleNamespace(
        id="eng_1", target_host="testfire.net",
        scope_hosts=list(scope),
        host_in_scope=lambda h: any(h == s or h.endswith("." + s) for s in scope),
    )
    e.retries_launched = 0
    return e, state


def _job(tool):
    return SimpleNamespace(id="job_1", tool=tool, target="https://testfire.net/",
                           catalog_item_id="MAP-HIDDEN-PARAMS")


def _finding(target, meta):
    return SimpleNamespace(target=target, metadata=meta, severity="info",
                           title="t", description="d", evidence="e")


async def _ingest(executor, tool, finding, monkeypatch):
    # events.emit writes to the DB; the assertions are about assets.
    import app.orchestrator.executor as ex

    async def _emit(*a, **k):
        return None

    monkeypatch.setattr(ex.events, "emit", _emit)
    await executor._ingest_finding(_job(tool), finding)


# ---- defect 1: the asset contract had two producers and no consumer --------

def test_arjuns_discovered_parameters_become_an_asset(monkeypatch):
    """arjun IS the tool for this: MAP-HIDDEN-PARAMS, "the injection points
    every later test needs". Its wrapper re-emits the endpoint with the
    parameters attached and declares it in metadata["asset"]/["asset_kind"] -
    and the ingest allowlisted katana/gau/ffuf BY TOOL NAME, so arjun's output
    was dropped. Nothing read those two keys anywhere in the codebase."""
    e, state = _executor(monkeypatch=monkeypatch)
    url = "https://testfire.net/search.jsp?query=1"
    f = _finding(url, {"tool": "arjun", "vuln_class": "recon", "param": "query",
                       "asset": url, "asset_kind": "endpoint"})
    asyncio.run(_ingest(e, "arjun", f, monkeypatch))

    endpoints = [a for a in state.assets_added if a["kind"] == "endpoint"]
    assert endpoints, "arjun found an injection point and no asset was created"
    assert endpoints[0]["has_params"] is True, \
        "the asset carries no query string, so every injection item skips it"


def test_jsluice_urls_with_params_become_an_asset(monkeypatch):
    e, state = _executor(monkeypatch=monkeypatch)
    url = "https://testfire.net/api/account?id=1"
    f = _finding(url, {"tool": "jsluice", "params": ["id"],
                       "asset": url, "asset_kind": "endpoint"})
    asyncio.run(_ingest(e, "jsluice", f, monkeypatch))
    assert any(a["has_params"] for a in state.assets_added)


def test_a_declared_asset_on_a_foreign_host_is_refused(monkeypatch):
    """jsluice pulls URLs out of JavaScript and those name any host - a CDN, a
    third-party API, the vendor's SaaS. An asset is what later phases aim tools
    at, so scope is enforced here. Scope is the authorization."""
    e, state = _executor(monkeypatch=monkeypatch)
    f = _finding("https://cdn.googleapis.com/x?k=1",
                 {"tool": "jsluice", "asset": "https://cdn.googleapis.com/x?k=1",
                  "asset_kind": "endpoint"})
    asyncio.run(_ingest(e, "jsluice", f, monkeypatch))
    assert state.assets_added == [], "an out-of-scope host became a scan target"


def test_a_declared_asset_that_is_not_a_url_is_refused(monkeypatch):
    e, state = _executor(monkeypatch=monkeypatch)
    f = _finding("x", {"tool": "arjun", "asset": "not a url",
                       "asset_kind": "endpoint"})
    asyncio.run(_ingest(e, "arjun", f, monkeypatch))
    assert state.assets_added == []


def test_the_asset_contract_has_a_consumer():
    """Both producers wrote metadata["asset_kind"] and nothing read it. An
    invariant, so a third producer cannot be added into the same silence."""
    import pathlib

    root = pathlib.Path(_inspect.getfile(Executor)).resolve().parents[2]
    producers = set()
    for path in (root / "app").rglob("*.py"):
        text = path.read_text()
        if '"asset_kind"' in text and "wrappers" in str(path):
            producers.add(path.name)
    assert producers, "no wrapper declares an asset any more; drop this test"
    consumer = (root / "app" / "orchestrator" / "executor.py").read_text()
    assert 'meta.get("asset_kind")' in consumer, \
        f"{sorted(producers)} declare assets that the ingest never creates"


# ---- defect 2: the pass that finds parameters ran after every scan ---------

def test_parameters_are_discovered_before_the_injection_tests_are_planned():
    """analyze_params seeds parameterised endpoint assets - its own docstring
    says it exists so "the param-gated exploitation items (sqlmap / dalfox /
    nuclei -dast) test them". It ran only in run_analysis, during finalisation,
    after every scan phase had been planned and run. Its seeds could therefore
    only help a SECOND run."""
    from app.orchestrator import loop

    src = _inspect.getsource(loop.run_engagement_loop)
    assert "_discover_params(" in src, \
        "nothing discovers parameters while the plan can still change"
    # It has to be on the vuln-phase transition, alongside the JS cache - the
    # documented moment "still early enough for the leads to change what gets
    # scanned".
    assert src.index("_materialise_js(engagement, run)") < src.index(
        "_discover_params(engagement, run)") < src.index("_run_correlation("), \
        "parameter discovery is not on the vuln-phase transition"


def test_it_still_runs_in_the_analysis_phase_too():
    """The later call sees the traffic the scan itself captured."""
    from app.analysis import run_analysis

    assert "analyze_params" in _inspect.getsource(run_analysis)


# ---- defect 3: it only ever looked at captured proxy traffic --------------

def test_parameter_discovery_does_not_need_someone_to_have_browsed_the_target():
    """Candidates came from FlowRepository alone. On an automated run nobody
    browses the target through the MITM, so there were no flows, so nothing was
    probed, so no parameterised asset was seeded - on any first run, for any
    target. The endpoints the crawl already found are in scope by construction
    and are perfectly good candidates."""
    from app.analysis import param_discovery

    src = _inspect.getsource(param_discovery.analyze_params)
    assert "EngagementState" in src and 'assets("endpoint")' in src, \
        "the probe still depends entirely on captured proxy traffic"


def test_parameter_discovery_says_when_it_found_nothing():
    """Every injection test depends on this pass and it emitted nothing, so
    "no injection task was planned" had no explanation anywhere."""
    from app.analysis import param_discovery

    src = _inspect.getsource(param_discovery.analyze_params)
    assert "events.emit" in src
    assert "applies only to an endpoint with parameters" in src


# ---- the consequence these three had in common ----------------------------

# The exact cost of the three defects above, measured rather than assumed.
# sqlmap (--forms), dalfox, nosqli and the generic nuclei -dast run on ANY
# endpoint - they mine parameters themselves - so SQLi and XSS are NOT in this
# list. What was lost is command injection and six nuclei -dast families,
# which is most of what the operator asked for: RCE and LFI above all.
_PARAM_GATED = ["EXP-CMDI", "EXP-SSRF", "EXP-SSTI", "EXP-LFI", "EXP-XXE",
                "EXP-REDIRECT", "EXP-CRLF"]


@pytest.mark.parametrize("item_id", _PARAM_GATED)
def test_each_param_gated_item_needs_a_parameterised_asset(item_id):
    from app.methodology.catalog import CATALOG_BY_ID, applies

    item = CATALOG_BY_ID[item_id]
    bare = {"is_host": False, "requires_params": False,
            "url": "https://testfire.net/search.jsp", "source": "katana", "tech": []}
    with_params = {**bare, "requires_params": True,
                   "url": "https://testfire.net/search.jsp?query=1"}
    assert applies(item, bare) is False, \
        f"{item_id} is no longer param-gated; _PARAM_GATED is stale"
    assert applies(item, with_params) is True


def test_the_param_gated_list_is_still_accurate():
    """A guard on the comment above: if someone adds a param gate to sqlmap or
    dalfox, the diagnosis in this file stops being true and should be re-read."""
    from app.methodology.catalog import CATALOG

    gated = sorted(i.id for i in CATALOG
                   if (i.applies_when or {}).get("requires_params"))
    assert gated == sorted(_PARAM_GATED), (
        f"the set of param-gated items changed to {gated}; re-check which "
        f"vulnerability classes a missing parameterised asset now costs")


def test_sqli_and_xss_do_not_depend_on_a_parameterised_asset():
    """Stated explicitly because it bounds the diagnosis: these two run on any
    endpoint, so if a target full of SQLi reports none, the cause is NOT the
    missing parameter asset and has to be looked for elsewhere."""
    from app.methodology.catalog import CATALOG_BY_ID, applies

    bare = {"is_host": False, "requires_params": False,
            "url": "https://testfire.net/bank/login.jsp", "source": "katana",
            "tech": []}
    for item_id in ("EXP-SQLI", "EXP-XSS"):
        assert applies(CATALOG_BY_ID[item_id], bare) is True, item_id


# ---- a run that never reached exploitation said nothing about it -----------

def test_a_run_that_stopped_on_its_budget_says_so():
    """limits_for named only exploit_denied/stopped/cancelled. A run that spent
    its job or time budget during mapping never plans the vuln or exploitation
    phases - the normal outcome on a target whose crawl finds many endpoints -
    and the panel printed nothing at all."""
    from app.validation.limits import limits_for

    keys = {limit.key for limit in limits_for(
        allow_active_exploit=True, stop_reason="job_budget",
        reached_exploitation=False, last_phase="mapping")}
    assert "job_budget_spent" in keys
    assert "exploitation_never_started" in keys


def test_the_headline_comes_first():
    """Every other explanation is secondary to "the phase that proves things
    never started"."""
    from app.validation.limits import limits_for

    limits = limits_for(allow_active_exploit=True, stop_reason="time_budget",
                        reached_exploitation=False, last_phase="recon",
                        tools_unavailable=["wpscan"])
    assert limits[0].key == "exploitation_never_started"
    assert "recon" in limits[0].why


def test_an_unknown_phase_history_claims_nothing():
    """None must not be read as False: a caller that does not track phases must
    not make the panel assert the exploitation phase was skipped."""
    from app.validation.limits import limits_for

    keys = {limit.key for limit in limits_for(
        allow_active_exploit=True, stop_reason="", reached_exploitation=None)}
    assert "exploitation_never_started" not in keys


def test_the_loop_reports_the_phases_it_reached():
    from app.orchestrator import loop

    src = _inspect.getsource(loop.run_engagement_loop)
    assert "phases_seen.add(current_phase)" in src
    assert "phases_seen=phases_seen" in src


def test_an_info_finding_is_never_exploited():
    """Closes the loop: info-only detection means zero exploitation, whatever
    the sandbox does. The three defects above are upstream of every fix made to
    the proof path."""
    from app.exploit.strategy import is_exploitable

    ok, why = is_exploitable({"vuln_class": "sql_injection", "status": "likely",
                              "severity": "info"})
    assert ok is False
    assert "severity" in why
