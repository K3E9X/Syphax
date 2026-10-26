"""Stateful API testing: the bug that needs two requests in the right order.

This is the gap RESTler exists to fill, and RESTler is not shipped. The real
numbers, measured rather than estimated, are in the commit message; the short
version is that the official image is Alpine/musl (so its binaries will not
run in our Debian worker), it carries .NET 6.0.27 - out of support since
November 2024 - and reaching it as a sidecar would mean handing the worker the
Docker socket, which is root on the host. Building it from source means owning
a retarget to .NET 8 and shipping a write-heavy fuzzer that sends PUT and
DELETE by default, against the gating the rest of this suite is built on.

So the one thing RESTler has that nothing else here does is implemented
directly: a SEQUENCE. Every other check in the suite sends one request and
reads one response. This one creates an object, learns its identity from the
response, and then asks a second question about it - which is how the strongest
authorisation findings are actually established.

    POST /api/notes {"title": "<marker>"}   -> 201 {"id": 4821, ...}
    GET  /api/notes/4821                     (no credential at all)
    -> 200, and the body contains our marker

That is broken object level authorisation (API1) proven to a standard nothing
else here reaches: we know the object's id because the API told us, and we know
the content because we wrote it. There is no inference left.

The qualifier that keeps it honest: an API where nothing requires
authentication may be a public service, and reporting a readable public note as
an access-control break would be wrong. So the severity depends on whether this
host enforces authentication ANYWHERE in the captured traffic, and the finding
says which case it is.

Gated on `allow_active_exploit`, because the sequence starts with a write. The
neighbour-identifier check additionally needs `allow_data_proof`, because
reading an object we did not create means reading someone's real data.

Stored as a synthetic job (tool="api_sequences").
"""
from __future__ import annotations

import json
import logging
import re
import uuid as _uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.limits import cap
from app.analysis._store import save_analysis_job
from app.analysis.mass_assignment import should_skip
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.api_sequences")

MAX_SEQUENCES = cap(3, floor=12)           # distinct create-then-read sequences attempted
MARKER_PREFIX = "syphax-seq-"

# Response keys that identify the object that was just created.
_ID_KEYS = ("id", "_id", "uuid", "guid", "identifier", "pk", "key", "slug",
            "name", "ref", "number")
# Keys whose value we may safely replace with a marker: free text, not a
# format-constrained field a server would reject.
_TEXT_KEYS = ("title", "name", "subject", "label", "description", "body",
              "content", "text", "comment", "message", "note", "summary")

_NUMERIC = re.compile(r"^\d+$")


def marker() -> str:
    """A value that cannot occur in the target's own data."""
    return f"{MARKER_PREFIX}{_uuid.uuid4().hex[:12]}"


def plant_marker(body: str) -> Optional[Tuple[str, str]]:
    """(body with a marker planted, the marker). None if there is nowhere.

    The marker is what makes the second request's answer unambiguous: a body
    that contains it is the object we created, not a coincidence.
    """
    try:
        parsed = json.loads(body or "")
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(parsed, dict):
        return None
    token = marker()
    for key in _TEXT_KEYS:
        if isinstance(parsed.get(key), str):
            return json.dumps({**parsed, key: f"{parsed[key]} {token}"}), token
    # No free-text field: append one. A server that ignores it still creates
    # the object, and then the marker simply does not help - which the caller
    # detects as "no marker in the response" and stops.
    for key, value in parsed.items():
        if isinstance(value, str) and len(value) < 200:
            return json.dumps({**parsed, key: f"{value} {token}"}), token
    return None


def identity_of(response_body: str) -> Optional[Tuple[str, str]]:
    """(key, value) identifying the created object, or None."""
    try:
        parsed = json.loads(response_body or "")
    except Exception:  # noqa: BLE001
        return None
    for node in _candidate_objects(parsed):
        for key in _ID_KEYS:
            value = node.get(key)
            if isinstance(value, (int, str)) and str(value).strip():
                text = str(value).strip()
                if len(text) <= 128:
                    return key, text
    return None


def _candidate_objects(node: Any, depth: int = 0) -> List[Dict[str, Any]]:
    """The created object: the top-level dict, then one level of wrappers.

    Most APIs answer `{...}`; many answer `{"data": {...}}`; a few answer
    `{"result": {"item": {...}}}`.
    """
    if depth > 3:
        return []
    if isinstance(node, dict):
        out = [node]
        for value in node.values():
            out.extend(_candidate_objects(value, depth + 1))
        return out
    if isinstance(node, list) and node:
        return _candidate_objects(node[0], depth + 1)
    return []


def read_url(create_url: str, identifier: str) -> str:
    """Where the created object is read back from.

    POST to a collection returns an object read at collection/{id}. That is
    the REST convention and the only one worth guessing: if the API does not
    follow it the read answers 404 and the sequence stops, which costs one
    request.
    """
    base = create_url.split("?")[0].rstrip("/")
    return f"{base}/{identifier}"


def neighbour_of(identifier: str) -> Optional[str]:
    """The identifier next to this one, for a sequential key. None otherwise.

    Only numeric identifiers: decrementing a UUID is meaningless, and guessing
    at an opaque key would send requests with no hypothesis behind them.
    """
    if not _NUMERIC.match(identifier or ""):
        return None
    value = int(identifier)
    return str(value - 1) if value > 1 else None


def contains_marker(body: str, token: str) -> bool:
    return bool(token) and token in (body or "")


def finding_for_readable(create_url: str, url: str, *, id_key: str,
                         identifier: str, token: str, status: int,
                         enforces_auth_elsewhere: bool) -> Finding:
    """The object we created, read back with no credential."""
    evidence = (
        f"1. POST {create_url} with a planted marker -> {id_key}={identifier}\n"
        f"2. GET {url} with no Authorization header, no cookie -> {status}\n"
        f"3. the response carries the marker we wrote ({token})\n"
        f"so the object created in step 1 is readable by an unauthenticated "
        f"caller. The identifier came from the API itself and the content came "
        f"from us; there is no inference in this chain.")
    if enforces_auth_elsewhere:
        return Finding(
            severity="high",
            title=f"Object created through the API is readable without "
                  f"authentication: {urlparse(url).path}",
            description=(
                "A two-request sequence: an object was created, the API "
                "returned its identifier, and a plain GET with no credential "
                "returned that object - identified by a marker written into "
                "it, so the match is not a coincidence. This host answers "
                "401/403 elsewhere, so authentication is something this API "
                "does; this operation is not doing it. That is broken object "
                "level authorisation (OWASP API1:2023), and the object graph "
                "is enumerable from here: identifiers are handed out by the "
                "create endpoint.\n\n"
                "Why this is worth more than a scanner match: single-request "
                "testing can only ever infer authorisation from a status "
                "code. This knows which object it asked for and what was in "
                "it."),
            target=url, evidence=evidence,
            metadata={"tool": "api_sequences",
                      "vuln_class": "broken_access_control",
                      "status": "confirmed", "confidence": 0.92,
                      "owasp_api": "API1:2023", "sequence": "create-then-read",
                      "identifier": f"{id_key}={identifier}",
                      "create_url": create_url},
        )
    return Finding(
        severity="medium",
        title=f"API objects are readable without authentication: "
              f"{urlparse(url).path}",
        description=(
            "An object was created and then read back with no credential, "
            "confirmed by a marker written into it. Nothing in the captured "
            "traffic for this host ever answered 401 or 403, so this may be a "
            "deliberately public API rather than a missing check - and "
            "reporting a readable public resource as an access-control break "
            "would be wrong.\n\n"
            "What is established either way: anything written through this "
            "operation is world-readable, and the identifiers are issued by "
            "the create endpoint itself. If any of these objects is meant to "
            "be private, this is OWASP API1:2023. That judgement needs the "
            "application's own intent, which is why this is reported at "
            "medium and not high."),
        target=url, evidence=evidence,
        metadata={"tool": "api_sequences",
                  "vuln_class": "broken_access_control",
                  "status": "confirmed", "confidence": 0.75,
                  "owasp_api": "API1:2023", "sequence": "create-then-read",
                  "identifier": f"{id_key}={identifier}",
                  "create_url": create_url},
    )


def finding_for_neighbour(url: str, *, identifier: str, neighbour: str,
                          status: int, body_length: int,
                          quote: str = "") -> Finding:
    """A different object, at the identifier next to ours."""
    return Finding(
        severity="high",
        title=f"Sequential object identifiers are enumerable without "
              f"authentication: {urlparse(url).path}",
        description=(
            f"Our own object was created at {identifier}. The identifier "
            f"immediately before it, {neighbour}, returns a DIFFERENT object "
            f"to an unauthenticated request - it does not carry our marker, so "
            f"it is not ours. Identifiers here are sequential and issued by "
            f"the API, which means every object ever created through this "
            f"endpoint is reachable by counting.\n\n"
            f"The response body is not recorded: it belongs to someone else, "
            f"and a report is not the place to put it. Its size is noted as "
            f"evidence that something was returned. OWASP API1:2023."),
        target=url,
        evidence=(f"GET {url} -> {status}, {body_length} bytes, "
                  f"no marker of ours\n"
                  f"our object: {identifier} | requested: {neighbour}\n"
                  + (f"sample (allow_data_proof is on): {quote[:200]}"
                     if quote else
                     "body withheld: it is another user's data and "
                     "allow_data_proof is off for this engagement")),
        metadata={"tool": "api_sequences",
                  "vuln_class": "idor", "status": "confirmed",
                  "confidence": 0.9, "owasp_api": "API1:2023",
                  "sequence": "create-then-enumerate",
                  "identifier": identifier, "probed": neighbour},
    )


# ---------------------------------------------------------------------------


async def analyze_api_sequences(engagement_id: str, *,
                                allow_active: bool = True) -> Dict[str, int]:
    from app.engagements import EngagementRepository
    from app.exploit.probe_client import ProbeClient
    from app.validation.safe_poc import (SafePoC, identity_for)

    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    if not (allow_active and getattr(eng, "allow_active_exploit", False)):
        await _say(engagement_id,
                   "Stateful API testing was not run: the sequence starts by "
                   "creating an object, so it needs active exploitation "
                   "enabled on this engagement.")
        return {"skipped": 1, "reason": "allow_active_exploit is off"}

    creates = await _creates_observed(eng)
    if not creates:
        await _say(engagement_id,
                   "No JSON create request was captured, so there was no "
                   "sequence to build. Stateful testing needs one real POST "
                   "from the application: the second request is derived from "
                   "what the first one returns.")
        return {"sequences": 0, "findings": 0}

    enforces_auth = await _enforces_auth_somewhere(eng)
    writer = ProbeClient(in_scope=eng.host_in_scope,
            identity=identity_for(eng))
    # The reader carries NO credential, and that is the entire test: an
    # object created as a logged-in user, read back by nobody. Giving it the
    # identity would read our own object with our own session, which succeeds
    # on every healthy application and would report a BOLA on all of them.
    reader = SafePoC(in_scope=eng.host_in_scope)
    findings: List[Finding] = []
    attempted = 0

    for create_url, body in creates[:MAX_SEQUENCES]:
        planted = plant_marker(body)
        if planted is None:
            continue
        mutated, token = planted
        attempted += 1

        created = await _post(writer, create_url, mutated)
        if created is None or not (200 <= created.status_code < 300):
            continue
        identity = identity_of(created.text)
        if identity is None:
            continue
        id_key, identifier = identity

        url = read_url(create_url, identifier)
        read = await _get(reader, url)
        if read is None or not (200 <= read.status_code < 300):
            continue
        if not contains_marker(read.text, token):
            continue        # we did not read back OUR object; prove nothing

        findings.append(finding_for_readable(
            create_url, url, id_key=id_key, identifier=identifier,
            token=token, status=read.status_code,
            enforces_auth_elsewhere=enforces_auth))

        # The neighbouring identifier: someone else's object. Only for a
        # sequential key, and only when the engagement allows reading real
        # data - the finding stands on the size of the answer otherwise.
        neighbour = neighbour_of(identifier)
        if neighbour is None:
            continue
        other_url = read_url(create_url, neighbour)
        other = await _get(reader, other_url)
        if other is None or not (200 <= other.status_code < 300):
            continue
        if contains_marker(other.text, token) or not (other.text or "").strip():
            continue
        findings.append(finding_for_neighbour(
            other_url, identifier=identifier, neighbour=neighbour,
            status=other.status_code, body_length=len(other.text or ""),
            quote=(other.text or "") if getattr(eng, "allow_data_proof", False) else ""))

    await save_analysis_job(engagement_id, "api_sequences", findings,
                            target=eng.target_url)
    logger.info("[%s] api_sequences: creates=%d attempted=%d findings=%d",
                engagement_id, len(creates), attempted, len(findings))
    return {"sequences": attempted, "findings": len(findings),
            "creates_available": len(creates)}


async def _creates_observed(eng) -> List[Tuple[str, str]]:
    """(url, json body) for each distinct POST the application itself made."""
    from app import db

    try:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT url, host, request_body, request_content_type FROM flows "
                "WHERE method = 'POST' AND request_body IS NOT NULL "
                'ORDER BY "timestamp" DESC LIMIT 400')
    except Exception:  # noqa: BLE001
        return []

    out: List[Tuple[str, str]] = []
    seen = set()
    for row in rows:
        url = str(row["url"] or "")
        if not url or url in seen or should_skip(url):
            continue
        if not eng.host_in_scope((row["host"] or "").lower()):
            continue
        if "json" not in str(row["request_content_type"] or "").lower():
            continue
        body = row["request_body"]
        if isinstance(body, (bytes, bytearray)):
            body = bytes(body).decode("utf-8", errors="replace")
        body = str(body or "")
        try:
            if not isinstance(json.loads(body), dict):
                continue
        except Exception:  # noqa: BLE001
            continue
        seen.add(url)
        out.append((url, body))
    return out


async def _enforces_auth_somewhere(eng) -> bool:
    """Does this host ever refuse for lack of a credential?

    The difference between "an operation lost its check" and "this is a public
    API", which is the difference between a high and a medium here.
    """
    from app import db

    try:
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COUNT(*) AS n FROM flows "
                "WHERE status_code IN (401, 403) AND host = $1",
                (eng.target_host or "").lower())
    except Exception:  # noqa: BLE001
        return False
    return bool(row and int(row["n"] or 0) > 0)


async def _post(client, url: str, body: str):
    try:
        return await client.fetch(url, method="POST", content=body,
                                  headers={"Content-Type": "application/json"})
    except Exception:  # noqa: BLE001
        return None


async def _get(safe, url: str):
    try:
        return await safe.fetch(url, method="GET")
    except Exception:  # noqa: BLE001
        return None


async def _say(engagement_id: str, message: str) -> None:
    try:
        from app import events
        await events.emit(engagement_id, events.THOUGHT, message,
                          level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001
        logger.debug("could not report the sequence decision")
