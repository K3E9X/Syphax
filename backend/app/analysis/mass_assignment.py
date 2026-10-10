"""Mass assignment: OWASP API3, reported only when the server echoes it back.

An API that binds a request body straight onto its model will accept any
property the model has, including the ones no client is supposed to set.
`{"name": "x"}` creates a user; `{"name": "x", "is_admin": true}` creates an
administrator, on an endpoint that was never meant to be able to.

The schema audit already reports the documented half of this - a request body
that leaves `additionalProperties` open says the door is not shut. This is the
live half: send the field and see what happens.

THE ORACLE IS THE ECHO. A 201 proves nothing on its own, because the server may
have accepted the request and discarded the extra field; we cannot read its
database. So:

  * the response carries back the field WE injected, with the value we sent
    -> confirmed. The server parsed it, bound it, and serialised it.
  * the server rejected the request (400/422) -> the field was validated away,
    which is the correct behaviour and produces no finding.
  * 2xx with no echo -> recorded as unconfirmed, with that stated. It is the
    honest verdict and it is not nothing: it tells a reviewer which operation
    to look at by hand.

WHAT IS NOT DONE, AND WHY. Only POST. The same weakness on PUT or PATCH
overwrites an existing object - the client's real data - and that needs the
`destructive` capability, not merely active-exploit. Rather than widen the
probe client's method policy (GET/HEAD/POST, deliberately not a superset of
anything), the update path is reported as untested with the capability that
would unlock it. An operator who has signed for it can then grant it, and the
gap is visible instead of silently absent.

Gated on `allow_active_exploit`: every probe here creates data on the target.

Stored as a synthetic job (tool="mass_assignment").
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.analysis._store import save_analysis_job
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.mass_assignment")

MAX_OPERATIONS = 4          # distinct POST operations probed
MAX_PROBES = 12             # total writes this analyser may perform

# Properties that change what the created object IS, rather than what it says.
# Each is sent on its own request so the echo identifies which one bound.
INJECTIONS: Tuple[Tuple[str, Any], ...] = (
    ("is_admin", True),
    ("role", "admin"),
    ("isAdmin", True),
    ("verified", True),
    ("email_verified", True),
    ("permissions", ["admin"]),
)

# A body we will not touch. An authentication endpoint answers a probe with a
# lockout or an alert, and a payment endpoint moves money.
_SKIP_PATHS = ("login", "signin", "sign-in", "auth/token", "oauth", "logout",
               "password", "reset", "payment", "pay", "charge", "refund",
               "transfer", "checkout", "delete", "remove")


def should_skip(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return any(marker in path for marker in _SKIP_PATHS)


def inject(body: str, field: str, value: Any) -> Optional[str]:
    """`body` with one extra property. None when it is not a JSON object.

    Only a JSON object is handled: form bodies and multipart are a different
    parser on the server side and a different test.
    """
    try:
        parsed = json.loads(body or "")
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(parsed, dict):
        return None
    if field in parsed:
        return None     # the client already sends it; injecting proves nothing
    return json.dumps({**parsed, field: value})


def echoed(response_body: str, field: str, value: Any) -> bool:
    """The response carries back the property we injected, with our value.

    Structural, not a substring match: `"is_admin": true` appearing inside an
    error message that quotes the request back is not the server having bound
    it. The field has to sit in the response's own object graph.
    """
    try:
        parsed = json.loads(response_body or "")
    except Exception:  # noqa: BLE001
        return False
    return _find(parsed, field, value, 0)


def _find(node: Any, field: str, value: Any, depth: int) -> bool:
    if depth > 6:
        return False
    if isinstance(node, dict):
        for key, item in node.items():
            if key == field and item == value:
                return True
            if _find(item, field, value, depth + 1):
                return True
    elif isinstance(node, list):
        for item in node[:50]:
            if _find(item, field, value, depth + 1):
                return True
    return False


def rejected(status: int) -> bool:
    """The server refused the body. That is the correct behaviour."""
    return status in (400, 422, 403, 409)


def finding_for(url: str, field: str, value: Any, *, status: int,
                confirmed: bool, request_body: str,
                response_excerpt: str) -> Finding:
    evidence = (f"POST {url}\n"
                f"injected property: {field} = {json.dumps(value)}\n"
                f"request body: {request_body[:600]}\n"
                f"response: HTTP {status}\n"
                f"{response_excerpt[:600]}")
    if confirmed:
        return Finding(
            severity="high",
            title=f"Mass assignment: the API bound an injected '{field}' "
                  f"on {urlparse(url).path}",
            description=(
                f"The request body was sent with an extra property '{field}' "
                f"that the client never sends, and the response carried it "
                f"back with the value we chose. The server parsed it, bound it "
                f"onto the object it created and serialised it again, which "
                f"means the object's {field} is settable by whoever makes the "
                f"request. Where that property governs privilege, verification "
                f"or ownership, this is privilege escalation through a field "
                f"name. OWASP API3:2023. The fix is an explicit allow-list of "
                f"bindable properties per operation - `additionalProperties: "
                f"false` in the contract and a strict deserialiser behind it, "
                f"not a denylist of the field names someone thought of.\n\n"
                f"Not tested: the same weakness on PUT/PATCH, which would "
                f"overwrite an existing object rather than create a new one. "
                f"That needs the 'destructive' capability on this engagement."),
            target=url, evidence=evidence,
            metadata={"tool": "mass_assignment", "vuln_class": "mass_assignment",
                      "status": "confirmed", "confidence": 0.9,
                      "owasp_api": "API3:2023", "property": field,
                      "method": "POST",
                      "untested": "PUT/PATCH (needs the destructive capability)"},
        )
    return Finding(
        severity="low",
        title=f"Injected '{field}' was accepted on {urlparse(url).path} "
              f"(binding not observable)",
        description=(
            f"The API accepted a request body carrying an extra '{field}' "
            f"property and answered {status}, but the response does not carry "
            f"the property back, so we cannot tell whether it was bound onto "
            f"the object or discarded. We do not read the target's database, "
            f"and a 2xx alone is not proof of mass assignment - stating it as "
            f"one would be a guess dressed as a finding.\n\n"
            f"What this is worth: the operation did not reject an undeclared "
            f"property, which a strict deserialiser would have. It is the "
            f"short list of operations to check by hand, with the exact "
            f"request to replay."),
        target=url, evidence=evidence,
        metadata={"tool": "mass_assignment", "vuln_class": "mass_assignment",
                  "status": "unconfirmed", "confidence": 0.35,
                  "owasp_api": "API3:2023", "property": field,
                  "method": "POST"},
    )


# ---------------------------------------------------------------------------


async def analyze_mass_assignment(engagement_id: str, *,
                                  allow_active: bool = True) -> Dict[str, int]:
    from app.engagements import EngagementRepository
    from app.exploit.probe_client import ProbeClient

    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    if not (allow_active and getattr(eng, "allow_active_exploit", False)):
        await _say(engagement_id,
                   "Mass assignment was not tested: every probe creates data "
                   "on the target, so it needs active exploitation enabled on "
                   "this engagement. The contract-level half of API3 (request "
                   "bodies that accept undeclared properties) is reported by "
                   "the schema audit either way.")
        return {"skipped": 1, "reason": "allow_active_exploit is off"}

    operations = await _writes_observed(eng)
    if not operations:
        await _say(engagement_id,
                   "No JSON write request was captured, so there was no body "
                   "to inject into. Mass assignment needs one real POST from "
                   "the application to build on - a fabricated body tests our "
                   "guess at the API, not the API.")
        return {"operations": 0, "probes": 0, "findings": 0}

    client = ProbeClient(in_scope=eng.host_in_scope)
    findings: List[Finding] = []
    probes = 0

    for url, body in operations[:MAX_OPERATIONS]:
        for field, value in INJECTIONS:
            if probes >= MAX_PROBES:
                break
            mutated = inject(body, field, value)
            if mutated is None:
                continue
            probes += 1
            resp = await _post(client, url, mutated)
            if resp is None or rejected(resp.status_code):
                continue
            if 200 <= resp.status_code < 300:
                findings.append(finding_for(
                    url, field, value, status=resp.status_code,
                    confirmed=echoed(resp.text, field, value),
                    request_body=mutated, response_excerpt=resp.text))
                break   # one finding per operation; the rest is the same bug

    await save_analysis_job(engagement_id, "mass_assignment", findings,
                            target=eng.target_url)
    confirmed = sum(1 for f in findings if f.metadata["status"] == "confirmed")
    logger.info("[%s] mass_assignment: operations=%d probes=%d findings=%d confirmed=%d",
                engagement_id, len(operations), probes, len(findings), confirmed)
    return {"operations": len(operations), "probes": probes,
            "findings": len(findings), "confirmed": confirmed}


async def _writes_observed(eng) -> List[Tuple[str, str]]:
    """(url, json body) for each distinct POST the application itself made.

    Built from captured traffic rather than from the schema on purpose: a real
    body carries the fields the API actually requires, so the probe differs
    from a working request by exactly one property. A body invented from the
    schema would be rejected for a dozen unrelated reasons and every result
    would be noise.
    """
    from app import db

    try:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT url, host, request_body, request_content_type FROM flows "
                "WHERE method = 'POST' AND request_body IS NOT NULL "
                'ORDER BY "timestamp" DESC LIMIT 400')
    except Exception:  # noqa: BLE001 - no traffic table is not a failure
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


async def _post(client, url: str, body: str):
    try:
        return await client.fetch(url, method="POST", content=body,
                                  headers={"Content-Type": "application/json"})
    except Exception:  # noqa: BLE001 - scope/policy refusal, or a dead host
        return None


async def _say(engagement_id: str, message: str) -> None:
    try:
        from app import events
        await events.emit(engagement_id, events.THOUGHT, message,
                          level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001
        logger.debug("could not report the mass-assignment decision")
