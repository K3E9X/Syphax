"""Access-control depth checks over captured traffic (Tier-1).

Logic analysis (logic.py) already covers IDOR/BOLA, CSRF and BFLA on privileged
paths. This module widens access-control testing across *all* authenticated
traffic, which is where ~40% of real bounty payouts live:

  * Missing authentication / broken access control - replay every
    cookie-or-bearer-authenticated GET with NO credentials. A 200 with
    equivalent content means the data is served to anyone (safe, read-only).
  * Method tampering - state-changing endpoints are flagged so the operator
    tests verb overrides (GET->PUT/DELETE, X-HTTP-Method-Override). Not
    executed automatically (would be a write).
  * Mass assignment - JSON write bodies are flagged so the operator tries
    injecting privileged fields (role/is_admin/verified). Not executed (write).

Stored as a synthetic job (tool="access-control").
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app.limits import cap
from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.models import Finding
from app.validation.safe_poc import SafePoC, ScopeError

logger = logging.getLogger("syphax.analysis.access_control")

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp")
MAX_ANON_REPLAY = cap(40)
MAX_FLAG = 60


async def analyze_access_control(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    flows_repo = FlowRepository()
    summaries = await flows_repo.list_flows(limit=1000)
    in_scope = [f for f in summaries
                if eng.host_in_scope((urlparse(f.url).hostname or "").lower())]

    safe = SafePoC(in_scope=eng.host_in_scope)
    findings: List[Finding] = []

    # ---- missing-auth / broken access control (anonymous replay) ----
    anon_n = 0
    seen_paths: set[str] = set()
    for f in in_scope:
        if anon_n >= MAX_ANON_REPLAY:
            break
        if (f.method or "").upper() != "GET" or f.status_code != 200:
            continue
        if _is_static(f.url):
            continue
        path = urlparse(f.url).path
        if path in seen_paths:
            continue
        full = await flows_repo.get_flow(f.id)
        if not full or not _was_authenticated(full):
            continue
        seen_paths.add(path)
        anon_n += 1
        verdict = await _replay_anonymous(safe, f, full)
        if verdict is None:
            continue
        status, confidence, poc = verdict
        findings.append(Finding(
            severity="high",
            title=f"Broken access control: {urlparse(f.url).path} served without auth",
            description="An endpoint that was requested with credentials returns the "
                        "same content with no credentials at all.",
            target=f.url,
            evidence=poc,
            metadata={"vuln_class": "broken_access_control", "status": status,
                      "confidence": confidence, "method": "GET"},
        ))

    # ---- method tampering + mass assignment (flag for review, never executed) ----
    flagged = 0
    for f in in_scope:
        if flagged >= MAX_FLAG:
            break
        method = (f.method or "").upper()
        if method not in _STATE_CHANGING:
            continue
        full = await flows_repo.get_flow(f.id)
        if not full or not _was_authenticated(full):
            continue
        path = urlparse(f.url).path
        flagged += 1
        findings.append(Finding(
            severity="low",
            title=f"Method tampering to test: {method} {path}",
            description="State-changing authenticated endpoint. Test verb overrides "
                        "(GET/PUT/DELETE, X-HTTP-Method-Override) and access as a "
                        "lower-privilege user. Not executed automatically (safe mode).",
            target=f.url,
            evidence=f"{method} {f.url} (authenticated).",
            metadata={"vuln_class": "access_control_review", "status": "unconfirmed",
                      "confidence": 0.3, "method": method, "kind": "method_tampering"},
        ))
        if _is_json_write(full):
            fields = _body_field_names(full)
            findings.append(Finding(
                severity="medium",
                title=f"Mass-assignment to test: {method} {path}",
                description="JSON write body. Test injecting privileged fields "
                            "(role, is_admin, verified, owner_id) - if the server "
                            "binds them, that's mass assignment. Not executed (safe mode).",
                target=f.url,
                evidence=f"{method} {f.url}\nobserved body fields: {', '.join(fields[:20]) or '(opaque)'}",
                metadata={"vuln_class": "mass_assignment", "status": "unconfirmed",
                          "confidence": 0.3, "method": method, "kind": "mass_assignment"},
            ))

    await save_analysis_job(engagement_id, "access-control", findings,
                            target="(captured traffic)")

    bac = sum(1 for x in findings if x.metadata.get("vuln_class") == "broken_access_control")
    logger.info("[%s] access-control: anon_replays=%d broken=%d flagged=%d",
                engagement_id, anon_n, bac, flagged)
    return {"anon_replays": anon_n, "broken_access_control": bac, "flagged": flagged}


# --------------------------------------------------------------------------- #

async def _replay_anonymous(safe: SafePoC, flow, full) -> Optional[tuple]:
    """Fetch the URL with no credentials. 200 + comparable size => the resource
    is served to anyone, despite being requested authenticated."""
    try:
        anon = await safe.fetch(flow.url, method="GET", headers={})
    except ScopeError:
        return None
    if anon is None or anon.status_code != 200 or len(anon.text) == 0:
        return None
    orig = flow.response_size or 0
    new = len(anon.text)
    api_like = "/api" in urlparse(flow.url).path.lower() or _json_response(full)
    close = orig == 0 or abs(new - orig) <= max(256, orig * 0.25)
    if close and api_like:
        return ("confirmed", 0.85,
                f"Authenticated endpoint {flow.url} returns HTTP 200 ({new} bytes) "
                f"with NO credentials - data exposed to anyone.")
    if close:
        return ("likely", 0.55,
                f"{flow.url} returns HTTP 200 ({new} bytes) unauthenticated; verify it "
                f"should require login.")
    return None


def _was_authenticated(full: Dict) -> bool:
    names = {str(n).lower(): str(v) for n, v in (full.get("request_headers") or [])}
    if names.get("authorization", "").lower().startswith("bearer "):
        return True
    return "cookie" in names and len(names["cookie"]) > 8


def _json_response(full: Dict) -> bool:
    ct = (full.get("response_content_type") or "").lower()
    return "json" in ct


def _is_json_write(full: Dict) -> bool:
    ct = (full.get("request_content_type") or "").lower()
    return "json" in ct


def _body_field_names(full: Dict) -> List[str]:
    body = full.get("request_body_preview") or {}
    if body.get("encoding") != "text":
        return []
    import json
    try:
        obj = json.loads(body.get("text") or "")
        return list(obj.keys()) if isinstance(obj, dict) else []
    except Exception:  # noqa: BLE001
        return []


def _is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXT)
