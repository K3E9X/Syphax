"""Application-logic analysis over captured proxy traffic (IDOR + CSRF + BFLA).

These classes can't be found by scanners pointed at a URL: they need real
authenticated requests. So we analyze the flows the operator captured through
the MITM proxy (while logged in) and look for:

  * IDOR / BOLA - GET requests whose path/query carry an object identifier.
    We confirm *safely* by re-requesting a neighbouring id through the
    in-scope, read-only SafePoC channel: a 200 on an id you were never given
    is a strong access-control signal; a 401/403/404 means it's protected.
  * CSRF - cookie-authenticated state-changing requests (POST/PUT/PATCH/
    DELETE) with no anti-CSRF token and no bearer auth.
  * BFLA / privilege escalation - privileged-looking endpoints (/admin, ...)
    reached by the primary identity, replayed safely as anonymous and as a
    low-privilege second identity. If a low-priv user (or anyone) can reach a
    privileged function, that's broken function-level authorization. Writes
    are never executed automatically (safe mode) - they're flagged for review.

Results are stored as a synthetic scan job (tool="logic") so they flow through
the normal validation / report / kill-chain pipeline unchanged. An optional
LLM pass (best-effort) refines severity and wording.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.limits import cap
from app import events
from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.llm import ROLE_VALIDATOR, LLMError, get_router
from app.proxy import FlowRepository
from app.scans.models import Finding
from app.validation.safe_poc import (SafePoC, ScopeError, identity_for)

logger = logging.getLogger("syphax.analysis.logic")

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_HEADERS = {"x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken", "x-xsrf"}
_CSRF_BODY_KEYS = (
    "csrf", "_csrf", "csrf_token", "csrfmiddlewaretoken",
    "authenticity_token", "__requestverificationtoken", "_token",
)
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp")

# Path fragments that suggest a privileged / administrative function.
_PRIV_PATTERNS = (
    "/admin", "/administrator", "/manage", "/management", "/internal",
    "/superuser", "/backoffice", "/staff", "/moderator", "/console",
    "/api/admin", "/users/roles", "/role", "/privileges", "/settings/users",
    "/system", "/config/users", "/audit",
)

MAX_FLOWS = 1000
MAX_IDOR_CONFIRM = cap(25)


async def analyze_logic(
    engagement_id: str, *, active_idor: bool = True, use_llm: bool = True
) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    flows_repo = FlowRepository()
    summaries = await flows_repo.list_flows(limit=MAX_FLOWS)
    in_scope = [f for f in summaries if eng.host_in_scope(_host(f.url))]

    safe = SafePoC(in_scope=eng.host_in_scope,
        identity=identity_for(eng))
    # Grey-box: a second identity's headers, used to prove cross-user access.
    second_headers = {h["name"]: h["value"] for h in (eng.secondary_auth or [])
                      if h.get("name") and h.get("value")}
    findings: List[Finding] = []

    # ---- IDOR ----
    confirmed_count = 0
    for f in in_scope:
        if (f.method or "").upper() != "GET":
            continue
        if _is_static(f.url):
            continue
        if f.status_code != 200:
            continue
        ident = _find_numeric_id(f.url)
        if ident is None:
            continue
        location, original, modified_url = ident

        status, confidence, poc = "likely", 0.5, (
            f"Authenticated GET {f.url} exposes an object by id "
            f"({location}={original}); access control not verified."
        )
        if active_idor and confirmed_count < MAX_IDOR_CONFIRM:
            confirmed_count += 1
            if second_headers:
                # Grey-box: replay the SAME request as identity B (rigorous).
                verdict = await _confirm_bola_greybox(safe, f, second_headers)
            else:
                # Black-box: probe a neighbouring id (weaker signal).
                verdict = await _confirm_idor(safe, f, modified_url, original)
            if verdict is None:
                # Protected / public -> not an IDOR; skip.
                continue
            status, confidence, poc = verdict

        findings.append(Finding(
            severity="high",
            title=f"Possible IDOR on {urlparse(f.url).path}",
            description="Object referenced by a guessable id in an authenticated request.",
            target=f.url,
            evidence=poc,
            metadata={"vuln_class": "idor", "status": status, "confidence": confidence,
                      "id_location": location, "id_value": original},
        ))

    # ---- CSRF (needs headers/body -> get_flow on state-changing requests) ----
    csrf_candidates = [f for f in in_scope if (f.method or "").upper() in _STATE_CHANGING]
    for f in csrf_candidates[:200]:
        full = await flows_repo.get_flow(f.id)
        if not full:
            continue
        verdict = _detect_csrf(full)
        if verdict is None:
            continue
        findings.append(Finding(
            severity="medium",
            title=f"Possible CSRF: {f.method} {urlparse(f.url).path}",
            description="Cookie-authenticated state-changing request with no anti-CSRF token.",
            target=f.url,
            evidence=verdict,
            metadata={"vuln_class": "csrf", "status": "likely", "confidence": 0.55,
                      "method": f.method},
        ))

    # ---- BFLA / privilege escalation ----
    # Privileged-looking endpoints reached as identity A; replay as the
    # low-privilege identity B. If B can use them => broken function-level
    # authorization / privesc.
    bfla_count = 0
    for f in in_scope:
        if not _is_privileged(f.url):
            continue
        method = (f.method or "GET").upper()
        if method == "GET" and f.status_code == 200 and bfla_count < MAX_IDOR_CONFIRM:
            bfla_count += 1
            verdict = await _confirm_bfla(safe, f, second_headers)
            if verdict is None:
                continue  # restricted for B / not reachable -> no privesc
            status, confidence, poc = verdict
            findings.append(Finding(
                severity="high",
                title=f"Privilege escalation (BFLA) on {urlparse(f.url).path}",
                description="A low-privilege identity can reach a privileged function.",
                target=f.url,
                evidence=poc,
                metadata={"vuln_class": "privilege_escalation", "status": status,
                          "confidence": confidence, "method": method},
            ))
        elif method in _STATE_CHANGING:
            # Can't safely execute an admin write as B; flag for manual review.
            findings.append(Finding(
                severity="medium",
                title=f"Privileged action to review: {method} {urlparse(f.url).path}",
                description="State-changing privileged endpoint; verify a low-privilege "
                            "user cannot invoke it (not executed automatically - safe mode).",
                target=f.url,
                evidence=f"{method} {f.url} observed as a privileged action.",
                metadata={"vuln_class": "privilege_escalation", "status": "unconfirmed",
                          "confidence": 0.4, "method": method},
            ))

    if use_llm:
        await _llm_refine(findings)

    await _save_logic_job(engagement_id, findings)

    idor_n = sum(1 for x in findings if x.metadata.get("vuln_class") == "idor")
    csrf_n = sum(1 for x in findings if x.metadata.get("vuln_class") == "csrf")
    bfla_n = sum(1 for x in findings if x.metadata.get("vuln_class") == "privilege_escalation")
    await events.emit(
        engagement_id, events.VALIDATED,
        f"Logic analysis: {idor_n} IDOR, {csrf_n} CSRF, {bfla_n} BFLA/privesc "
        f"candidate(s) from {len(in_scope)} captured flows",
        level=events.LEVEL_VERBOSE,
    )
    logger.info("[%s] logic analysis: idor=%d csrf=%d bfla=%d (flows=%d)",
                engagement_id, idor_n, csrf_n, bfla_n, len(in_scope))
    return {"flows_analyzed": len(in_scope), "idor": idor_n, "csrf": csrf_n,
            "bfla": bfla_n, "total": len(findings)}


# --------------------------------------------------------------------------- #
# IDOR
# --------------------------------------------------------------------------- #

def _find_numeric_id(url: str) -> Optional[Tuple[str, str, str]]:
    """Return (location, original_value, modified_url) for the first numeric id
    found in the path or query, with the id shifted to a neighbour."""
    parsed = urlparse(url)

    # Path segment that is all digits.
    segments = parsed.path.split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit() and len(seg) >= 1:
            neighbour = _neighbour(seg)
            new_segments = segments.copy()
            new_segments[i] = neighbour
            modified = urlunparse(parsed._replace(path="/".join(new_segments)))
            return ("path", seg, modified)

    # Query param with a numeric value.
    params = parse_qsl(parsed.query, keep_blank_values=True)
    for idx, (k, v) in enumerate(params):
        if v.isdigit():
            new_params = params.copy()
            new_params[idx] = (k, _neighbour(v))
            modified = urlunparse(parsed._replace(query=urlencode(new_params)))
            return (f"query:{k}", v, modified)

    return None


def _neighbour(value: str) -> str:
    try:
        n = int(value)
    except ValueError:
        return value
    return str(n - 1) if n > 1 else str(n + 1)


async def _confirm_idor(
    safe: SafePoC, flow, modified_url: str, original_id: str
) -> Optional[Tuple[str, float, str]]:
    """Safely re-request a neighbouring id (GET, in-scope). Returns
    (status, confidence, poc) or None when the resource is protected."""
    try:
        resp = await safe.fetch(modified_url, method="GET")
    except ScopeError:
        return ("likely", 0.5, f"Re-test skipped (out of scope): {modified_url}")
    if resp is None:
        return ("likely", 0.5, f"Neighbour id not reachable: {modified_url}")
    if resp.status_code in (401, 403, 404):
        # Access control is enforced for the neighbour -> not an IDOR.
        return None
    if resp.status_code == 200:
        orig_size = getattr(flow, "response_size", None) or 0
        new_size = len(resp.text)
        differs = orig_size == 0 or abs(new_size - orig_size) > max(64, orig_size * 0.05)
        conf = 0.75 if differs else 0.6
        poc = (
            f"Authenticated request used id {original_id}. Re-requesting a "
            f"neighbouring id returned HTTP 200 ({new_size} bytes) at "
            f"{modified_url} - access to another object without authorization."
        )
        return ("likely", conf, poc)
    # Other codes (5xx, redirects): inconclusive but worth noting.
    return ("likely", 0.5, f"Neighbour id returned HTTP {resp.status_code}: {modified_url}")


async def _confirm_bola_greybox(
    safe: SafePoC, flow, second_headers: Dict[str, str]
) -> Optional[Tuple[str, float, str]]:
    """Grey-box BOLA proof: replay the SAME authenticated request as a second
    identity. If identity B can read identity A's object (and it isn't simply
    public), that's a confirmed broken-object-level-authorization."""
    url = flow.url
    # 1. Rule out a public resource: fetch with no credentials at all.
    try:
        anon = await safe.fetch(url, method="GET", anonymous=True)
    except ScopeError:
        return ("likely", 0.5, f"Re-test skipped (out of scope): {url}")
    if anon is not None and anon.status_code == 200 and len(anon.text) > 0:
        # Anyone can read it -> it's public, not an authz flaw.
        return None

    # 2. Replay as identity B.
    resp = await safe.fetch(url, method="GET", headers=second_headers)
    if resp is None:
        return ("likely", 0.5, f"Second identity could not reach {url}")
    if resp.status_code in (401, 403, 404):
        # B is correctly denied -> object-level authorization works.
        return None
    if resp.status_code == 200 and len(resp.text) > 0:
        poc = (
            f"BOLA confirmed: the object at {url} was requested by identity A, "
            f"and a second identity (B) received HTTP 200 ({len(resp.text)} bytes) "
            f"for the same object - cross-user access without authorization. "
            f"(Anonymous access was not 200, so the resource is not public.)"
        )
        return ("confirmed", 0.95, poc)
    return ("likely", 0.5, f"Second identity got HTTP {resp.status_code} on {url}")


# --------------------------------------------------------------------------- #
# BFLA / privilege escalation
# --------------------------------------------------------------------------- #

def _is_privileged(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(p in path for p in _PRIV_PATTERNS)


async def _confirm_bfla(
    safe: SafePoC, flow, second_headers: Dict[str, str]
) -> Optional[Tuple[str, float, str]]:
    """Replay a privileged GET endpoint (reached as A) without privileges.
    Anonymous 200 => unauthenticated admin access (critical). Low-priv B 200
    => privilege escalation. 401/403/404 => properly restricted (None)."""
    url = flow.url
    try:
        anon = await safe.fetch(url, method="GET", anonymous=True)
    except ScopeError:
        return None
    if anon is not None and anon.status_code == 200 and len(anon.text) > 0:
        return ("confirmed", 0.9,
                f"Privileged endpoint {url} is reachable WITHOUT authentication "
                f"(HTTP 200, {len(anon.text)} bytes) - broken access control.")

    if not second_headers:
        # No low-priv identity to test with; flag as a candidate.
        return ("likely", 0.45,
                f"Privileged endpoint {url} reached by the primary identity; "
                f"provide a low-privilege identity (grey-box) to confirm privesc.")

    resp = await safe.fetch(url, method="GET", headers=second_headers)
    if resp is None:
        return ("likely", 0.45, f"Low-privilege identity could not reach {url}")
    if resp.status_code in (401, 403, 404):
        return None  # correctly restricted
    if resp.status_code == 200 and len(resp.text) > 0:
        return ("confirmed", 0.9,
                f"BFLA/privilege escalation: the low-privilege identity received "
                f"HTTP 200 ({len(resp.text)} bytes) on privileged endpoint {url}.")
    return ("likely", 0.5, f"Low-privilege identity got HTTP {resp.status_code} on {url}")


# --------------------------------------------------------------------------- #
# CSRF
# --------------------------------------------------------------------------- #

def _detect_csrf(full: Dict[str, Any]) -> Optional[str]:
    headers = full.get("request_headers") or []
    names = {str(n).lower(): str(v) for n, v in headers}

    if "cookie" not in names:
        return None  # not cookie-authenticated -> classic CSRF doesn't apply
    auth = names.get("authorization", "").lower()
    if auth.startswith("bearer "):
        return None  # token-auth APIs are not CSRF-able via the browser

    # Anti-CSRF header present?
    if any(h in names for h in _CSRF_HEADERS):
        return None

    # Anti-CSRF token in the body?
    body = full.get("request_body_preview") or {}
    body_text = (body.get("text") or "").lower() if body.get("encoding") == "text" else ""
    if any(k in body_text for k in _CSRF_BODY_KEYS):
        return None

    method = full.get("method", "?")
    return (f"{method} request authenticated by cookie with no anti-CSRF token "
            f"(no CSRF header, none in body). Forgeable cross-site.")


# --------------------------------------------------------------------------- #
# optional LLM refinement
# --------------------------------------------------------------------------- #

async def _llm_refine(findings: List[Finding]) -> None:
    if not findings:
        return
    client = get_router().get(ROLE_VALIDATOR)
    if not client.configured:
        return
    payload = [
        {"i": i, "class": f.metadata.get("vuln_class"), "title": f.title,
         "target": f.target, "evidence": f.evidence[:300]}
        for i, f in enumerate(findings)
    ]
    system = (
        "You review candidate IDOR/CSRF findings from authenticated traffic. "
        "For each, keep or drop it and set severity (low/medium/high/critical) "
        "and a one-sentence note. Reply JSON only: "
        '{"items":[{"i":0,"keep":true,"severity":"high","note":"..."}]}'
    )
    try:
        reply = await client.chat(
            [{"role": "system", "content": system},
             {"role": "user", "content": json.dumps(payload)}],
            temperature=0.1, max_tokens=1200,
        )
    except LLMError:
        return
    decisions = _parse_items(reply)
    keep: List[Finding] = []
    for i, f in enumerate(findings):
        d = decisions.get(i)
        if d is None:
            keep.append(f)
            continue
        if d.get("keep") is False:
            continue
        if d.get("severity"):
            f.severity = str(d["severity"]).lower()
        if d.get("note"):
            f.description = str(d["note"])
        keep.append(f)
    findings[:] = keep


def _parse_items(reply: str) -> Dict[int, Dict[str, Any]]:
    text = reply.strip()
    if text.startswith("```"):
        text = text.strip("`").split("\n", 1)[-1]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        s, e = text.find("{"), text.rfind("}")
        if s == -1 or e == -1:
            return {}
        try:
            obj = json.loads(text[s:e + 1])
        except json.JSONDecodeError:
            return {}
    out: Dict[int, Dict[str, Any]] = {}
    for it in (obj.get("items") or []) if isinstance(obj, dict) else []:
        if isinstance(it, dict) and "i" in it:
            try:
                out[int(it["i"])] = it
            except (TypeError, ValueError):
                continue
    return out


# --------------------------------------------------------------------------- #
# persistence: store as a synthetic 'logic' job
# --------------------------------------------------------------------------- #

async def _save_logic_job(engagement_id: str, findings: List[Finding]) -> None:
    await save_analysis_job(engagement_id, "logic", findings, target="(captured traffic)")


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXT)
