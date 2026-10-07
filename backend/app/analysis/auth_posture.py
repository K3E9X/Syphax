"""Identity and authentication posture (OWASP IDNT + ATHN).

Both families were completely untested. auth_brute.py sprays default
credentials, which is a different question - it asks "does this password work",
not "does this login tell me which usernames exist", "are the credentials sent
in clear", or "can an attacker reach the protected page by asking differently".

Four checks, three of them read-only over captured traffic:

  * credentials submitted over plaintext HTTP;
  * username enumeration - a login/reset response that distinguishes "no such
    user" from "wrong password";
  * a password policy that accepts short secrets (read from the client-side
    rule the app itself ships);
  * authentication bypass - a 401/403 endpoint retried with the headers that
    reverse proxies honour (X-Original-URL, X-Rewrite-URL, X-Forwarded-For).
    This one sends GETs through SafePoC, so it is in-scope and gated by
    `allow_active`; a 200 here is an observed bypass, not an inference.

Stored as a synthetic job (tool="auth_posture").
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app import db
from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.scans.models import Finding
from app.validation.safe_poc import SafePoC, ScopeError

logger = logging.getLogger("syphax.analysis.auth_posture")

MAX_FLOWS = 800
MAX_BYPASS_PROBES = 12

# A URL that plausibly handles identity.
_AUTH_PATH = re.compile(
    r"(login|signin|sign-in|auth|session|register|signup|sign-up|"
    r"password|passwd|forgot|reset|account|token|oauth|sso)", re.I)

# Field names that carry a secret.
_SECRET_FIELDS = ("password", "passwd", "pwd", "pass", "secret", "token",
                  "api_key", "apikey", "credential")

# Responses that answer "does this account exist?" instead of "wrong creds".
# Unambiguous: these name the account as the problem, full stop.
_ENUM_STRONG = (
    "user not found", "username not found", "no such user", "unknown user",
    "account not found", "no account", "email not found", "email not registered",
    "that email is not", "user does not exist", "account does not exist",
    "unrecognized email", "utilisateur inconnu", "compte introuvable",
    "cet email n'existe pas",
)
# Ambiguous on their own: "invalid username" enumerates, but "invalid username
# or password" is the CORRECT generic message. Only flag these when the
# response does not also offer the combined wording.
_ENUM_WEAK = ("invalid username", "incorrect username", "invalid user",
              "wrong username", "identifiant invalide")
_GENERIC_COMBINED = (
    "username or password", "user or password", "email or password",
    "username/password", "user/password", "email/password",
    "credentials are invalid", "invalid credentials",
    "identifiant ou mot de passe", "ou mot de passe",
)

# Headers a reverse proxy or framework may honour for routing/identity.
_BYPASS_HEADERS: Tuple[Tuple[str, Dict[str, str]], ...] = (
    ("X-Original-URL", {"X-Original-URL": "/"}),
    ("X-Rewrite-URL", {"X-Rewrite-URL": "/"}),
    ("X-Forwarded-For", {"X-Forwarded-For": "127.0.0.1"}),
    ("X-Custom-IP-Authorization", {"X-Custom-IP-Authorization": "127.0.0.1"}),
    ("X-Forwarded-Host", {"X-Forwarded-Host": "localhost"}),
)


# --------------------------------------------------------------------------- #
# Pure detection helpers
# --------------------------------------------------------------------------- #

def is_auth_url(url: str) -> bool:
    try:
        return bool(_AUTH_PATH.search(urlparse(url or "").path or ""))
    except ValueError:
        return False


def carries_secret(body: str, headers: List[Tuple[str, str]]) -> bool:
    """Does this request submit a credential (form field, JSON key or Basic)?"""
    low = (body or "").lower()
    if any(f'"{f}"' in low or f"{f}=" in low for f in _SECRET_FIELDS):
        return True
    for h in headers or []:
        if len(h) >= 2 and str(h[0]).lower() == "authorization":
            if str(h[1]).lower().startswith("basic "):
                return True
    return False


def enumeration_phrase(body: str) -> Optional[str]:
    """The phrase that reveals whether an account exists, if any.

    A response saying "invalid username or password" is doing the right thing;
    only an answer that singles out the account is enumeration.
    """
    low = (body or "").lower()
    for phrase in _ENUM_STRONG:
        if phrase in low:
            return phrase
    if any(g in low for g in _GENERIC_COMBINED):
        return None
    for phrase in _ENUM_WEAK:
        if phrase in low:
            return phrase
    return None


def weak_min_length(body: str) -> Optional[int]:
    """The shortest password the page itself says it will accept.

    Read from the HTML/JS minlength attribute only. A quantifier heuristic over
    validation regexes was tried and dropped: it either matched nothing useful
    or matched every `.{1,5}` in the bundle.
    """
    best: Optional[int] = None
    for m in re.finditer(r"min[_]?length\s*[=:]\s*[\"']?(\d{1,2})", body or "", re.I):
        try:
            n = int(m.group(1))
        except ValueError:
            continue
        if 0 < n < 8 and (best is None or n < best):
            best = n
    return best


def looks_protected(status: Optional[int]) -> bool:
    return status in (401, 403)


def bypass_succeeded(before: Optional[int], after: Optional[int]) -> bool:
    """A protected response that becomes a success when a header is added."""
    return looks_protected(before) and after is not None and 200 <= after < 300


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

async def analyze_auth_posture(engagement_id: str, *,
                               allow_active: bool = True) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    try:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                'SELECT url, host, method, status_code, request_headers_json, '
                'request_body, response_body, response_content_type '
                'FROM flows ORDER BY "timestamp" DESC LIMIT $1', MAX_FLOWS)
    except Exception:  # noqa: BLE001 - no proxy data is a normal state
        return {"skipped": 1}

    findings: List[Finding] = []
    seen: set = set()
    protected: List[str] = []

    for r in rows:
        host = (r["host"] or "").lower()
        url = r["url"] or ""
        if not host or not eng.host_in_scope(host):
            continue
        req_headers = _json_list(r["request_headers_json"])
        req_body = _text(r["request_body"])
        resp_body = _text(r["response_body"])

        # 1. credentials in the clear
        if url.startswith("http://") and carries_secret(req_body, req_headers):
            _add(findings, seen, "cleartext_credentials", host,
                 "high", f"Credentials submitted over plaintext HTTP on {host}",
                 "The request carries a password or token to an http:// URL, so "
                 "anyone on the path reads it.",
                 f"{r['method']} {url}", url)

        if not is_auth_url(url):
            continue

        # 2. username enumeration
        phrase = enumeration_phrase(resp_body)
        if phrase:
            _add(findings, seen, "user_enumeration", host,
                 "medium", f"Username enumeration on {urlparse(url).path}",
                 "The response distinguishes an unknown account from a wrong "
                 "password, so an attacker can harvest valid usernames before "
                 "ever guessing a password.",
                 f'response contains: "{phrase}"', url, phrase=phrase)

        # 3. password policy the app itself advertises
        ctype = (r["response_content_type"] or "").lower()
        if "html" in ctype or "javascript" in ctype:
            n = weak_min_length(resp_body)
            if n is not None:
                _add(findings, seen, "weak_password_policy", host,
                     "low", f"Password policy accepts {n}-character secrets",
                     f"The page's own rule allows a password of {n} characters. "
                     "Short secrets fall to offline cracking and credential "
                     "stuffing. Check the server enforces more than the browser does.",
                     f"minimum length advertised: {n}", url, min_length=n)

        if looks_protected(r["status_code"]) and url not in protected:
            protected.append(url)

    # 4. authentication bypass (active, in-scope GETs)
    if allow_active and protected:
        findings.extend(await _probe_bypass(eng, protected[:MAX_BYPASS_PROBES]))

    if findings:
        await save_analysis_job(engagement_id, "auth_posture", findings,
                                target=eng.target_host or eng.target_url)
    return {"findings": len(findings), "protected_urls": len(protected)}


async def _probe_bypass(eng, urls: List[str]) -> List[Finding]:
    """Retry a 401/403 URL with proxy headers. A 200 is an observed bypass."""
    safe = SafePoC(in_scope=eng.host_in_scope)
    out: List[Finding] = []
    for url in urls:
        try:
            base = await safe.fetch(url, method="GET")
        except (ScopeError, Exception):  # noqa: BLE001
            continue
        if base is None or not looks_protected(base.status_code):
            continue
        for label, headers in _BYPASS_HEADERS:
            try:
                resp = await safe.fetch(url, method="GET", headers=headers)
            except Exception:  # noqa: BLE001
                continue
            if resp is None or not bypass_succeeded(base.status_code, resp.status_code):
                continue
            out.append(Finding(
                severity="high",
                title=f"Authentication bypass via {label} on {urlparse(url).path}",
                description=(
                    f"{url} answers {base.status_code} normally, but returns "
                    f"{resp.status_code} when {label} is sent. The header is "
                    "being trusted for routing or for the access decision, so "
                    "the protection can be skipped by asking differently."),
                target=url,
                evidence=f"without header: {base.status_code}; "
                         f"with {label}: {resp.status_code}",
                metadata={"vuln_class": "auth_bypass", "header": label,
                          "baseline_status": base.status_code,
                          "bypass_status": resp.status_code,
                          "status": "confirmed", "confidence": 0.9,
                          "proven": True, "tool": "auth_posture"},
            ))
            break   # one proven bypass per URL is enough
    return out


# --------------------------------------------------------------------------- #

def _add(findings: List[Finding], seen: set, vclass: str, host: str,
         sev: str, title: str, desc: str, evidence: str, url: str,
         **meta: Any) -> None:
    key = (host, vclass, title)
    if key in seen:
        return
    seen.add(key)
    findings.append(Finding(
        severity=sev, title=title, description=desc, target=url,
        evidence=evidence[:600],
        metadata={"vuln_class": vclass, "host": host,
                  "tool": "auth_posture", **meta}))


def _json_list(raw) -> List[Tuple[str, str]]:
    try:
        out = json.loads(raw or "[]")
        return out if isinstance(out, list) else []
    except (TypeError, ValueError):
        return []


def _text(body: Any) -> str:
    if not body:
        return ""
    if isinstance(body, memoryview):
        body = body.tobytes()
    if isinstance(body, (bytes, bytearray)):
        return bytes(body[:200_000]).decode("utf-8", errors="replace")
    return str(body)[:200_000]
