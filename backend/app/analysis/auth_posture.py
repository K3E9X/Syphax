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
# Anchored on path SEGMENTS: an unanchored search made /authors/42,
# /static/reset.css and /blog/password-manager-review "auth URLs".
_AUTH_PATH = re.compile(
    r"(?:^|[/-])(login|signin|sign-in|logon|auth|authenticate|session|sessions|"
    r"register|signup|sign-up|password|passwd|forgot|reset|account|accounts|"
    r"token|oauth\d?|sso)"
    # Trailing boundary: end, a path separator, a query - or a SCRIPT
    # extension. Allowing any "." or "-" made /static/reset.css and
    # /blog/password-manager-review auth URLs.
    r"(?:$|[/?]|\.(?:php|aspx?|jsp|do|cgi|s?html?)\b)", re.I)

# Field names that carry a secret.
# Matched as FIELD NAMES at a delimiter. A bare substring test made
# "compass=north" and "csrf_token=..." look like credentials, and a CSRF token
# on a plain-HTTP staging host was reported high as "credentials in cleartext".
_SECRET_FIELD_RE = re.compile(
    r"""(?:^|[&?;,{\s"'])\s*"?(password|passwd|pwd|secret|client_secret|"""
    r"""api[_-]?key|apikey|credential|private[_-]?key)"?\s*[=:]""", re.I)

# Responses that answer "does this account exist?" instead of "wrong creds".
# Unambiguous: these name the account as the problem, full stop.
_ENUM_STRONG = (
    "user not found", "username not found", "no such user", "unknown user",
    "account not found", "no account found", "no such account",
    "email not found", "email not registered",
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
# Built per-URL: X-Original-URL / X-Rewrite-URL must carry the PROTECTED path.
# Sending "/" asked the proxy for the homepage, so a 200 was the public home
# page being served - reported as a proven high "authentication bypass".
def _bypass_variants(path: str) -> Tuple[Tuple[str, Dict[str, str]], ...]:
    return (
        ("X-Original-URL", {"X-Original-URL": path}),
        ("X-Rewrite-URL", {"X-Rewrite-URL": path}),
        ("X-Forwarded-For", {"X-Forwarded-For": "127.0.0.1"}),
        ("X-Custom-IP-Authorization", {"X-Custom-IP-Authorization": "127.0.0.1"}),
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
    if _SECRET_FIELD_RE.search(body or ""):
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
    text = body or ""
    for m in re.finditer(r"min[_]?length\s*[=:]\s*[\"'{]?\s*(\d{1,2})", text, re.I):
        # The rule must be about a PASSWORD: a search box with minlength=3 was
        # reported as "password policy accepts 3-character secrets".
        window = text[max(0, m.start() - 220):m.end() + 220].lower()
        if "pass" not in window and "secret" not in window:
            continue
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


def _body_fingerprint(text: str) -> str:
    """A cheap identity for a response body, for comparing two responses."""
    import hashlib
    return hashlib.sha256((text or "").strip().encode("utf-8", "replace")).hexdigest()


async def _probe_bypass(eng, urls: List[str]) -> List[Finding]:
    """Retry a 401/403 URL with proxy headers.

    A 200 is NOT enough. X-Original-URL / X-Rewrite-URL ask the proxy to serve
    a path, so sending "/" made it serve the public homepage - and that 200 was
    reported as a PROVEN high bypass. Two corrections: the header now carries
    the PROTECTED path, and the body must differ from the public root,
    otherwise we simply got a different, public resource.
    """
    safe = SafePoC(in_scope=eng.host_in_scope)
    out: List[Finding] = []
    roots: Dict[str, str] = {}

    for url in urls:
        parsed = urlparse(url)
        path = parsed.path or "/"
        try:
            base = await safe.fetch(url, method="GET")
        except ScopeError:
            logger.warning("auth bypass probe refused, out of scope: %s", url)
            continue
        except Exception:  # noqa: BLE001 - a network failure is not a finding
            continue
        if base is None or not looks_protected(base.status_code):
            continue

        origin = f"{parsed.scheme}://{parsed.netloc}/"
        if origin not in roots:
            try:
                root = await safe.fetch(origin, method="GET")
                roots[origin] = _body_fingerprint(root.text) if root else ""
            except Exception:  # noqa: BLE001
                roots[origin] = ""

        for label, headers in _bypass_variants(path):
            try:
                resp = await safe.fetch(url, method="GET", headers=headers)
            except Exception:  # noqa: BLE001
                continue
            if resp is None or not bypass_succeeded(base.status_code, resp.status_code):
                continue
            if roots.get(origin) and _body_fingerprint(resp.text) == roots[origin]:
                continue        # it served the homepage: nothing was bypassed
            out.append(Finding(
                severity="high",
                title=f"Authentication bypass via {label} on {path}",
                description=(
                    f"{url} answers {base.status_code} normally, but returns "
                    f"{resp.status_code} with a different body when {label} is "
                    "sent. The header is being trusted for routing or for the "
                    "access decision. Confirm the body IS the protected "
                    "resource before reporting it."),
                target=url,
                evidence=(f"without header: {base.status_code}; with {label}: "
                          f"{resp.status_code}; body differs from {origin}"),
                metadata={"vuln_class": "auth_bypass", "header": label,
                          "baseline_status": base.status_code,
                          "bypass_status": resp.status_code,
                          # Observed, but nothing has checked the body IS the
                          # protected resource - a strong lead, not a proof.
                          # It used to ship as status=confirmed/proven/0.9.
                          "status": "likely", "confidence": 0.7,
                          "tool": "auth_posture"},
            ))
            break
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
