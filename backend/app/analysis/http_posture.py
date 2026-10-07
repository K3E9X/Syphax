"""HTTP security posture: cookies, CSP, clickjacking, transport, disclosure.

The whole OWASP Session Management and Client-side families were untested: a
missing HttpOnly on a session cookie, a CSP that allows 'unsafe-inline', a page
that can be framed - none of it had a check. nikto brushes past some of it, but
nothing read the actual Set-Cookie and Content-Security-Policy of the responses
the proxy already captured.

Entirely read-only and sends NOTHING: it re-reads the stored responses. That
means it works on a WAF'd or rate-limited target where active probing stalls,
and it costs the engagement no requests at all.

One finding per (host, issue) - the same missing header on 200 pages is one
weakness, not two hundred.

Stored as a synthetic job (tool="http_posture").
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from app import db
from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.http_posture")

MAX_FLOWS = 800
# Names that suggest the cookie carries a session or an identity.
_SESSION_HINTS = ("sess", "sid", "auth", "token", "jwt", "login", "user",
                  "remember", "csrf", "xsrf", "phpsessid", "jsessionid", "asp.net")
# Six months, the figure preload lists require.
_HSTS_MIN = 15552000


# --------------------------------------------------------------------------- #
# Header helpers
# --------------------------------------------------------------------------- #

def _header(headers: List[Tuple[str, str]], name: str) -> Optional[str]:
    name = name.lower()
    for h in headers:
        if len(h) >= 2 and str(h[0]).lower() == name:
            return str(h[1])
    return None


def _all_headers(headers: List[Tuple[str, str]], name: str) -> List[str]:
    name = name.lower()
    return [str(h[1]) for h in headers if len(h) >= 2 and str(h[0]).lower() == name]


def parse_cookie(raw: str) -> Dict[str, Any]:
    """Name and flags of one Set-Cookie value."""
    parts = [p.strip() for p in (raw or "").split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and parts[0] else ""
    flags = {p.split("=", 1)[0].strip().lower() for p in parts[1:] if p}
    samesite = None
    for p in parts[1:]:
        if p.lower().startswith("samesite"):
            _, _, v = p.partition("=")
            samesite = v.strip().lower() or None
    return {"name": name, "secure": "secure" in flags,
            "httponly": "httponly" in flags, "samesite": samesite}


def is_session_cookie(name: str) -> bool:
    n = (name or "").lower()
    return any(h in n for h in _SESSION_HINTS)


def csp_weaknesses(csp: str) -> List[str]:
    """Which parts of a Content-Security-Policy defeat its own purpose."""
    out: List[str] = []
    low = (csp or "").lower()
    if not low.strip():
        return out
    script = ""
    for directive in low.split(";"):
        d = directive.strip()
        if d.startswith("script-src") or (d.startswith("default-src") and not script):
            script = d
    if "'unsafe-inline'" in script:
        out.append("script-src allows 'unsafe-inline' - an injected <script> executes")
    if "'unsafe-eval'" in script:
        out.append("script-src allows 'unsafe-eval'")
    if " *" in f" {script}" or script.endswith(" *"):
        out.append("script-src allows any origin (*)")
    if "data:" in script:
        out.append("script-src allows data: URIs")
    if "frame-ancestors" not in low:
        out.append("no frame-ancestors directive (clickjacking not covered by CSP)")
    return out


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

async def analyze_http_posture(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    try:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                'SELECT url, host, status_code, response_headers_json '
                'FROM flows WHERE response_headers_json IS NOT NULL '
                'ORDER BY "timestamp" DESC LIMIT $1', MAX_FLOWS)
    except Exception:  # noqa: BLE001 - no proxy data is a normal state
        logger.debug("http_posture: could not read flows")
        return {"skipped": 1}

    # host -> what we saw. First (most recent) response per host wins for the
    # header checks; cookies are collected across all of them.
    seen: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        host = (r["host"] or "").lower()
        if not host or not eng.host_in_scope(host):
            continue
        try:
            headers = json.loads(r["response_headers_json"] or "[]")
        except (TypeError, ValueError):
            continue
        if not isinstance(headers, list):
            continue
        entry = seen.setdefault(host, {"headers": headers, "url": r["url"],
                                       "https": str(r["url"] or "").startswith("https"),
                                       "cookies": []})
        entry["cookies"].extend(_all_headers(headers, "set-cookie"))

    findings: List[Finding] = []
    for host, data in seen.items():
        findings.extend(_host_findings(host, data))

    if findings:
        await save_analysis_job(engagement_id, "http_posture", findings,
                                target=eng.target_host or eng.target_url)
    return {"hosts": len(seen), "findings": len(findings)}


def _host_findings(host: str, data: Dict[str, Any]) -> List[Finding]:
    headers: List[Tuple[str, str]] = data["headers"]
    url: str = data["url"] or f"https://{host}/"
    https: bool = bool(data["https"])
    out: List[Finding] = []

    def add(sev: str, title: str, desc: str, evidence: str, vclass: str,
            **meta: Any) -> None:
        out.append(Finding(severity=sev, title=title, description=desc,
                           target=url, evidence=evidence[:600],
                           metadata={"vuln_class": vclass, "host": host,
                                     "tool": "http_posture", **meta}))

    # ---- cookies (Session Management) ----
    reported: set = set()
    for raw in data["cookies"]:
        c = parse_cookie(raw)
        if not c["name"] or c["name"] in reported:
            continue
        reported.add(c["name"])
        session = is_session_cookie(c["name"])
        problems = []
        if session and not c["httponly"]:
            problems.append("no HttpOnly (readable by JavaScript, so XSS steals it)")
        if https and not c["secure"]:
            problems.append("no Secure (sent over plaintext HTTP too)")
        if not c["samesite"]:
            problems.append("no SameSite (sent on cross-site requests - CSRF)")
        elif c["samesite"] == "none" and not c["secure"]:
            problems.append("SameSite=None without Secure (browsers reject it)")
        if problems:
            add("medium" if session else "low",
                f"Cookie '{c['name']}' is missing protections on {host}",
                "; ".join(problems) + ".",
                raw, "cookie_security", cookie=c["name"], session=session)

    # ---- CSP / clickjacking (Client-side) ----
    csp = _header(headers, "content-security-policy")
    xfo = _header(headers, "x-frame-options")
    if not csp:
        add("medium", f"No Content-Security-Policy on {host}",
            "Nothing constrains where scripts may be loaded or executed from, so "
            "any injected markup runs with the page's full privileges.",
            "Content-Security-Policy: (absent)", "security_headers")
    else:
        weak = csp_weaknesses(csp)
        if weak:
            add("medium", f"Weak Content-Security-Policy on {host}",
                "The policy is present but does not stop script injection: "
                + "; ".join(weak) + ".",
                f"Content-Security-Policy: {csp}", "security_headers",
                weaknesses=weak)
    frame_ok = bool(xfo) or (csp and "frame-ancestors" in csp.lower())
    if not frame_ok:
        add("medium", f"{host} can be framed (clickjacking)",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so "
            "the page can be embedded and its clicks hijacked.",
            "X-Frame-Options: (absent); CSP frame-ancestors: (absent)",
            "clickjacking")

    # ---- transport ----
    if https:
        hsts = _header(headers, "strict-transport-security")
        if not hsts:
            add("medium", f"No HSTS on {host}",
                "Without Strict-Transport-Security a first or downgraded request can "
                "be intercepted in plaintext.",
                "Strict-Transport-Security: (absent)", "security_headers")
        else:
            age = 0
            for part in hsts.split(";"):
                if part.strip().lower().startswith("max-age"):
                    try:
                        age = int(part.split("=", 1)[1].strip())
                    except (IndexError, ValueError):
                        age = 0
            if age < _HSTS_MIN:
                add("low", f"HSTS max-age is short on {host}",
                    f"max-age={age}s is below the six months (15552000s) browsers "
                    "and preload lists expect.",
                    f"Strict-Transport-Security: {hsts}", "security_headers",
                    max_age=age)

    # ---- misc hardening ----
    if not _header(headers, "x-content-type-options"):
        add("low", f"No X-Content-Type-Options on {host}",
            "Browsers may MIME-sniff a response and execute it as a different type.",
            "X-Content-Type-Options: (absent)", "security_headers")
    if not _header(headers, "referrer-policy"):
        add("info", f"No Referrer-Policy on {host}",
            "Full URLs (including tokens in paths or queries) leak to third parties "
            "in the Referer header.",
            "Referrer-Policy: (absent)", "security_headers")

    # ---- version disclosure ----
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = _header(headers, name)
        # A bare product name is fine; a version is what feeds a CVE lookup.
        if value and any(ch.isdigit() for ch in value):
            add("low", f"{name.title()} discloses a version on {host}",
                "The exact component version is advertised, which hands an attacker "
                "the CVE list for it without a single probe.",
                f"{name}: {value}", "information_disclosure", header=name)

    return out
