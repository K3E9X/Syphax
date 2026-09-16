"""One GET of the root, and the three files the web agrees are public.

Everything the fingerprinter, the header review and the redirect trail need
comes from here, and it is bounded by app/recon/budget.py rather than by
judgement: the paths are a constant, the count is capped at runtime, and the
methods are GET and HEAD.

The request count is asserted rather than assumed. A future change that adds a
loop here would otherwise quietly turn a pre-engagement view - which by
definition has no authorized scope to check against - into a scanner.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.recon import budget
from app.recon.target import Target

logger = logging.getLogger("syphax.recon.http")

# Security headers, and what their absence actually costs. Reported as facts
# with consequences rather than as a grade: a missing CSP on a static brochure
# site is not the same finding as a missing CSP on an authenticated app, and
# this view does not know which one it is looking at.
SECURITY_HEADERS = {
    "strict-transport-security":
        "without it, a first visit over http can be intercepted before the redirect",
    "content-security-policy":
        "without it, any injected script runs with the page's full privileges",
    "x-frame-options":
        "without it (and without CSP frame-ancestors), the page can be framed - clickjacking",
    "x-content-type-options":
        "without nosniff, a response the browser guesses wrong about can execute",
    "referrer-policy":
        "without it, full URLs - including anything in a query string - leak to third parties",
    "permissions-policy":
        "without it, embedded content inherits camera, microphone and geolocation access",
}

# Headers that say more than they mean to.
DISCLOSING_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                      "x-generator", "x-drupal-cache", "x-runtime", "x-turbo-charged-by")


@dataclass
class Probe:
    requests_made: int = 0
    root: Optional[Dict[str, Any]] = None
    redirects: List[Dict[str, Any]] = field(default_factory=list)
    files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    error: str = ""


def _client(timeout):
    import httpx  # noqa: PLC0415
    from app.scans.identity import current_profile  # noqa: PLC0415

    profile = current_profile()
    headers = {"User-Agent": str(profile["ua"]), **dict(profile["headers"])}
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,      # followed by hand, so the chain is visible
        verify=False,                # an invalid certificate is a finding, not a wall
        headers=headers,
    )


async def probe(target: Target) -> Probe:
    import httpx  # noqa: PLC0415

    result = Probe()
    timeout = httpx.Timeout(budget.READ_TIMEOUT, connect=budget.CONNECT_TIMEOUT)

    try:
        async with _client(timeout) as client:
            root = await _follow(client, target.url_for(target.path or "/"), result)
            if root is None:
                result.error = result.error or "the target did not answer"
                return result
            result.root = root

            for path in budget.PROBE_PATHS:
                if path == "/":
                    continue
                if result.requests_made >= budget.MAX_TARGET_REQUESTS:
                    break
                result.files[path] = await _fetch_public_file(
                    client, target.url_for(path), result)
    except Exception as exc:  # noqa: BLE001 - every transport error is "no answer"
        result.error = _readable(exc)
    return result


async def _follow(client, url: str, result: Probe) -> Optional[Dict[str, Any]]:
    """GET, following redirects by hand so the chain is reportable.

    The chain is worth showing on its own: an http->https upgrade, a redirect
    to a login page and a redirect to a completely different domain are three
    very different starting points, and `follow_redirects=True` hides all three
    behind one final response.
    """
    current = url
    for _ in range(budget.MAX_REDIRECTS + 1):
        if result.requests_made >= budget.MAX_TARGET_REQUESTS:
            result.error = "request budget reached"
            return None
        response = await _get(client, current, result)
        if response is None:
            return None
        if response["status"] in (301, 302, 303, 307, 308) and response["headers"].get("location"):
            location = response["headers"]["location"]
            result.redirects.append({
                "from": current, "status": response["status"], "to": location,
            })
            current = _absolute(current, location)
            continue
        return response
    result.redirects.append({"from": current, "status": 0,
                             "to": f"stopped after {budget.MAX_REDIRECTS} redirects"})
    return None


async def _get(client, url: str, result: Probe) -> Optional[Dict[str, Any]]:
    import httpx  # noqa: PLC0415

    result.requests_made += 1
    try:
        response = await client.get(url)
    except httpx.HTTPError as exc:
        result.error = _readable(exc)
        return None

    body = response.content[:budget.MAX_BODY_BYTES]
    text = body.decode(response.encoding or "utf-8", "replace")
    headers = {k.lower(): v for k, v in response.headers.items()}
    return {
        "url": str(response.url),
        "status": response.status_code,
        "reason": response.reason_phrase,
        "headers": headers,
        "cookies": _cookie_names(response),
        # The RAW Set-Cookie lines, because the flags live there. A dict of
        # headers folds repeated Set-Cookie into one comma-joined value, and a
        # cookie value containing a comma then makes the flags unparseable.
        "set_cookie": list(response.headers.get_list("set-cookie")),
        "body": text,
        "body_bytes": len(response.content),
        "truncated": len(response.content) > len(body),
        "title": _title(text),
        "http_version": response.http_version,
        "elapsed_ms": round(response.elapsed.total_seconds() * 1000) if response.elapsed else None,
    }


async def _fetch_public_file(client, url: str, result: Probe) -> Dict[str, Any]:
    import httpx  # noqa: PLC0415

    result.requests_made += 1
    try:
        response = await client.get(url)
    except httpx.HTTPError as exc:
        return {"status": 0, "error": _readable(exc)}
    body = response.content[:8192].decode(response.encoding or "utf-8", "replace")
    present = response.status_code == 200 and bool(body.strip())
    return {
        "status": response.status_code,
        "present": present,
        # Truncated hard: this is a preview so the operator can see whether it
        # is worth reading, not a copy of the file.
        "preview": body[:2000] if present else "",
        "bytes": len(response.content),
    }


def _cookie_names(response) -> List[str]:
    names: List[str] = []
    for raw in response.headers.get_list("set-cookie"):
        names.append(raw.split("=", 1)[0].strip())
    return names


def _title(text: str) -> str:
    import re  # noqa: PLC0415
    match = re.search(r"<title[^>]*>(.{0,200}?)</title>", text, re.IGNORECASE | re.DOTALL)
    return " ".join(match.group(1).split()) if match else ""


def _absolute(base: str, location: str) -> str:
    from urllib.parse import urljoin  # noqa: PLC0415
    return urljoin(base, location)


def _readable(exc: Exception) -> str:
    import httpx  # noqa: PLC0415
    if isinstance(exc, httpx.ConnectTimeout):
        return "connection timed out"
    if isinstance(exc, httpx.ReadTimeout):
        return "the target accepted the connection but never answered"
    if isinstance(exc, httpx.ConnectError):
        return f"could not connect: {exc}"
    return str(exc) or exc.__class__.__name__


# ---- pure review of what came back ------------------------------------------

def review_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Security headers present, missing, and what each absence costs."""
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    present, missing = [], []
    for name, consequence in SECURITY_HEADERS.items():
        if name in lower:
            present.append({"name": name, "value": lower[name][:300]})
        else:
            missing.append({"name": name, "consequence": consequence})

    # CSP frame-ancestors supersedes X-Frame-Options; reporting both as missing
    # when one covers the other is how a header review loses its credibility.
    csp = lower.get("content-security-policy", "")
    if "frame-ancestors" in csp.lower():
        missing = [m for m in missing if m["name"] != "x-frame-options"]

    disclosing = [{"name": h, "value": lower[h][:200]}
                  for h in DISCLOSING_HEADERS if h in lower]
    return {"present": present, "missing": missing, "disclosing": disclosing}


def review_cookies(set_cookie_headers: List[str]) -> List[Dict[str, Any]]:
    """Per-cookie flags. Session cookies without HttpOnly and Secure are the
    two that matter, and they are visible from the first response."""
    out = []
    for raw in set_cookie_headers or []:
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        same_site = ""
        for part in low.split(";"):
            part = part.strip()
            if part.startswith("samesite="):
                same_site = part.split("=", 1)[1]
        out.append({
            "name": name,
            "http_only": "httponly" in low,
            "secure": "secure" in low,
            "same_site": same_site or "unset",
        })
    return out
