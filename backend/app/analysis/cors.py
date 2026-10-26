"""CORS misconfiguration test over captured traffic + the base URL.

CORS isn't found by the param fuzzers: it lives in response headers. We replay
in-scope endpoints with a forged Origin and inspect the CORS response headers.
The dangerous case is an endpoint that reflects an arbitrary Origin *and* sets
Access-Control-Allow-Credentials: true - any site can then read the victim's
authenticated responses.

Read-only and in-scope only (one GET per endpoint through SafePoC).

Stored as a synthetic job (tool="cors").
"""
from __future__ import annotations

import logging
import secrets
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app.limits import cap
from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.models import Finding
from app.validation.safe_poc import SafePoC, ScopeError

logger = logging.getLogger("syphax.analysis.cors")

MAX_ENDPOINTS = cap(30)
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp")


async def analyze_cors(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    evil = f"https://evil-{secrets.token_hex(4)}.example"
    safe = SafePoC(in_scope=eng.host_in_scope)

    # Candidate URLs: the base target + in-scope captured GETs, de-duped by path.
    urls: List[str] = [eng.target_url]
    seen_paths = {urlparse(eng.target_url).path}
    try:
        flows = await FlowRepository().list_flows(limit=1000)
    except Exception:  # noqa: BLE001
        flows = []
    for f in flows:
        if (f.method or "").upper() != "GET":
            continue
        host = (urlparse(f.url).hostname or "").lower()
        if not eng.host_in_scope(host):
            continue
        path = urlparse(f.url).path
        if path in seen_paths or _is_static(f.url):
            continue
        seen_paths.add(path)
        urls.append(f.url)
        if len(urls) >= MAX_ENDPOINTS:
            break

    findings: List[Finding] = []
    for url in urls:
        verdict = await _probe(safe, url, evil)
        if verdict is None:
            continue
        sev, status, conf, poc = verdict
        findings.append(Finding(
            severity=sev,
            title=f"CORS misconfiguration on {urlparse(url).path or '/'}",
            description="Cross-Origin Resource Sharing policy allows an untrusted origin.",
            target=url,
            evidence=poc,
            metadata={"vuln_class": "cors", "status": status, "confidence": conf},
        ))

    await save_analysis_job(engagement_id, "cors", findings, target="(captured traffic)")
    logger.info("[%s] cors: probed=%d findings=%d", engagement_id, len(urls), len(findings))
    return {"probed": len(urls), "findings": len(findings)}


async def _probe(safe: SafePoC, url: str, evil: str) -> Optional[tuple]:
    try:
        resp = await safe.fetch(url, method="GET", headers={"Origin": evil})
    except ScopeError:
        return None
    if resp is None:
        return None
    acao = (resp.headers.get("access-control-allow-origin") or "").strip()
    acac = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()
    if not acao:
        return None

    reflects_evil = acao == evil
    if reflects_evil and acac == "true":
        return ("high", "confirmed", 0.9,
                f"{url} reflects an arbitrary Origin ({evil}) and sets "
                f"Access-Control-Allow-Credentials: true. Any site can read this "
                f"victim's authenticated responses.")
    if reflects_evil:
        return ("medium", "likely", 0.6,
                f"{url} reflects an arbitrary Origin ({evil}) in "
                f"Access-Control-Allow-Origin (no credentials). Untrusted origins "
                f"can read non-credentialed responses.")
    if acao == "*" and acac == "true":
        # Browsers actually reject this combo; flag as a server-config smell.
        return ("low", "unconfirmed", 0.3,
                f"{url} returns Access-Control-Allow-Origin: * with "
                f"Allow-Credentials: true (rejected by browsers, but a misconfig).")
    if acao == "*":
        return ("info", "unconfirmed", 0.25,
                f"{url} allows any origin (Access-Control-Allow-Origin: *) without "
                f"credentials. Fine for public data; review if it serves private data.")
    return None


def _is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXT)
