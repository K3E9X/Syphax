"""Hidden parameter discovery (arjun-style), traffic-aware.

Scanners only fuzz the parameters they can see. This widens that surface:

  * Passive - harvest the real parameter names the app already uses, from every
    captured request (query string + JSON/form body keys). These are high-signal
    because the app demonstrably reads them.
  * Active - for in-scope GET endpoints that expose no parameters yet, probe a
    candidate set (harvested names + a common-name list) with unique markers and
    detect which ones reflect in the response. Reflected params are immediate
    XSS/open-redirect/SSRF leads.

Discovered parameters are seeded back as parameterised endpoint assets, so the
param-gated exploitation items (sqlmap / dalfox / nuclei -dast) test them.

Read-only and in-scope (GET via SafePoC). Stored as a job (tool="params").
"""
from __future__ import annotations

import logging
import secrets
from typing import Dict, List, Set
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.models import Finding
from app.validation.safe_poc import SafePoC, ScopeError

logger = logging.getLogger("syphax.analysis.params")

MAX_ENDPOINTS = 15
BATCH = 25
MAX_CANDIDATES = 80
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp")

# Common hidden-parameter names worth probing when an endpoint exposes none.
_COMMON_PARAMS = [
    "id", "user", "user_id", "uid", "account", "page", "q", "query", "search",
    "s", "redirect", "redirect_uri", "url", "next", "return", "returnurl",
    "callback", "continue", "dest", "destination", "file", "path", "filename",
    "dir", "folder", "download", "lang", "locale", "debug", "test", "admin",
    "token", "key", "api_key", "access", "role", "format", "type", "view",
    "template", "include", "doc", "image", "img", "ref", "source", "data",
]


async def analyze_params(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    flows_repo = FlowRepository()
    summaries = await flows_repo.list_flows(limit=1000)
    in_scope = [f for f in summaries
                if eng.host_in_scope((urlparse(f.url).hostname or "").lower())]

    # ---- passive: harvest real parameter names from captured traffic ----
    harvested: Set[str] = set()
    for f in in_scope:
        harvested.update(_query_keys(f.url))
    # Bodies need the full flow; sample to bound DB reads.
    for f in in_scope[:150]:
        full = await flows_repo.get_flow(f.id)
        if full:
            harvested.update(_body_keys(full))

    candidates = _candidate_list(harvested)

    safe = SafePoC(in_scope=eng.host_in_scope)
    findings: List[Finding] = []

    if harvested:
        findings.append(Finding(
            severity="info",
            title=f"{len(harvested)} parameter name(s) observed in traffic",
            description="Real parameter names the application reads (from captured "
                        "requests) - reuse them when testing other endpoints.",
            target=eng.target_url,
            evidence=", ".join(sorted(harvested)[:60]),
            metadata={"vuln_class": "param_discovery", "status": "unconfirmed",
                      "confidence": 0.3, "kind": "harvested"},
        ))

    # ---- active: probe param-less GET endpoints for reflected params ----
    probed = 0
    seeded_urls: List[str] = []
    seen_paths: Set[str] = set()
    for f in in_scope:
        if probed >= MAX_ENDPOINTS:
            break
        if (f.method or "").upper() != "GET" or _is_static(f.url):
            continue
        parsed = urlparse(f.url)
        if parsed.query:
            continue  # already parameterised; the fuzzers see it already
        if parsed.path in seen_paths:
            continue
        seen_paths.add(parsed.path)
        probed += 1

        reflected = await _probe_reflection(safe, f.url, candidates)
        if not reflected:
            continue
        seed = _with_params(f.url, reflected)
        seeded_urls.append(seed)
        findings.append(Finding(
            severity="low",
            title=f"Reflected hidden parameter(s) on {parsed.path or '/'}",
            description="Undocumented parameters are reflected in the response - "
                        "test them for XSS / open redirect / SSRF.",
            target=f.url,
            evidence=f"Reflected params: {', '.join(reflected)}\nSeeded: {seed}",
            metadata={"vuln_class": "param_discovery", "status": "likely",
                      "confidence": 0.5, "kind": "reflected", "params": reflected},
        ))

    await save_analysis_job(engagement_id, "params", findings, target="(captured traffic)")
    seeded = await _seed(engagement_id, eng, seeded_urls)

    logger.info("[%s] params: harvested=%d probed=%d reflected_endpoints=%d seeded=%d",
                engagement_id, len(harvested), probed, len(seeded_urls), seeded)
    return {"harvested": len(harvested), "probed": probed,
            "reflected_endpoints": len(seeded_urls), "seeded": seeded}


# --------------------------------------------------------------------------- #

def _query_keys(url: str) -> List[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if k]


def _body_keys(full: Dict) -> List[str]:
    body = full.get("request_body_preview") or {}
    if body.get("encoding") != "text":
        return []
    text = body.get("text") or ""
    ctype = (full.get("request_content_type") or "").lower()
    if "json" in ctype:
        import json
        try:
            obj = json.loads(text)
            return [str(k) for k in obj] if isinstance(obj, dict) else []
        except Exception:  # noqa: BLE001
            return []
    if "form-urlencoded" in ctype or "=" in text:
        return [k for k, _ in parse_qsl(text, keep_blank_values=True) if k]
    return []


def _candidate_list(harvested: Set[str]) -> List[str]:
    # Harvested names first (highest signal), then common names, de-duped.
    out: List[str] = []
    for name in list(harvested) + _COMMON_PARAMS:
        n = name.strip()
        if n and n.isascii() and len(n) <= 40 and n not in out:
            out.append(n)
        if len(out) >= MAX_CANDIDATES:
            break
    return out


async def _probe_reflection(safe: SafePoC, url: str, candidates: List[str]) -> List[str]:
    """Send candidates (batched) with unique markers; return reflected names."""
    reflected: List[str] = []
    for i in range(0, len(candidates), BATCH):
        batch = candidates[i:i + BATCH]
        markers = {p: "axhk" + secrets.token_hex(3) for p in batch}
        probe_url = _with_query(url, markers)
        try:
            resp = await safe.fetch(probe_url, method="GET")
        except ScopeError:
            return reflected
        if resp is None:
            continue
        for p in _reflected(markers, resp.text):
            if p not in reflected:
                reflected.append(p)
    return reflected


def _reflected(markers: Dict[str, str], text: str) -> List[str]:
    return [p for p, m in markers.items() if m in text]


def _with_query(url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode(params)))


def _with_params(url: str, names: List[str]) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode({n: "1" for n in names})))


def _is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXT)


async def _seed(engagement_id: str, eng, urls: List[str]) -> int:
    if not urls:
        return 0
    try:
        from app.orchestrator.state import EngagementState
    except Exception:  # noqa: BLE001
        return 0
    state = EngagementState(engagement_id)
    count = 0
    for url in urls:
        try:
            await state.add_asset("endpoint", url, source="param-discovery")
            count += 1
        except Exception:  # noqa: BLE001
            continue
    return count
