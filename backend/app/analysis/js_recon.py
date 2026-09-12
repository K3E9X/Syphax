"""Secret + endpoint mining over captured responses (Tier-1 recon).

Two high-value passes over the traffic captured through the proxy:

  * Secrets - scan EVERY in-scope text response (JS bundles, HTML, JSON API
    responses, source maps) for credentials with a curated set of high-signal
    regexes (the families gitleaks/trufflehog look for). Secrets don't only
    live in JS: they leak in HTML comments, JSON bodies and .map files too.
    A live key is often the single highest-value finding on a target.
  * Endpoints - extract API endpoints/paths referenced in JS (and HTML) so the
    rest of the engagement tests surface that isn't linked from the UI.
    Discovered same-origin endpoints are seeded as engagement assets.

The same captured JavaScript is written to disk for the file-based tools by
app/analysis/js_cache.py - separately, because that has to happen before the
vuln-analysis phase and this analyzer runs after every scan.

Everything is read-only: we only parse bodies already captured.

Stored as a synthetic job (tool="js-recon").
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.js_recon")

MAX_SCAN_FLOWS = 300
MAX_BODY = 2 * 1024 * 1024

# High-signal secret patterns. (name, regex, severity). Kept deliberately tight
# to minimise false positives - generic "password=" style matches are noisy.
_SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]", str]] = [
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), "high"),
    ("AWS secret access key", re.compile(r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z/+]{40})['\"]"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{20,}\b"), "high"),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), "critical"),
    ("Stripe restricted key", re.compile(r"\brk_live_[0-9a-zA-Z]{20,}\b"), "high"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "medium"),
    ("Twilio account SID", re.compile(r"\bAC[0-9a-fA-F]{32}\b"), "medium"),
    ("SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"), "high"),
    ("Mailgun key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "medium"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "low"),
    ("Firebase database URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), "low"),
    ("Basic-auth credentials in URL", re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"), "high"),
    ("Generic API key/secret assignment",
     re.compile(r"(?i)(?:api[_-]?key|api[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{16,})['\"]"),
     "medium"),
]

# Endpoint references: string literals that look like a path or URL.
_ENDPOINT_RE = re.compile(r"""['"`](/(?:api|v\d|rest|graphql|admin|internal|user|account|auth)[A-Za-z0-9_\-/.?=&{}:]*)['"`]""")
_FULLURL_RE = re.compile(r"""['"`](https?://[A-Za-z0-9.\-]+/[A-Za-z0-9_\-/.?=&{}:]*)['"`]""")

_NOISE = ("/api/placeholder", "schema.org", "w3.org", "googleapis.com/css")


async def analyze_js(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    flows_repo = FlowRepository()
    summaries = await flows_repo.list_flows(limit=1000)
    in_scope = [f for f in summaries
                if eng.host_in_scope((urlparse(f.url).hostname or "").lower())]

    findings: List[Finding] = []
    endpoints: set[str] = set()
    secrets_seen: set[str] = set()

    scanned = 0
    js_seen = 0
    for f in in_scope:
        if scanned >= MAX_SCAN_FLOWS:
            break
        full = await flows_repo.get_flow(f.id)
        if not full:
            continue
        body = full.get("response_body_preview") or {}
        if body.get("encoding") != "text":
            continue
        text = (body.get("text") or "")[:MAX_BODY]
        if not text:
            continue
        scanned += 1
        ctype = (full.get("response_content_type") or "").lower()
        label = _content_label(ctype, f.url)
        is_js = _looks_like_js(f)
        if is_js:
            js_seen += 1

        # ---- secrets (every text response) ----
        for name, pattern, severity in _SECRET_PATTERNS:
            for m in pattern.finditer(text):
                raw = m.group(0)
                key = f"{name}:{raw[:60]}"
                if key in secrets_seen:
                    continue
                secrets_seen.add(key)
                findings.append(Finding(
                    severity=severity,
                    title=f"Secret leaked in {label}: {name}",
                    description=f"A {name} appears in a {label.lower()} response served at {f.url}.",
                    target=f.url,
                    evidence=f"{name} found in {f.url} ({label})\n  match: {_redact(raw)}",
                    metadata={"vuln_class": "secret_exposure", "status": "confirmed",
                              "confidence": 0.9, "secret_type": name, "source": f.url},
                ))

        # ---- endpoints (JS and HTML carry the surface) ----
        if is_js or "html" in ctype:
            for m in _ENDPOINT_RE.finditer(text):
                endpoints.add(m.group(1))
            for m in _FULLURL_RE.finditer(text):
                u = m.group(1)
                if eng.host_in_scope((urlparse(u).hostname or "").lower()):
                    endpoints.add(u)

    endpoints = {e for e in endpoints if not any(n in e for n in _NOISE)}

    if endpoints:
        sample = sorted(endpoints)[:80]
        findings.append(Finding(
            severity="info",
            title=f"{len(endpoints)} endpoint(s) discovered in client code",
            description="Endpoints/paths referenced in JS/HTML - additional attack "
                        "surface not necessarily linked from the UI.",
            target=eng.target_url,
            evidence="\n".join(sample) + ("\n..." if len(endpoints) > len(sample) else ""),
            metadata={"vuln_class": "endpoint_discovery", "status": "unconfirmed",
                      "confidence": 0.3, "count": len(endpoints)},
        ))

    await save_analysis_job(engagement_id, "js-recon", findings, target="(captured responses)")

    seeded = await _seed_endpoints(engagement_id, eng, endpoints)

    secret_n = sum(1 for x in findings if x.metadata.get("vuln_class") == "secret_exposure")
    logger.info("[%s] js-recon: scanned=%d (js=%d) secrets=%d endpoints=%d seeded=%d",
                engagement_id, scanned, js_seen, secret_n, len(endpoints), seeded)
    return {"scanned": scanned, "js_flows": js_seen, "secrets": secret_n,
            "endpoints": len(endpoints), "seeded": seeded}


def _content_label(ctype: str, url: str) -> str:
    path = urlparse(url).path.lower()
    if "javascript" in ctype or "ecmascript" in ctype or path.endswith((".js", ".mjs")):
        return "JavaScript"
    if path.endswith(".map") or "sourcemap" in ctype:
        return "source map"
    if "html" in ctype:
        return "HTML"
    if "json" in ctype:
        return "API response"
    return "response"


def _looks_like_js(flow) -> bool:
    ct = (flow.response_content_type or "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return True
    path = urlparse(flow.url).path.lower()
    return path.endswith(".js") or path.endswith(".mjs")


def _redact(raw: str) -> str:
    """Show enough to identify the secret, not enough to fully expose it."""
    raw = raw.strip()
    if len(raw) <= 12:
        return raw[:4] + "***"
    return raw[:8] + "..." + raw[-4:]


async def _seed_endpoints(engagement_id: str, eng, endpoints: set) -> int:
    """Add discovered same-origin endpoints to the engagement state as assets."""
    try:
        from app.orchestrator.state import EngagementState
    except Exception:  # noqa: BLE001
        return 0
    state = EngagementState(engagement_id)
    base = eng.target_url
    count = 0
    for ep in endpoints:
        if count >= 200:
            break
        url = ep if ep.startswith("http") else urljoin(base, ep)
        host = (urlparse(url).hostname or "").lower()
        if not eng.host_in_scope(host):
            continue
        try:
            await state.add_asset("endpoint", url, source="js")
            count += 1
        except Exception:  # noqa: BLE001
            continue
    return count
