"""Materialise the captured JavaScript so the file-based tools can read it.

retire.js (known-vulnerable client libraries) and jsluice (AST-based URL and
secret extraction) do not speak HTTP - they read files. The proxy already
captured the bundles, so this writes those bodies into the host's artifact
directory rather than fetching anything a second time.

Timing is the whole reason this is a separate step. `analyze_js` runs in the
finalisation pass, after every scan phase is over, so a retire.js task
scheduled in vuln analysis would have found an empty directory. The
orchestrator calls this at the recon/mapping -> vuln-analysis boundary, which
is the first moment the crawl has driven traffic through the proxy and still
early enough for the results to change what gets scanned.

Read-only and idempotent: filenames are derived from the URL, so running it
twice rewrites the same files instead of accumulating copies.
"""
from __future__ import annotations

import logging
from typing import Dict
from urllib.parse import urlparse

from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.artifacts import js_dir, safe_filename, write_artifact

logger = logging.getLogger("syphax.analysis.js_cache")

MAX_FLOWS = 400
MAX_BODY = 2 * 1024 * 1024

# Content types worth handing to a JavaScript parser. Source maps and JSON are
# included: jsluice finds endpoints in both, and a .map often carries the
# original, unminified sources.
JS_CONTENT = ("javascript", "ecmascript", "sourcemap")
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".map")


def looks_like_js(url: str, content_type: str) -> bool:
    ct = (content_type or "").lower()
    if any(token in ct for token in JS_CONTENT):
        return True
    path = (urlparse(url or "").path or "").lower()
    return path.endswith(JS_SUFFIXES)


async def materialise_js(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    flows_repo = FlowRepository()
    summaries = await flows_repo.list_flows(limit=1000)
    in_scope = [f for f in summaries
                if eng.host_in_scope((urlparse(f.url).hostname or "").lower())]

    written = skipped = 0
    for f in in_scope[:MAX_FLOWS]:
        if not looks_like_js(f.url, getattr(f, "response_content_type", "") or ""):
            continue
        full = await flows_repo.get_flow(f.id)
        if not full:
            continue
        body = full.get("response_body_preview") or {}
        if body.get("encoding") != "text":
            continue
        text = (body.get("text") or "")[:MAX_BODY]
        if not text:
            continue
        saved = write_artifact(js_dir(f.url), safe_filename(f.url, suffix=".js"), text)
        if saved is None:
            skipped += 1
        else:
            written += 1

    logger.info("[%s] js-cache: wrote %d file(s), %d unwritable",
                engagement_id, written, skipped)
    return {"written": written, "skipped": skipped}
