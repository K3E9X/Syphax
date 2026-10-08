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

MAX_CRAWLED_JS = 60
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

    # The crawler finds the bundles; nothing downloaded them.
    #
    # Until now this read ONLY proxy flows, so on a run where the operator
    # never browsed the target through mitmproxy the cache stayed empty - and
    # jsluice (urls AND secrets), retire.js and js_recon all analysed an empty
    # directory. That is why an autonomous run could finish reporting no
    # secrets at all while katana had already listed every .js bundle.
    fetched = await _fetch_crawled_js(eng, seen_urls={f.url for f in in_scope})
    written += fetched

    logger.info("[%s] js-cache: wrote %d file(s) (%d fetched from crawl), "
                "%d unwritable", engagement_id, written, fetched, skipped)
    return {"written": written, "fetched": fetched, "skipped": skipped}


async def _fetch_crawled_js(eng, *, seen_urls: set) -> int:
    """Download the JavaScript the crawl discovered, in scope, read-only.

    One GET per bundle through SafePoC (scope-enforced, GET/HEAD only). Bounded
    so a crawl that found a thousand chunks does not turn into a thousand
    requests.
    """
    from app.orchestrator.state import EngagementState
    from app.validation.safe_poc import SafePoC, ScopeError

    try:
        assets = await EngagementState(eng.id).assets("endpoint")
    except Exception:  # noqa: BLE001 - no assets is not an error here
        return 0

    urls = []
    for a in assets:
        url = a.value
        if url in seen_urls or not looks_like_js(url, ""):
            continue
        if not eng.host_in_scope((urlparse(url).hostname or "").lower()):
            continue
        urls.append(url)
        if len(urls) >= MAX_CRAWLED_JS:
            break
    if not urls:
        return 0

    safe = SafePoC(in_scope=eng.host_in_scope)
    written = 0
    for url in urls:
        try:
            resp = await safe.fetch(url, method="GET")
        except ScopeError:
            continue
        except Exception:  # noqa: BLE001 - one unreachable bundle is not fatal
            continue
        text = (resp.text if resp else "")[:MAX_BODY]
        if not text.strip():
            continue
        if write_artifact(js_dir(url), safe_filename(url, suffix=".js"), text):
            written += 1
    return written
