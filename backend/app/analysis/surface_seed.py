"""The endpoints a target publishes about itself, and its API contract.

Two sources the run never used, both cheap and both high-yield:

  * robots.txt and sitemap.xml. The owner wrote them. robots.txt is a list of
    the paths they did not want indexed - the admin panel, the internal
    tooling, the export endpoints - and sitemap.xml is their own index of the
    site. Pre-recon already fetched both and nothing read them.

  * the API schema. It is both what schemathesis tests against and what the
    contract audit reads, so the document is stored rather than only noted.
    VULN-API-CONTRACT runs schemathesis, which property-tests
    EVERY documented operation against the API's own OpenAPI contract, and it
    applies only to an asset whose URL says "openapi", "swagger" or
    "api-docs". Nothing ever created such an asset, so the tool was dormant
    unless a crawl happened to stumble on a link to one. Eight well-known
    locations settle it for eight requests.

Read-only GETs through SafePoC, so the engagement's scope is enforced.
"""
from __future__ import annotations

import logging
from typing import Dict, List
from urllib.parse import urljoin

from app.prerecon.endpoints import paths_from, sitemaps_from
from app.validation.safe_poc import SafePoC, ScopeError

logger = logging.getLogger("syphax.analysis.surface_seed")

# Where an OpenAPI/Swagger document lives when nobody hid it.
SCHEMA_PATHS = (
    "/openapi.json", "/swagger.json", "/openapi.yaml",
    "/v3/api-docs", "/swagger/v1/swagger.json",
    "/.well-known/openapi.json", "/api/openapi.json", "/api-docs",
)

# A schema is only a schema if it says so. A SPA that answers 200 with its
# index.html for every unknown path would otherwise hand schemathesis an HTML
# page and a confusing failure.
_SCHEMA_MARKERS = ('"openapi"', '"swagger"', "openapi:", "swagger:", '"paths"')

MAX_SEEDED_PATHS = 150


async def seed_published_surface(engagement_id: str) -> Dict[str, int]:
    """Seed endpoint assets from robots/sitemap, and find the API schema."""
    from app.engagements import EngagementRepository
    from app.orchestrator.state import EngagementState

    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    safe = SafePoC(in_scope=eng.host_in_scope)
    state = EngagementState(engagement_id)
    base = eng.target_url or ""
    seeded = 0
    schema_url = ""

    # --- what the owner published ---------------------------------------
    paths: List[str] = []
    for name in ("/robots.txt", "/sitemap.xml"):
        body = await _body(safe, urljoin(base, name))
        if not body:
            continue
        paths.extend(paths_from(name, body))
        if name == "/robots.txt":
            for sitemap in sitemaps_from(body):
                extra = await _body(safe, sitemap)
                if extra:
                    paths.extend(paths_from("sitemap.xml", extra))

    for path in _unique(paths)[:MAX_SEEDED_PATHS]:
        try:
            await state.add_asset("endpoint", urljoin(base, path),
                                  source="published")
            seeded += 1
        except Exception:  # noqa: BLE001 - one bad path is not the pass
            logger.debug("could not seed %s", path)

    # --- the API contract ------------------------------------------------
    for path in SCHEMA_PATHS:
        url = urljoin(base, path)
        body = await _body(safe, url)
        if not body:
            continue
        head = body[:600].lower()
        if not any(marker in head for marker in _SCHEMA_MARKERS):
            continue
        schema_url = url
        try:
            await state.add_asset("endpoint", url, source="api-schema")
        except Exception:  # noqa: BLE001
            logger.debug("could not seed the schema asset")
        # Keep the document. It was fetched and then thrown away, so the
        # contract audit (analysis/schema_audit) had to hope the crawl would
        # fetch it again through the capture proxy. Written beside the
        # synthesised one, under a different name: this is the vendor's own
        # contract and the audit must never confuse the two.
        try:
            from app.scans.artifacts import OPENAPI, artifact_dir, ensure, write_artifact
            write_artifact(ensure(artifact_dir(base, OPENAPI)),
                           "published.json", body)
        except Exception:  # noqa: BLE001 - the audit can still read the capture
            logger.debug("could not store the published schema")
        break

    await _say(engagement_id, seeded, schema_url)
    return {"seeded": seeded, "schema": 1 if schema_url else 0}


async def _body(safe: SafePoC, url: str) -> str:
    try:
        resp = await safe.fetch(url, method="GET")
    except ScopeError:
        return ""
    except Exception:  # noqa: BLE001 - a missing file is the normal case
        return ""
    if resp is None or resp.status_code != 200:
        return ""
    return (getattr(resp, "text", "") or "")[:200_000]


def _unique(values: List[str]) -> List[str]:
    seen = set()
    out = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


async def _say(engagement_id: str, seeded: int, schema_url: str) -> None:
    try:
        from app import events
        if schema_url:
            await events.emit(
                engagement_id, events.THOUGHT,
                f"API contract found at {schema_url} - schemathesis can now "
                f"property-test every documented operation against it.",
                level=events.LEVEL_INFO)
        if seeded:
            await events.emit(
                engagement_id, events.THOUGHT,
                f"{seeded} endpoint(s) seeded from the target's own robots.txt "
                f"and sitemap.xml - paths the owner published, including the "
                f"ones they asked not to have indexed.",
                level=events.LEVEL_INFO)
        if not seeded and not schema_url:
            await events.emit(
                engagement_id, events.THOUGHT,
                "No robots.txt, sitemap.xml or API schema at the usual "
                "locations, so none of the target's own published surface "
                "could be used.",
                level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001 - reporting never fails the pass
        logger.debug("could not report the seeded surface")
