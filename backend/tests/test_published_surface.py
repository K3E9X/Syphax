"""The target's own published surface, and its API contract.

"La pre-recon est bien cablee pour tout ce qu'on veut faire ? surtout en terme
d'endpoint et api."

Pre-recon is passive by design - DNS, CT logs, TLS, a bounded HTTP probe - and
endpoint discovery belongs to the run. But two things it already had in hand
were being thrown away, and both are about endpoints and APIs.
"""
from __future__ import annotations

import inspect as _inspect

import pytest

from app.prerecon.endpoints import MAX_PATHS, paths_from, sitemaps_from


ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /internal/export
Allow: /public/reports
Disallow: /*.bak$
Disallow: /
Sitemap: https://t.example/sitemap.xml
"""

SITEMAP = ("<urlset><url><loc>https://t.example/a</loc></url>"
           "<url><loc>https://t.example/api/v1/users</loc></url></urlset>")


# ---- robots.txt is a list of what the owner did not want found ----------

def test_disallow_is_read_as_a_path_not_as_a_prohibition():
    """It is the owner's own list of the paths they did not want indexed -
    the admin panel, the internal tooling, the export endpoints."""
    paths = paths_from("robots.txt", ROBOTS)
    assert "/admin" in paths
    assert "/internal/export" in paths


def test_allow_counts_too():
    assert "/public/reports" in paths_from("robots.txt", ROBOTS)


def test_a_wildcard_is_a_pattern_not_a_path():
    """Feeding "/*.bak$" to a scanner produces a request for a file called
    "*.bak$"."""
    assert not any("*" in p or "$" in p for p in paths_from("robots.txt", ROBOTS))


def test_disallow_slash_is_not_an_endpoint():
    assert "/" not in paths_from("robots.txt", ROBOTS)


def test_a_sitemap_reference_is_followed_up():
    assert sitemaps_from(ROBOTS) == ["https://t.example/sitemap.xml"]


def test_a_sitemap_gives_its_locations():
    paths = paths_from("sitemap.xml", SITEMAP)
    assert paths == ["/a", "/api/v1/users"]


def test_another_file_gives_nothing():
    assert paths_from("security.txt", "Contact: mailto:x@y") == []


def test_the_parser_is_bounded():
    """A sitemap can list a hundred thousand URLs, and returning all of them
    would reproduce the flood this codebase just spent a day removing."""
    huge = "<urlset>" + "".join(
        f"<loc>https://t.example/p{i}</loc>" for i in range(5000)) + "</urlset>"
    assert len(paths_from("sitemap.xml", huge)) == MAX_PATHS


def test_pre_recon_parses_what_it_already_fetched():
    """Zero extra requests: the bodies were downloaded and discarded."""
    from app.prerecon import http_probe

    src = _inspect.getsource(http_probe)
    assert "paths_from(url, body)" in src


# ---- the API contract that left schemathesis dormant --------------------

def test_the_schema_locations_cover_the_usual_frameworks():
    from app.analysis.surface_seed import SCHEMA_PATHS

    joined = " ".join(SCHEMA_PATHS)
    for expected in ("openapi.json", "swagger.json", "v3/api-docs",
                     ".well-known"):
        assert expected in joined, expected


@pytest.mark.parametrize("item_id", ["VULN-API-CONTRACT"])
def test_what_the_schema_asset_unlocks(item_id):
    """schemathesis property-tests EVERY documented operation, and applies only
    to an asset whose URL says openapi/swagger/api-docs. Nothing ever created
    one, so the tool was dormant unless a crawl stumbled on a link."""
    from app.methodology.catalog import CATALOG_BY_ID, applies

    item = CATALOG_BY_ID[item_id]
    ctx = {"is_host": False, "requires_params": False, "is_https": True,
           "url": "https://t.example/openapi.json", "source": "api-schema",
           "tech": []}
    assert applies(item, ctx) is True
    ctx_plain = {**ctx, "url": "https://t.example/about"}
    assert applies(item, ctx_plain) is False


def test_an_html_page_is_not_mistaken_for_a_schema():
    """A single-page app answers 200 with index.html for every unknown path.
    Seeding that would hand schemathesis an HTML page and a confusing
    failure."""
    from app.analysis.surface_seed import _SCHEMA_MARKERS

    html = "<!doctype html><html><head><title>App</title></head>"
    assert not any(m in html.lower() for m in _SCHEMA_MARKERS)
    for real in ('{"openapi": "3.0.0", "paths": {}}', "openapi: 3.0.0"):
        assert any(m in real.lower() for m in _SCHEMA_MARKERS), real


def test_the_run_seeds_before_it_plans():
    """Seeded after planning, these endpoints would be discovered in a phase
    that had already chosen what to do."""
    from app.orchestrator import loop

    src = _inspect.getsource(loop.run_engagement_loop)
    assert "seed_published_surface(engagement.id)" in src
    assert src.index("seed_published_surface") < src.index("planner.plan("), \
        "the surface is seeded after the first plan is built"


def test_seeding_never_fails_the_run():
    from app.orchestrator import loop

    src = _inspect.getsource(loop.run_engagement_loop)
    # rsplit: the name appears twice (the import, then the call), and
    # splitting on the first leaves the two-line gap between them.
    block = src.rsplit("seed_published_surface", 1)[1]
    assert "except Exception" in block


def test_it_only_reads():
    """Through SafePoC, so the engagement's scope is enforced."""
    from app.analysis import surface_seed

    src = _inspect.getsource(surface_seed)
    assert "SafePoC" in src
    assert 'method="GET"' in src
    for write in ("POST", "PUT", "DELETE", "PATCH"):
        assert f'method="{write}"' not in src
