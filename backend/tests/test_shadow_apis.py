"""Shadow and zombie APIs: OWASP API9, improper inventory management.

API9 is the only item on the API Top 10 that is not a bug in a line of code.
/api/v2 is current, documented and reviewed; /api/v1 is still answering two
years after the team stopped thinking about it. Nobody shipped a vulnerability
into v1 - the vulnerability is that v1 never received the security work v2 did.

What these tests hold in place: candidates are DERIVED from what the
application itself used (never guessed), a soft-404 host cannot manufacture a
shadow API, the auth regression is reported as the access-control break it is
rather than as an inventory note, and everything found is put on the scan
surface instead of only in the report.
"""
from __future__ import annotations

import inspect as _inspect

import pytest

from app.analysis import api_inventory as inv


# ---- candidates come from the application's own paths -----------------

def test_a_versioned_path_yields_its_neighbours_first():
    """A team that ships v3 usually still runs v2 and rarely still runs v1."""
    urls = [c for c, _ in inv.candidates_for("https://t.example/api/v3/users")]
    assert "https://t.example/api/v2/users" in urls
    assert urls.index("https://t.example/api/v2/users") < \
        urls.index("https://t.example/api/v1/users")


def test_the_named_environments_are_probed_in_place_of_the_version():
    urls = [c for c, _ in inv.candidates_for("https://t.example/api/v2/orders")]
    assert "https://t.example/api/internal/orders" in urls
    assert "https://t.example/api/legacy/orders" in urls


def test_the_current_version_is_never_its_own_candidate():
    url = "https://t.example/api/v2/orders"
    assert url not in [c for c, _ in inv.candidates_for(url)]


def test_only_the_first_version_segment_is_rewritten():
    """/api/v1/v2/x has one API version. Rewriting both would invent paths the
    application never had any form of."""
    urls = [c for c, _ in inv.candidates_for("https://t.example/api/v1/v2/x")]
    assert all("/api/v1/" not in u for u in urls)


def test_a_query_string_is_dropped_from_a_candidate():
    """A version sibling is a claim about a path, not about a parameter."""
    urls = [c for c, _ in inv.candidates_for("https://t.example/api/v2/u?id=4")]
    assert all("?" not in u for u in urls)


def test_an_api_path_with_no_version_gets_an_inserted_tier():
    urls = [c for c, _ in inv.candidates_for("https://t.example/api/users")]
    assert "https://t.example/api/v1/users" in urls
    assert "https://t.example/api/internal/users" in urls


def test_an_ordinary_page_produces_no_candidates():
    """Probing /about/v1 and /about/internal is noise, not a hypothesis."""
    assert inv.candidates_for("https://t.example/about") == []
    assert inv.candidates_for("https://t.example/") == []


def test_the_candidate_count_per_path_is_bounded():
    many = inv.candidates_for("https://t.example/api/v5/deep/nested/resource")
    assert len(many) <= inv.MAX_CANDIDATES_PER_PATH


def test_a_date_versioned_api_is_recognised_as_versioned():
    """Stripe-style /2024-01-01/ versioning: the named environments still
    apply even though there is no vN to decrement."""
    urls = [c for c, _ in inv.candidates_for("https://t.example/api/2024-01-01/x")]
    assert "https://t.example/api/internal/x" in urls


@pytest.mark.parametrize("segment,expected", [
    ("v2", ["v1", "v3", "v0", "v4"]),
    ("v1", ["v0", "v2", "v3"]),      # no v-1
    ("v10", ["v9", "v11", "v8", "v12", "v7"]),
    ("beta", []),
    ("users", []),
])
def test_version_siblings_never_go_below_zero(segment, expected):
    assert inv.version_siblings(segment)[:len(expected)] == expected


def test_candidates_are_pure_and_send_nothing():
    src = _inspect.getsource(inv.candidates_for)
    for forbidden in ("await", "fetch", "httpx", "requests"):
        assert forbidden not in src


# ---- a catch-all host must not manufacture a finding per probe ---------

@pytest.mark.parametrize("status,body,expected", [
    (200, "<h1>404 Not Found</h1>", True),
    (200, "Cannot GET /api/v1/users", True),
    (200, "Page introuvable", True),
    (200, '{"users": [{"id": 1}]}', False),
    (404, "not found", False),      # a real 404 is handled by the status check
    (200, "", False),
])
def test_a_200_that_means_not_found_is_not_a_live_version(status, body, expected):
    assert inv.is_soft_404(status, body) is expected


def test_a_404_sibling_is_not_reported():
    """The common case by far: v1 was actually removed. That is the team doing
    it right, and it must produce silence."""
    assert 404 not in inv._LIVE_STATUS


def test_a_405_sibling_counts_as_live():
    """"Method not allowed" is the route answering: it exists, it just does
    not take GET. That is a live forgotten version."""
    assert 405 in inv._LIVE_STATUS


# ---- the finding that matters: the control the old version lost --------

def test_losing_authentication_is_the_finding():
    current = {"status": 401, "needs_auth": True, "rate_limited": True}
    sibling = {"status": 200, "needs_auth": False, "rate_limited": True}
    assert inv.regression(current, sibling) == "authentication"


def test_losing_rate_limiting_is_reported_too():
    current = {"status": 200, "needs_auth": False, "rate_limited": True}
    sibling = {"status": 200, "needs_auth": False, "rate_limited": False}
    assert inv.regression(current, sibling) == "rate limiting"


def test_an_equally_protected_sibling_is_not_a_regression():
    posture = {"status": 401, "needs_auth": True, "rate_limited": False}
    assert inv.regression(posture, dict(posture)) == ""


def test_a_sibling_that_is_more_protected_is_not_a_regression():
    """v1 requiring auth where v2 does not is the team's own choice, not a
    break. Reporting it would be an invented finding."""
    current = {"status": 200, "needs_auth": False, "rate_limited": False}
    sibling = {"status": 401, "needs_auth": True, "rate_limited": True}
    assert inv.regression(current, sibling) == ""


def test_an_auth_regression_is_an_access_control_break_not_an_inventory_note():
    """The severity and the class are the whole point: an old version that
    kept the route and lost the control is an authentication bypass with a
    version number, and the exploit layer can prove it."""
    finding = inv._shadow_finding(
        "https://t.example/api/v2/users", "https://t.example/api/v1/users",
        "version sibling of 'v2'",
        {"status": 401, "needs_auth": True, "rate_limited": False},
        {"status": 200, "needs_auth": False, "rate_limited": False,
         "body_len": 4096, "content_type": "application/json"})
    assert finding.severity == "high"
    assert finding.metadata["vuln_class"] == "broken_access_control"
    assert finding.metadata["owasp_api"] == "API9:2023"
    # Both halves of the comparison are in the evidence, or the reader has to
    # take the claim on trust.
    assert "api/v2/users -> 401" in finding.evidence
    assert "api/v1/users -> 200" in finding.evidence


def test_an_equally_protected_shadow_version_is_low_and_inventory():
    finding = inv._shadow_finding(
        "https://t.example/api/v2/users", "https://t.example/api/v1/users",
        "version sibling of 'v2'",
        {"status": 200, "needs_auth": False, "rate_limited": False},
        {"status": 200, "needs_auth": False, "rate_limited": False,
         "body_len": 10, "content_type": "application/json"})
    assert finding.severity == "low"
    assert finding.metadata["vuln_class"] == "shadow_api"


def test_an_unauthenticated_archived_api_endpoint_is_medium():
    finding = inv._zombie_finding(
        "https://t.example/api/v1/export",
        {"status": 200, "needs_auth": False, "body_len": 900,
         "content_type": "application/json"})
    assert finding.severity == "medium"
    assert finding.metadata["source"] == "archive"


def test_an_archived_page_behind_auth_is_only_low():
    finding = inv._zombie_finding(
        "https://t.example/api/v1/export",
        {"status": 401, "needs_auth": True, "body_len": 10,
         "content_type": "text/html"})
    assert finding.severity == "low"


# ---- the verdict is two responses, not a guess ------------------------

def test_the_findings_carry_their_own_confirmed_verdict():
    """We probed both sides. Letting the validator re-derive a verdict from
    the severity would throw away the strongest evidence on the finding."""
    for finding in (
        inv._shadow_finding("https://t.example/api/v2/u", "https://t.example/api/v1/u",
                            "x", {"status": 401, "needs_auth": True},
                            {"status": 200, "needs_auth": False, "body_len": 1,
                             "content_type": ""}),
        inv._zombie_finding("https://t.example/api/v1/x",
                            {"status": 200, "needs_auth": False, "body_len": 1,
                             "content_type": ""}),
    ):
        assert finding.metadata["status"] == "confirmed"
        assert finding.metadata["confidence"] >= 0.8


def test_the_validator_keeps_that_verdict():
    from app.validation.validator import _ANALYSIS_TOOLS
    assert "api_inventory" in _ANALYSIS_TOOLS


def test_the_probe_budget_is_bounded():
    """A versioned API with two hundred routes would otherwise turn into a
    thousand GETs and spend the run's whole budget on inventory."""
    from tests._limits import is_bounded, standard
    assert is_bounded(inv.MAX_PROBES)
    assert standard(60) <= 100
    assert inv.MAX_ZOMBIE_PROBES <= inv.MAX_PROBES


def test_every_probe_goes_through_the_safe_layer():
    """GET/HEAD only, in scope, one request, capped body. The analyser must
    not hold an HTTP client of its own."""
    src = _inspect.getsource(inv)
    assert "SafePoC" in src
    for forbidden in ("httpx.AsyncClient", "requests.get", "urlopen"):
        assert forbidden not in src


def test_a_candidate_is_scope_checked_before_it_is_probed():
    src = _inspect.getsource(inv.analyze_api_inventory)
    assert "url_in_scope" in src


# ---- found means scanned, not just reported ---------------------------

def test_what_is_found_is_put_on_the_scan_surface():
    """Finding v1 and not scanning it would be worse than not finding it: the
    report would say the surface was covered."""
    src = _inspect.getsource(inv._seed)
    assert 'add_asset("endpoint"' in src
    assert 'source="api-inventory"' in src


def test_seeding_is_scope_checked_too():
    assert "url_in_scope" in _inspect.getsource(inv._seed)


def test_the_hunt_runs_before_the_vuln_phase_is_planned():
    from app.orchestrator import loop
    src = _inspect.getsource(loop)
    assert "await _hunt_shadow_apis(engagement, run)" in src
    assert (src.index("await _hunt_shadow_apis(engagement, run)")
            < src.index("await _run_correlation(engagement, run, executor, runs)"))


def test_it_also_runs_with_the_other_traffic_analysers():
    """The second pass sees the whole run's traffic, not just recon's."""
    from app.analysis import run_analysis
    assert "api_inventory" in _inspect.getsource(run_analysis)


def test_the_hunt_never_fails_the_run():
    from app.orchestrator import loop
    src = _inspect.getsource(loop._hunt_shadow_apis)
    assert "except Exception" in src and "logger.exception" in src


def test_findings_are_stored_as_a_synthetic_job_like_every_analyser():
    src = _inspect.getsource(inv.analyze_api_inventory)
    assert 'save_analysis_job(engagement_id, "api_inventory"' in src


# ---- the budget buys operations, not duplicate URLs -------------------

def test_two_hundred_urls_of_one_route_cost_one_probe():
    """/api/v2/users/1 and /api/v2/users/2 are the same route. Probing both
    would spend the whole budget rewriting one path two hundred times."""
    first = inv._shape("https://t.example/api/v2/users/1")
    assert first == inv._shape("https://t.example/api/v2/users/48219")
    assert first != inv._shape("https://t.example/api/v2/orders/1")


def test_the_shape_is_per_host():
    """api.t.example/v1/x and t.example/v1/x are two different APIs."""
    assert inv._shape("https://api.t.example/v1/x") != \
        inv._shape("https://t.example/v1/x")


def test_the_shape_agrees_with_the_synthesised_schema():
    """One definition of "an operation", so the inventory and the schema
    cannot disagree about what counts as one route."""
    from app.analysis.openapi_synth import templated
    assert inv._shape("https://t.example/api/v2/users/7").endswith(
        templated("/api/v2/users/7"))


# ---- no exploit needed is a reason, not a gap -------------------------

def test_a_shadow_api_finding_says_why_it_needs_no_exploit():
    """The generic "no route available" reads as a gap in the tool. For this
    class the response attached to the finding already is the proof."""
    from app.exploit.strategy import plan_for
    plan = plan_for({"id": "f1", "title": "Archived endpoint still answering",
                     "target": "https://t.example/api/v1/x",
                     "vuln_class": "shadow_api", "severity": "medium",
                     "status": "confirmed"})
    assert plan.routes == []
    assert "the proof" in plan.skipped_because
    assert "no route available" not in plan.skipped_because


def test_the_auth_regression_variant_does_get_a_route():
    """It is reported as broken_access_control precisely so the exploit layer
    can demonstrate the unauthenticated read."""
    from app.exploit.strategy import plan_for
    plan = plan_for({"id": "f2", "title": "Forgotten version without auth",
                     "target": "https://t.example/api/v1/users",
                     "vuln_class": "broken_access_control", "severity": "high",
                     "status": "confirmed"})
    assert plan.routes, plan.skipped_because
