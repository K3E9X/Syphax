"""Mass assignment (API3) and rate limiting (API4), both behind their gates.

These are the two checks in the API suite that cannot be done read-only: one
writes and one repeats. So the tests here are as much about the restraint as
about the detection - what is refused, what is bounded, and how carefully the
finding states what was actually established.
"""
from __future__ import annotations

import inspect as _inspect
import json

import pytest

from app.analysis import mass_assignment as ma
from app.analysis import rate_limit as rl


# =======================================================================
# Mass assignment
# =======================================================================

BODY = json.dumps({"name": "test", "email": "a@b.c"})


def test_the_injected_property_is_added_to_a_real_body():
    """The probe differs from a working request by exactly one property. A
    body invented from the schema would be rejected for a dozen unrelated
    reasons and every result would be noise."""
    mutated = json.loads(ma.inject(BODY, "is_admin", True))
    assert mutated == {"name": "test", "email": "a@b.c", "is_admin": True}


def test_a_property_the_client_already_sends_is_not_injected():
    """Injecting it proves nothing: the API is supposed to read it."""
    assert ma.inject(json.dumps({"role": "user"}), "role", "admin") is None


def test_a_non_json_body_is_left_alone():
    """Form and multipart bodies are a different parser on the server side
    and a different test."""
    assert ma.inject("name=test&email=a%40b.c", "is_admin", True) is None
    assert ma.inject("", "is_admin", True) is None
    assert ma.inject(json.dumps([1, 2, 3]), "is_admin", True) is None


# ---- the oracle is the echo, and only the echo ------------------------

def test_the_echo_is_what_confirms_it():
    """A 201 proves nothing on its own: the server may have accepted the
    request and discarded the extra field. We cannot read its database."""
    assert ma.echoed(json.dumps({"id": 7, "name": "test", "is_admin": True}),
                     "is_admin", True)


def test_a_nested_echo_counts():
    assert ma.echoed(json.dumps({"data": {"user": {"is_admin": True}}}),
                     "is_admin", True)


def test_the_echo_must_carry_our_value_not_just_the_name():
    """The server returning its own `is_admin: false` is the server working."""
    assert not ma.echoed(json.dumps({"name": "test", "is_admin": False}),
                         "is_admin", True)


def test_an_error_message_quoting_the_request_back_is_not_an_echo():
    """Structural, not a substring match. This is the false positive that
    would otherwise turn every validating API into a high-severity finding."""
    quoted = json.dumps({"error": 'unknown field "is_admin": true in body'})
    assert not ma.echoed(quoted, "is_admin", True)


def test_a_non_json_response_cannot_echo():
    assert not ma.echoed("<html>created</html>", "is_admin", True)


def test_a_deeply_nested_response_does_not_recurse_forever():
    deep = {"a": None}
    node = deep
    for _ in range(40):
        node["a"] = {"a": None}
        node = node["a"]
    ma.echoed(json.dumps(deep), "is_admin", True)   # returns


@pytest.mark.parametrize("status", [400, 422, 403, 409])
def test_a_rejected_body_is_the_correct_behaviour_and_no_finding(status):
    assert ma.rejected(status)


@pytest.mark.parametrize("status", [200, 201, 202, 204, 500])
def test_anything_else_is_not_a_rejection(status):
    assert not ma.rejected(status)


# ---- the two verdicts are worded differently -------------------------

def test_an_echoed_injection_is_high_and_confirmed():
    finding = ma.finding_for("https://t.example/api/users", "is_admin", True,
                             status=201, confirmed=True,
                             request_body=BODY, response_excerpt="{}")
    assert finding.severity == "high"
    assert finding.metadata["status"] == "confirmed"
    assert finding.metadata["vuln_class"] == "mass_assignment"
    assert finding.metadata["owasp_api"] == "API3:2023"
    assert "bound it" in finding.description


def test_an_accepted_but_unobservable_injection_is_low_and_unconfirmed():
    """Stating it as mass assignment would be a guess dressed as a finding -
    and the description has to say so, because this is exactly where a tool
    is tempted to overclaim."""
    finding = ma.finding_for("https://t.example/api/users", "is_admin", True,
                             status=201, confirmed=False,
                             request_body=BODY, response_excerpt="{}")
    assert finding.severity == "low"
    assert finding.metadata["status"] == "unconfirmed"
    assert finding.metadata["confidence"] < 0.5
    assert "cannot tell" in finding.description
    assert "database" in finding.description


def test_the_evidence_carries_the_request_so_it_can_be_replayed():
    finding = ma.finding_for("https://t.example/api/users", "role", "admin",
                             status=200, confirmed=True,
                             request_body=BODY, response_excerpt='{"role":"admin"}')
    assert "POST https://t.example/api/users" in finding.evidence
    assert "role" in finding.evidence
    assert BODY[:20] in finding.evidence


def test_the_confirmed_finding_names_the_untested_half_and_its_capability():
    """The PUT/PATCH variant overwrites the client's real data. Reporting the
    gap keeps it visible instead of silently absent."""
    finding = ma.finding_for("https://t.example/api/users", "is_admin", True,
                             status=201, confirmed=True,
                             request_body=BODY, response_excerpt="{}")
    assert "PUT" in finding.description or "PATCH" in finding.description
    assert "destructive" in finding.description
    assert "destructive" in finding.metadata["untested"]


# ---- what is never touched -------------------------------------------

@pytest.mark.parametrize("path", [
    "/api/login", "/api/auth/token", "/oauth/authorize", "/account/password",
    "/api/payments", "/api/transfer", "/api/orders/4/refund",
    "/api/users/4/delete",
])
def test_authentication_payment_and_destructive_paths_are_skipped(path):
    assert ma.should_skip(f"https://t.example{path}")


def test_an_ordinary_create_endpoint_is_not_skipped():
    assert not ma.should_skip("https://t.example/api/users")
    assert not ma.should_skip("https://t.example/api/v2/comments")


def test_only_post_is_ever_sent():
    """The probe client's method policy is GET/HEAD/POST, deliberately not a
    superset of anything, and this analyser must not widen it."""
    from app.exploit.probe_client import ALLOWED_METHODS
    assert ALLOWED_METHODS == {"GET", "HEAD", "POST"}
    src = _inspect.getsource(ma._post)
    assert 'method="POST"' in src


def test_the_probe_count_is_bounded():
    """Every probe here creates data on the target, so it must not become
    unbounded by accident. The ceiling is SYPHAX_TEST_DEPTH now (app/limits):
    finite at whatever depth the suite runs at, and the documented small
    number at `standard`."""
    from tests._limits import is_bounded, standard
    assert is_bounded(ma.MAX_PROBES)
    assert is_bounded(ma.MAX_OPERATIONS)
    assert standard(12) <= 20
    assert standard(4, floor=16) <= 6


def test_the_write_probe_is_gated_on_active_exploitation():
    """Every probe creates data on the target."""
    src = _inspect.getsource(ma.analyze_mass_assignment)
    assert "allow_active" in src
    assert "allow_active_exploit" in src
    assert "skipped" in src


def test_the_refusal_explains_itself_and_points_at_what_still_ran():
    src = _inspect.getsource(ma.analyze_mass_assignment)
    assert "schema audit" in src


# =======================================================================
# Rate limiting
# =======================================================================

def test_a_429_is_a_limit_and_the_count_is_reported():
    name, detail = rl.verdict([200, 200, 200, 429], {}, sent=4, seconds=0.4)
    assert name == "throttled"
    assert "after 4 of 4" in detail


def test_a_rate_limit_header_is_a_limit_even_without_a_429():
    """An API answering x-ratelimit-remaining: 4997 is throttled, and saying
    otherwise would be false. This is the most common wrong finding in the
    class and it costs one header read to avoid."""
    name, detail = rl.verdict([200] * 20, {"X-RateLimit-Remaining": "4997"},
                              sent=20, seconds=1.0)
    assert name == "declared"
    assert "4997" in detail


@pytest.mark.parametrize("header", ["Retry-After", "RateLimit-Limit",
                                    "X-Rate-Limit-Remaining",
                                    "X-RateLimit-Reset"])
def test_the_header_check_covers_the_spellings_in_the_wild(header):
    assert rl.limit_headers({header: "1"})


def test_no_429_and_no_header_is_the_only_finding_case():
    name, _ = rl.verdict([200] * 20, {"content-type": "application/json"},
                         sent=20, seconds=1.0)
    assert name == "unlimited"


def test_an_endpoint_that_only_errors_is_unusable_not_unlimited():
    """Twenty 500s are not evidence about throttling."""
    name, detail = rl.verdict([500] * 20, {}, sent=20, seconds=1.0)
    assert name == "unusable"
    assert "500" in detail


def test_no_responses_at_all_is_unusable():
    assert rl.verdict([], {}, sent=0, seconds=1.0)[0] == "unusable"


# ---- the finding is a bound, and says so -----------------------------

def test_the_title_states_the_number_of_requests():
    """"No rate limiting" is the easiest claim in API testing to get wrong,
    because not hitting a limit is also what happens when you send too few
    requests. A limit set at 1000/min must not read as an absence."""
    finding = rl.finding_for("https://t.example/api/items", "detail",
                             sent=20, seconds=1.0, capped_by_policy=True)
    assert "20 requests" in finding.title
    assert "no rate limit" in finding.title.lower()


def test_the_description_refuses_to_claim_there_is_no_limit():
    finding = rl.finding_for("https://t.example/api/items", "detail",
                             sent=20, seconds=1.0, capped_by_policy=True)
    assert "does not prove" in finding.description
    assert "would look" in finding.description


def test_the_default_burst_is_low_severity_and_the_capability_burst_is_medium():
    """The strength of the claim follows the size of the measurement."""
    small = rl.finding_for("https://t/api/x", "d", sent=rl.BURST_DEFAULT,
                           seconds=1.0, capped_by_policy=True)
    large = rl.finding_for("https://t/api/x", "d", sent=rl.BURST_WITH_CAPABILITY,
                           seconds=4.0, capped_by_policy=False)
    assert small.severity == "low"
    assert large.severity == "medium"


def test_a_policy_capped_burst_says_which_capability_would_raise_it():
    finding = rl.finding_for("https://t/api/x", "d", sent=20, seconds=1.0,
                             capped_by_policy=True)
    assert "denial_of_service" in finding.description
    assert str(rl.BURST_WITH_CAPABILITY) in finding.description


def test_the_measured_rate_is_on_the_finding():
    finding = rl.finding_for("https://t/api/x", "d", sent=20, seconds=2.0,
                             capped_by_policy=True)
    assert finding.metadata["measured_rate_per_second"] == 10.0
    assert finding.metadata["requests_sent"] == 20


# ---- the restraint ---------------------------------------------------

def test_the_default_burst_is_smaller_than_a_page_load():
    assert rl.BURST_DEFAULT <= 25


def test_the_capability_burst_is_still_bounded():
    """The point is a defensible measurement, not an outage."""
    assert rl.BURST_WITH_CAPABILITY <= 200


def test_the_bigger_burst_needs_the_declared_capability():
    from app.exploit.capabilities import CAP_DENIAL
    assert rl.burst_size(set()) == rl.BURST_DEFAULT
    assert rl.burst_size({CAP_DENIAL}) == rl.BURST_WITH_CAPABILITY
    assert rl.burst_size({"destructive"}) == rl.BURST_DEFAULT


@pytest.mark.parametrize("path", [
    "/api/login", "/signin", "/auth/token", "/oauth/authorize",
    "/account/password/reset", "/api/mfa/verify", "/api/otp",
    "/api/payments", "/checkout", "/api/transfer",
])
def test_authentication_and_payment_are_never_bursted(path):
    """A burst on authentication means lockouts for real users and an
    incident ticket the client did not plan for. That is the credential_spray
    capability's territory and auth_brute owns it."""
    assert not rl.may_burst(f"https://t.example{path}")


@pytest.mark.parametrize("path", ["/api/export", "/reports/monthly",
                                  "/download/archive", "/api/search"])
def test_expensive_endpoints_are_excluded_for_a_different_reason(path):
    """Twenty requests here IS expensive for the target, and the measurement
    is not worth the load."""
    assert not rl.may_burst(f"https://t.example{path}")


def test_an_ordinary_api_read_may_be_bursted():
    assert rl.may_burst("https://t.example/api/items")
    assert rl.may_burst("https://t.example/api/v2/products/42")


def test_the_burst_is_read_only():
    """It goes through the safe layer, which is GET/HEAD and nothing else."""
    src = _inspect.getsource(rl)
    assert "SafePoC" in src
    assert "ProbeClient" not in src
    assert 'method="GET"' in _inspect.getsource(rl._one)


def test_the_burst_stops_as_soon_as_the_limit_answers():
    """Once a 429 comes back, more requests are pointless load on a target
    that has already given the answer."""
    src = _inspect.getsource(rl._burst)
    assert "429" in src
    assert "break" in src


def test_the_burst_is_gated_on_active_exploitation():
    src = _inspect.getsource(rl.analyze_rate_limit)
    assert "allow_active" in src and "allow_active_exploit" in src


def test_a_limit_that_exists_is_said_out_loud():
    """"We did not report one" and "we found one" look identical in a report
    otherwise."""
    src = _inspect.getsource(rl.analyze_rate_limit)
    assert "_say" in src


def test_the_endpoint_count_is_bounded():
    """A rate-limit check bursts an endpoint, so how MANY endpoints it touches
    is a coverage cap and follows SYPHAX_TEST_DEPTH; how HARD it bursts one
    does not (see BURST_WITH_CAPABILITY)."""
    from tests._limits import is_bounded, standard
    assert is_bounded(rl.MAX_ENDPOINTS)
    assert standard(2, floor=8) <= 3


# =======================================================================
# Both, in the run
# =======================================================================

def test_both_run_with_the_other_analysers_and_take_the_per_run_override():
    from app.analysis import run_analysis
    src = _inspect.getsource(run_analysis)
    for name in ("mass_assignment", "rate_limit"):
        assert name in src
        assert f'("{name}",' in src
    # The per-run override can only ever be more restrictive than the
    # engagement, because both are required.
    assert "allow_active=allow_active" in src


def test_both_keep_their_own_verdicts_through_validation():
    from app.validation.validator import _ANALYSIS_TOOLS
    assert "mass_assignment" in _ANALYSIS_TOOLS
    assert "rate_limit" in _ANALYSIS_TOOLS


def test_both_classes_reach_the_exploit_layer():
    from app.exploit.strategy import plan_for
    for vuln_class in ("mass_assignment", "rate_limit"):
        plan = plan_for({"id": "f", "title": "t", "target": "https://t/x",
                         "vuln_class": vuln_class, "severity": "medium",
                         "status": "confirmed"})
        assert plan.routes, f"{vuln_class}: {plan.skipped_because}"
