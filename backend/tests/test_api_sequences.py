"""Stateful API testing: the bug that needs two requests in the right order.

This is the gap RESTler exists to fill, and RESTler is not shipped - the
measured reasons are in the module docstring and the commit message. What is
implemented is the one thing it had that nothing else here did: a sequence.

    POST /api/notes {"title": "... <marker>"}  -> 201 {"id": 4821}
    GET  /api/notes/4821   (no credential)      -> 200, carrying our marker

The marker is the whole design. Without it a 200 on the second request is an
inference; with it the chain has no inference left in it - we know the
identifier because the API issued it, and the content because we wrote it.
"""
from __future__ import annotations

import inspect as _inspect
import json

import pytest

from app.analysis import api_sequences as seq


# ---- the marker: what makes the second answer unambiguous -------------

def test_a_marker_is_planted_in_a_free_text_field():
    body = json.dumps({"title": "my note", "public": False})
    mutated, token = seq.plant_marker(body)
    parsed = json.loads(mutated)
    assert token in parsed["title"]
    assert parsed["title"].startswith("my note")   # the original value survives
    assert parsed["public"] is False               # nothing else is touched


def test_the_marker_cannot_occur_in_the_targets_own_data():
    first, second = seq.marker(), seq.marker()
    assert first != second
    assert first.startswith(seq.MARKER_PREFIX)
    assert len(first) > len(seq.MARKER_PREFIX) + 8


def test_a_body_with_no_free_text_field_falls_back_to_any_string():
    mutated, token = seq.plant_marker(json.dumps({"sku": "AB-12"}))
    assert token in json.loads(mutated)["sku"]


def test_a_body_with_no_string_at_all_has_nowhere_to_plant():
    assert seq.plant_marker(json.dumps({"count": 3, "ok": True})) is None


def test_a_non_json_body_is_left_alone():
    assert seq.plant_marker("a=1&b=2") is None
    assert seq.plant_marker(json.dumps([1, 2])) is None
    assert seq.plant_marker("") is None


@pytest.mark.parametrize("body,expected", [
    ('{"title":"x syphax-seq-abc123"}', True),
    ('{"title":"someone elses note"}', False),
    ("", False),
])
def test_the_marker_is_what_identifies_our_object(body, expected):
    assert seq.contains_marker(body, "syphax-seq-abc123") is expected


# ---- learning the identifier from the response -----------------------

@pytest.mark.parametrize("response,expected", [
    ('{"id": 4821, "title": "x"}', ("id", "4821")),
    ('{"data": {"id": 7}}', ("id", "7")),
    ('{"result": {"item": {"uuid": "abc-def"}}}', ("uuid", "abc-def")),
    ('{"_id": "650f1c"}', ("_id", "650f1c")),
])
def test_the_created_objects_identifier_is_read_out_of_the_response(response, expected):
    assert seq.identity_of(response) == expected


def test_a_response_with_no_identifier_stops_the_sequence():
    """Without an identifier there is no second request to make, and guessing
    one would be sending requests with no hypothesis behind them."""
    assert seq.identity_of('{"status": "created"}') is None
    assert seq.identity_of("created") is None
    assert seq.identity_of("") is None


def test_an_absurdly_long_identifier_is_refused():
    assert seq.identity_of(json.dumps({"id": "x" * 500})) is None


def test_the_read_url_follows_the_rest_convention():
    """POST to a collection returns an object read at collection/{id}. If the
    API does not follow it the read answers 404 and the sequence stops, which
    costs one request."""
    assert seq.read_url("https://t.example/api/notes", "4821") == \
        "https://t.example/api/notes/4821"
    assert seq.read_url("https://t.example/api/notes/", "4821") == \
        "https://t.example/api/notes/4821"
    assert seq.read_url("https://t.example/api/notes?draft=1", "7") == \
        "https://t.example/api/notes/7"


# ---- the neighbour check only fires on a sequential key --------------

def test_a_numeric_identifier_has_a_neighbour():
    assert seq.neighbour_of("4821") == "4820"


def test_a_uuid_has_none():
    """Decrementing a UUID is meaningless."""
    assert seq.neighbour_of("550e8400-e29b-41d4-a716-446655440000") is None
    assert seq.neighbour_of("650f1cab") is None


def test_the_first_identifier_has_no_neighbour_below_it():
    assert seq.neighbour_of("1") is None
    assert seq.neighbour_of("0") is None


# ---- the verdict depends on whether this API authenticates at all ----

def test_an_api_that_authenticates_elsewhere_gives_a_high():
    """401/403 somewhere on the host means authentication is something this
    API does - and this operation is not doing it."""
    finding = seq.finding_for_readable(
        "https://t.example/api/notes", "https://t.example/api/notes/4821",
        id_key="id", identifier="4821", token="syphax-seq-abc",
        status=200, enforces_auth_elsewhere=True)
    assert finding.severity == "high"
    assert finding.metadata["vuln_class"] == "broken_access_control"
    assert finding.metadata["owasp_api"] == "API1:2023"
    assert finding.metadata["confidence"] > 0.9


def test_an_api_that_authenticates_nowhere_gives_only_a_medium():
    """It may be a deliberately public service, and reporting a readable
    public resource as an access-control break would be wrong."""
    finding = seq.finding_for_readable(
        "https://t.example/api/notes", "https://t.example/api/notes/4821",
        id_key="id", identifier="4821", token="syphax-seq-abc",
        status=200, enforces_auth_elsewhere=False)
    assert finding.severity == "medium"
    assert "public" in finding.description
    assert "would be wrong" in finding.description


def test_the_evidence_is_the_whole_chain_numbered():
    """A reader has to be able to follow it without trusting the conclusion."""
    finding = seq.finding_for_readable(
        "https://t.example/api/notes", "https://t.example/api/notes/4821",
        id_key="id", identifier="4821", token="syphax-seq-abc",
        status=200, enforces_auth_elsewhere=True)
    for step in ("1. POST", "2. GET", "3. the response carries the marker"):
        assert step in finding.evidence
    assert "no Authorization header" in finding.evidence
    assert "syphax-seq-abc" in finding.evidence


# ---- someone else's data is not quoted into the report ---------------

def test_the_neighbours_body_is_withheld_by_default():
    """It belongs to someone else, and a report is not the place to put it."""
    finding = seq.finding_for_neighbour(
        "https://t.example/api/notes/4820", identifier="4821",
        neighbour="4820", status=200, body_length=812, quote="")
    assert "withheld" in finding.evidence
    assert "allow_data_proof is off" in finding.evidence
    assert "812 bytes" in finding.evidence


def test_a_sample_is_included_only_when_the_engagement_allows_it():
    finding = seq.finding_for_neighbour(
        "https://t.example/api/notes/4820", identifier="4821",
        neighbour="4820", status=200, body_length=812,
        quote='{"title":"someone elses note"}')
    assert "allow_data_proof is on" in finding.evidence
    assert "someone elses note" in finding.evidence


def test_the_neighbour_finding_is_idor():
    finding = seq.finding_for_neighbour(
        "https://t.example/api/notes/4820", identifier="4821",
        neighbour="4820", status=200, body_length=812)
    assert finding.severity == "high"
    assert finding.metadata["vuln_class"] == "idor"
    assert "counting" in finding.description


def test_the_neighbour_read_is_gated_on_data_proof():
    src = _inspect.getsource(seq.analyze_api_sequences)
    assert "allow_data_proof" in src


# ---- the sequence stops rather than guessing -------------------------

def test_reading_back_something_that_is_not_ours_proves_nothing():
    """The marker check is what stops a 200 on an unrelated page becoming a
    confirmed access-control break."""
    src = _inspect.getsource(seq.analyze_api_sequences)
    assert "contains_marker" in src
    assert "prove nothing" in src


def test_the_sequence_count_is_bounded():
    assert seq.MAX_SEQUENCES <= 5


def test_authentication_and_payment_creates_are_skipped():
    """The skip list is shared with the mass-assignment probe, so the two
    cannot disagree about what is safe to POST to."""
    from app.analysis.mass_assignment import should_skip
    assert seq.should_skip is should_skip
    assert seq.should_skip("https://t.example/api/login")
    assert not seq.should_skip("https://t.example/api/notes")


def test_the_write_uses_the_probe_client_and_the_read_uses_the_safe_one():
    """The read must carry no credential - that is the test - and the safe
    layer sends none. Using the probe client for both would be a wider method
    policy than the read needs."""
    src = _inspect.getsource(seq.analyze_api_sequences)
    assert "ProbeClient(in_scope=eng.host_in_scope)" in src
    assert "SafePoC(in_scope=eng.host_in_scope)" in src
    assert 'method="POST"' in _inspect.getsource(seq._post)
    assert 'method="GET"' in _inspect.getsource(seq._get)


def test_it_is_gated_on_active_exploitation():
    src = _inspect.getsource(seq.analyze_api_sequences)
    assert "allow_active" in src and "allow_active_exploit" in src
    assert "skipped" in src


def test_the_sequence_is_built_from_a_real_request():
    """A body invented from the schema would be rejected for a dozen
    unrelated reasons, and every result would be noise."""
    src = _inspect.getsource(seq._creates_observed)
    assert "method = 'POST'" in src
    assert "request_body IS NOT NULL" in src
    assert "host_in_scope" in src


# ---- it has a place in the run ---------------------------------------

def test_it_runs_with_the_other_analysers_under_the_same_override():
    from app.analysis import run_analysis
    src = _inspect.getsource(run_analysis)
    assert '("api_sequences",' in src
    assert "analyze_api_sequences(eid, allow_active=allow_active)" in src


def test_the_validator_keeps_its_verdict():
    from app.validation.validator import _ANALYSIS_TOOLS
    assert "api_sequences" in _ANALYSIS_TOOLS


def test_both_classes_it_reports_have_an_exploit_route():
    from app.exploit.strategy import plan_for
    for vuln_class in ("broken_access_control", "idor"):
        plan = plan_for({"id": "f", "title": "t", "target": "https://t/x",
                         "vuln_class": vuln_class, "severity": "high",
                         "status": "confirmed"})
        assert plan.routes, f"{vuln_class}: {plan.skipped_because}"


def test_restler_is_not_a_dependency_anywhere():
    """The decision has to be visible in the tree, not only in a commit
    message: nothing installs it, and no wrapper expects the binary."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text().lower()
    assert "restler" not in dockerfile
    assert not (root / "app" / "scans" / "wrappers" / "restler.py").exists()
