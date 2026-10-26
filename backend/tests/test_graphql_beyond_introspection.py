"""GraphQL after introspection is switched off.

"Is introspection on?" is the first question about a GraphQL endpoint and the
least interesting, because switching it off is the one thing every team does.
These are the checks that survive it - and the boundary that keeps them legal:
no mutation (a write), no batch, and never the thousands of aliases that turn a
measurement into an outage.
"""
from __future__ import annotations

import inspect as _inspect
import json

import pytest

from app.analysis import graphql as gql
from app.analysis import graphql_probes as probes


def body(obj) -> str:
    return json.dumps(obj)


# ---- field suggestions: schema disclosure with introspection off -------

def test_a_did_you_mean_answer_is_schema_disclosure():
    """Each wrong guess is answered with the right name, so the type graph
    can be walked one field at a time."""
    on, message = probes.suggests_fields(body({"errors": [{
        "message": 'Cannot query field "usr" on type "Query". '
                   'Did you mean "user" or "users"?'}]}))
    assert on
    assert "Did you mean" in message


def test_a_plain_rejection_is_not_a_suggestion():
    on, _ = probes.suggests_fields(body({"errors": [{
        "message": 'Cannot query field "usr" on type "Query".'}]}))
    assert not on


def test_a_suggestion_outside_the_errors_array_is_still_found():
    """Some servers answer with a bare body rather than a GraphQL envelope."""
    on, message = probes.suggests_fields(
        "Unknown field. Did you mean `accountBalance`?")
    assert on and "accountBalance" in message


def test_the_suggestion_probe_needs_no_knowledge_of_the_schema():
    """It asks for a near-miss of __typename, which every schema has, so the
    check works on a target whose fields we have never seen."""
    assert probes.NEAR_MISS_FIELD in probes.QUERY_SUGGESTION
    assert probes.NEAR_MISS_FIELD != "__typename"
    assert "__typename".startswith(probes.NEAR_MISS_FIELD)


# ---- __schema blocked at the WAF, __type left reachable ---------------

def test_type_answering_while_schema_is_blocked_is_still_introspection():
    """Introspection is not off here - the literal string "__schema" is
    filtered, and a different query walks around it."""
    readable, count = probes.type_readable(body({"data": {"__type": {
        "name": "Query", "fields": [{"name": "me"}, {"name": "users"},
                                    {"name": "adminAuditLog"}]}}}))
    assert readable and count == 3


def test_a_refused_type_query_is_not_a_finding():
    readable, count = probes.type_readable(body({"errors": [
        {"message": "GraphQL introspection is not allowed"}]}))
    assert not readable and count == 0


def test_the_partial_probe_does_not_contain_the_blocked_string():
    """The whole point: a WAF rule on "__schema" must not match it."""
    assert "__schema" not in probes.QUERY_PARTIAL_INTROSPECTION
    assert "__type" in probes.QUERY_PARTIAL_INTROSPECTION


def test_the_field_count_is_the_evidence():
    """"__type named 48 fields of Query" is a statement about disclosure.
    "it answered 200" is not."""
    checks = {"partial_introspection": True, "field_count": 48,
              "evidence": {"partial_introspection": "named 48 field(s)"}}
    finding = next(f for f in gql.findings_for("https://t.example/graphql", checks)
                   if f.metadata["kind"] == "partial_introspection")
    assert "48" in finding.description


# ---- amplification: the primitive is reported, never exercised --------

def test_two_aliases_resolving_shows_the_primitive():
    assert probes.aliases_executed(body({"data": {"a": "Query", "b": "Query"}}))


def test_one_alias_resolving_is_not_enough():
    assert not probes.aliases_executed(body({"data": {"a": "Query"}}))


def test_the_alias_probe_sends_exactly_two_aliases():
    """This is the line between a measurement and a denial-of-service test,
    and it has to be visible in the query itself."""
    assert probes.QUERY_ALIASES.count(":__typename") == 2


def test_the_directive_probe_sends_exactly_two_directives():
    assert probes.QUERY_DUPLICATE_DIRECTIVE.count("@skip") == 2


def test_a_spec_compliant_server_rejects_the_duplicate_directive():
    assert not probes.duplicate_directive_accepted(body({"errors": [{
        "message": "The directive 'skip' can only be used once at this location."}]}))


def test_a_server_that_executed_it_accepted_it():
    assert probes.duplicate_directive_accepted(body({"data": {"__typename": "Query"}}))


def test_the_amplification_findings_say_what_was_not_sent():
    """An operator reading "alias amplification is available" has to know we
    established the primitive and did not use it, or the report implies a
    test we refuse to run."""
    for kind in ("aliases", "duplicate_directives"):
        finding = gql.findings_for("https://t.example/graphql",
                                   {kind: True, "evidence": {}})[0]
        text = (finding.description or "").lower()
        assert "two" in text
        assert finding.severity == "low"
        assert finding.metadata["vuln_class"] == "rate_limit"


def test_no_probe_query_is_a_mutation():
    """Writes are the checks that cannot be done without changing the target."""
    queries = [v for k, v in vars(probes).items()
               if k.startswith("QUERY_") and isinstance(v, str)]
    assert queries, "no probe queries found - the check would be vacuous"
    for query in queries:
        assert "mutation" not in query.lower()
        assert "subscription" not in query.lower()


def test_the_safe_layer_refuses_anything_but_a_read():
    """The guarantee is structural, not a convention: a POST from this
    analyser raises rather than reaching the target."""
    import pytest as _pytest

    from app.validation.safe_poc import PolicyError, SafePoC
    safe = SafePoC(in_scope=lambda host: True)
    with _pytest.raises(PolicyError):
        safe._check("POST", "https://t.example/graphql")
    safe._check("GET", "https://t.example/graphql")   # the only thing we do


def test_no_probe_is_a_batch():
    """A JSON array of queries is a POST body, which this analyser cannot
    send - but the queries themselves must not smuggle one either."""
    for key, value in vars(probes).items():
        if key.startswith("QUERY_") and isinstance(value, str):
            assert not value.strip().startswith("[")


# ---- the console left in production -----------------------------------

@pytest.mark.parametrize("marker,name", [
    ("<div id=\"graphiql\">", "GraphiQL"),
    ("graphql-playground-react", "GraphQL Playground"),
    ("altair-container", "Altair"),
    ("graphql-voyager", "GraphQL Voyager"),
])
def test_an_interactive_console_is_recognised(marker, name):
    assert probes.console_in_response(f"<html>{marker}</html>", "text/html") == name


def test_a_json_api_response_is_not_a_console():
    """Otherwise every endpoint that mentions graphiql in an error message
    becomes an exposed console."""
    assert probes.console_in_response(
        body({"errors": [{"message": "use graphiql"}]}), "application/json") == ""


def test_the_console_finding_is_a_misconfiguration():
    finding = gql.findings_for("https://t.example/graphql",
                               {"console": "GraphiQL", "evidence": {}})[0]
    assert finding.severity == "medium"
    assert finding.metadata["vuln_class"] == "misconfiguration"
    assert "GraphiQL" in finding.title


# ---- the engine, because a CVE search needs a name --------------------

@pytest.mark.parametrize("text,engine", [
    (body({"errors": [{"extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}}]}),
     "Apollo Server"),
    (body({"errors": [{"message": "Field 'x' doesn't exist on type 'Query'"}]}),
     "graphql-ruby"),
    (body({"errors": [{"message": "field \"x\" not found in type: 'query_root'"}]}),
     "Hasura"),
    (body({"errors": [{"message": "Validation error of type FieldUndefined"}]}),
     "graphql-java"),
    (body({"errors": [{"message": "expected at least one definition"}]}),
     "gqlgen (Go)"),
])
def test_distinctive_error_wording_names_the_implementation(text, engine):
    assert probes.engine_from(text) == engine


def test_wording_that_is_not_distinctive_names_nothing():
    """A guessed engine sends an operator looking for the wrong CVEs, which
    is worse than not guessing."""
    assert probes.engine_from(body({"errors": [{"message": "Bad Request"}]})) == ""
    assert probes.engine_from("") == ""


# ---- one finding per thing established --------------------------------

def test_full_introspection_and_partial_are_not_both_reported():
    """They are the same disclosure. Reporting both would double-count it."""
    findings = gql.findings_for("https://t.example/graphql",
                                {"introspection": True,
                                 "partial_introspection": True, "evidence": {}})
    kinds = [f.metadata["kind"] for f in findings]
    assert "introspection" in kinds
    assert "partial_introspection" not in kinds


def test_several_independent_weaknesses_become_several_findings():
    findings = gql.findings_for("https://t.example/graphql", {
        "introspection": True, "suggestions": True, "aliases": True,
        "console": "GraphiQL", "engine": "Apollo Server", "evidence": {}})
    kinds = {f.metadata["kind"] for f in findings}
    assert kinds == {"introspection", "suggestions", "aliases", "console"}
    assert all(f.metadata["engine"] == "Apollo Server" for f in findings)


def test_an_endpoint_with_nothing_wrong_is_recorded_as_info():
    """It is still the one URL the whole API answers on, so it belongs in the
    report - and the description has to say what was actually tested."""
    findings = gql.findings_for("https://t.example/graphql",
                                {"endpoint": True, "get_queries": True,
                                 "engine": "Apollo Server", "evidence": {}})
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].metadata["status"] == "unconfirmed"
    description = findings[0].description
    for tested in ("Introspection", "suggestions", "alias", "console"):
        assert tested in description
    assert "Apollo Server" in description


def test_every_finding_carries_its_verdict_and_its_evidence_slot():
    findings = gql.findings_for("https://t.example/graphql", {
        "suggestions": True, "console": "Altair",
        "evidence": {"suggestions": "GET ... -> Did you mean", "console": "GET ..."}})
    for finding in findings:
        assert finding.metadata["status"] == "confirmed"
        assert finding.evidence
        assert finding.target == "https://t.example/graphql"


def test_worth_reporting_ignores_the_mere_existence_of_an_endpoint():
    assert not probes.worth_reporting({"endpoint": True, "get_queries": True})
    assert probes.worth_reporting({"endpoint": True, "suggestions": True})


# ---- the cheap disqualification comes first ---------------------------

def test_a_non_graphql_endpoint_costs_one_request_not_eight():
    src = _inspect.getsource(gql.run_suite)
    first = src.index("QUERY_TYPENAME")
    for later in ("_INTROSPECTION", "QUERY_SUGGESTION", "QUERY_ALIASES",
                  "QUERY_DUPLICATE_DIRECTIVE"):
        assert first < src.index(later), later
    assert "return None" in src


def test_the_endpoint_count_is_bounded():
    """The suite is eight GETs per endpoint; the candidate list includes
    guessed paths, so it cannot be unbounded."""
    from tests._limits import is_bounded, standard
    assert is_bounded(gql.MAX_ENDPOINTS)
    assert standard(6) <= 10


def test_a_console_proves_a_graphql_server_that_refuses_get_queries():
    """An endpoint that only speaks POST would otherwise be dropped, console
    and all - and a GraphiQL page is proof the server is there."""
    src = _inspect.getsource(gql.run_suite)
    marker = src.index("responds_to_graphql")
    assert "_console" in src[marker:]


# ---- the findings reach the exploit layer instead of being discarded --

def test_the_schema_disclosure_findings_have_an_exploit_route():
    """They used to carry vuln_class "graphql", which nothing routed, so
    every GraphQL finding this analyser produced fell into "no route
    available" and the campaign discarded it without a word."""
    from app.exploit.strategy import plan_for
    for kind in ("introspection", "suggestions"):
        finding = gql.findings_for("https://t.example/graphql",
                                   {kind: True, "evidence": {"x": "y"}})[0]
        plan = plan_for({"id": "f1", "title": finding.title,
                         "target": finding.target,
                         "vuln_class": finding.metadata["vuln_class"],
                         "severity": finding.severity, "status": "confirmed"})
        assert plan.routes, f"{kind} has no route: {plan.skipped_because}"


def test_what_the_model_is_asked_to_do_with_a_readable_schema():
    """Authoring is worth a model call here because the schema names the
    operations no client calls - that is the escalation, not a re-send."""
    from app.exploit.strategy import AUTHORABLE_CLASSES
    assert "graphql_introspection" in AUTHORABLE_CLASSES
