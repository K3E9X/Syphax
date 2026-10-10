"""Auditing the API contract itself, before anything is sent to the API.

A fuzzer tests what the implementation does. This reads what the contract
SAYS, which answers a different set of questions, because the interesting
ones are statements of absence: no security scheme on the operation that
deletes an account, no 429 anywhere in three hundred operations, a request
body that accepts any property the caller invents.

cherrybomb was the plan for this and was dropped - its only non-deprecated
install path is `cargo install`, i.e. a Rust toolchain in the image, for a
project with no activity since October 2024 and a check list it does not
publish. These checks are named and defended instead.
"""
from __future__ import annotations

import json

import pytest
import yaml

from app.analysis import schema_audit as audit


def spec(**overrides):
    """A minimal, well-behaved OpenAPI 3 document."""
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1.0.0"},
        "servers": [{"url": "https://t.example"}],
        "components": {"securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"}}},
        "security": [{"bearer": []}],
        "paths": {"/users/{userId}": {"get": {
            "parameters": [{"name": "userId", "in": "path", "required": True,
                            "schema": {"type": "string", "maxLength": 36}}],
            "responses": {"200": {"description": "ok"},
                          "429": {"description": "too many"}}}}},
    }
    doc.update(overrides)
    return doc


def kinds(findings):
    return {f.metadata["kind"] for f in findings}


def one(findings, kind):
    return next(f for f in findings if f.metadata["kind"] == kind)


# ---- parsing: JSON, YAML, and nothing else ----------------------------

def test_a_json_schema_parses():
    assert audit.parse(json.dumps(spec()))["openapi"] == "3.0.3"


def test_a_yaml_schema_parses():
    """/openapi.yaml is one of the eight locations the run probes, so half
    the documents it finds are YAML."""
    assert audit.parse(yaml.safe_dump(spec()))["openapi"] == "3.0.3"


def test_an_html_page_is_not_a_schema():
    """A SPA answering 200 with index.html for every unknown path would
    otherwise be audited as an API contract."""
    assert audit.parse("<html><body>Not found</body></html>") is None


def test_a_json_document_that_is_not_openapi_is_rejected():
    assert audit.parse(json.dumps({"users": [1, 2]})) is None


def test_the_yaml_loader_cannot_construct_python_objects():
    """The document comes from the target. yaml.safe_load only."""
    import inspect
    src = inspect.getsource(audit.parse)
    assert "yaml.safe_load" in src
    assert "yaml.load" not in src.replace("yaml.safe_load", "")
    assert audit.parse("!!python/object/apply:os.system ['id']") is None


def test_an_empty_or_huge_body_does_not_raise():
    assert audit.parse("") is None
    assert audit.parse("x" * (audit.MAX_DOC_BYTES + 5000)) is None


# ---- our own synthesised schema is never audited as a contract --------

def test_the_observed_schema_is_refused():
    """It declares no security because WE did not write one. Auditing it for
    missing security would manufacture a finding per operation out of our own
    omission."""
    from app.analysis.openapi_synth import build
    observed = build([{"method": "GET", "url": "https://t.example/api/users",
                       "status_code": 200,
                       "response_content_type": "application/json"}],
                     base_url="https://t.example")
    assert audit.is_observed(observed)
    assert audit.audit(observed, schema_url="x") == []


def test_a_published_schema_is_not_mistaken_for_an_observed_one():
    assert not audit.is_observed(spec())


# ---- authentication: the checks that pay ------------------------------

def test_a_contract_with_no_security_at_all_is_high():
    doc = spec()
    doc.pop("components")
    doc.pop("security")
    finding = one(audit.audit(doc, schema_url="https://t.example/openapi.json"),
                  "no_security")
    assert finding.severity == "high"
    assert finding.metadata["vuln_class"] == "broken_authentication"
    assert finding.metadata["owasp_api"] == "API2:2023"
    # The second reading is the one that matters and has to be stated.
    assert "absent from" in finding.description


def test_security_as_an_empty_list_on_one_operation_is_an_opt_out():
    """`security: []` is not "unspecified" - it is the single-line change
    that exempts one endpoint from the whole API's authentication."""
    doc = spec()
    doc["paths"]["/users/{userId}"]["get"]["security"] = []
    finding = one(audit.audit(doc, schema_url="s"), "security_opt_out")
    assert finding.severity == "high"
    assert "GET /users/{userId}" in finding.evidence


def test_an_operation_addressing_an_object_without_auth_is_bola_shaped():
    doc = spec()
    doc.pop("security")
    doc["paths"]["/users/{userId}"]["get"]["security"] = []
    findings = audit.audit(doc, schema_url="s")
    # No global requirement to override, so it is not an opt-out; it is an
    # unauthorised object access.
    assert "security_opt_out" not in kinds(findings)
    finding = one(findings, "unauthorised_object_access")
    assert finding.metadata["vuln_class"] == "broken_access_control"
    assert finding.metadata["owasp_api"] == "API1:2023"


def test_an_unauthenticated_write_is_reported_separately():
    doc = spec()
    doc.pop("security")
    doc["paths"]["/signup"] = {"post": {"security": [],
                                        "responses": {"201": {"description": "ok"}}}}
    findings = audit.audit(doc, schema_url="s")
    assert "POST /signup" in one(findings, "unauthenticated_write").evidence


def test_a_properly_secured_contract_produces_no_auth_finding():
    """The default must stay quiet, or every schema is a finding."""
    assert not (kinds(audit.audit(spec(), schema_url="s")) & {
        "no_security", "security_opt_out", "unauthorised_object_access",
        "unauthenticated_write"})


@pytest.mark.parametrize("path,expected", [
    ("/users/{userId}", True),
    ("/orders/{orderId}/items", True),
    ("/accounts/{uuid}", True),
    ("/documents/{ref}", True),
    ("/search/{locale}", False),
    ("/status", False),
])
def test_addressing_one_object_is_about_the_identifier(path, expected):
    assert audit.addresses_one_object(path, {}) is expected


def test_a_path_parameter_declared_only_in_parameters_still_counts():
    assert audit.addresses_one_object(
        "/thing", {"parameters": [{"name": "accountId", "in": "path"}]})


# ---- weak schemes -----------------------------------------------------

@pytest.mark.parametrize("scheme,phrase", [
    ({"type": "http", "scheme": "basic"}, "replayed on every"),
    ({"type": "apiKey", "in": "query", "name": "k"}, "access logs"),
    ({"type": "oauth2", "flows": {"implicit": {}}}, "URL fragment"),
])
def test_a_weak_scheme_is_named_with_the_reason(scheme, phrase):
    problems = audit.weak_schemes({"s": scheme})
    assert problems and phrase in problems[0][1]


def test_a_bearer_token_and_a_header_api_key_are_not_weak():
    assert audit.weak_schemes({
        "a": {"type": "http", "scheme": "bearer"},
        "b": {"type": "apiKey", "in": "header", "name": "X-Key"},
        "c": {"type": "oauth2", "flows": {"authorizationCode": {}}}}) == []


# ---- the rest of the contract ----------------------------------------

def test_a_plaintext_server_url_is_reported():
    doc = spec(servers=[{"url": "http://api.t.example"}])
    assert one(audit.audit(doc, schema_url="s"),
               "plaintext_server").severity == "medium"


def test_a_localhost_server_url_is_not():
    """Every generated example document has one. It is not a finding about
    the target."""
    doc = spec(servers=[{"url": "http://localhost:8080"}])
    assert "plaintext_server" not in kinds(audit.audit(doc, schema_url="s"))


def test_a_contract_with_no_429_anywhere_is_reported():
    doc = spec()
    doc["paths"]["/users/{userId}"]["get"]["responses"].pop("429")
    finding = one(audit.audit(doc, schema_url="s"), "no_throttling_documented")
    assert finding.metadata["vuln_class"] == "rate_limit"
    assert finding.metadata["owasp_api"] == "API4:2023"
    assert finding.severity == "low"


def test_one_documented_429_is_enough_to_stay_quiet():
    assert "no_throttling_documented" not in kinds(audit.audit(spec(), schema_url="s"))


def test_an_open_write_body_is_the_documented_half_of_mass_assignment():
    doc = spec()
    doc["paths"]["/users"] = {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"type": "object", "properties": {
            "name": {"type": "string"}}}}}},
        "responses": {"201": {"description": "ok"}}}}
    finding = one(audit.audit(doc, schema_url="s"), "open_request_body")
    assert finding.metadata["vuln_class"] == "mass_assignment"
    assert finding.metadata["owasp_api"] == "API3:2023"
    assert "POST /users (application/json)" in finding.evidence


def test_additional_properties_false_shuts_the_door():
    doc = spec()
    doc["paths"]["/users"] = {"post": {"requestBody": {"content": {
        "application/json": {"schema": {
            "type": "object", "additionalProperties": False,
            "properties": {"name": {"type": "string"}}}}}},
        "responses": {"201": {"description": "ok"}}}}
    assert "open_request_body" not in kinds(audit.audit(doc, schema_url="s"))


def test_a_referenced_body_schema_is_followed():
    """Real schemas put the model in components and $ref it. Not following
    the reference would make this check silently never fire."""
    doc = spec()
    doc["components"]["schemas"] = {"NewUser": {
        "type": "object", "properties": {"name": {"type": "string"}}}}
    doc["paths"]["/users"] = {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"$ref": "#/components/schemas/NewUser"}}}},
        "responses": {"201": {"description": "ok"}}}}
    assert "open_request_body" in kinds(audit.audit(doc, schema_url="s"))


def test_a_self_referential_schema_does_not_hang():
    doc = spec()
    doc["components"]["schemas"] = {"Loop": {"$ref": "#/components/schemas/Loop"}}
    doc["paths"]["/x"] = {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"$ref": "#/components/schemas/Loop"}}}},
        "responses": {"201": {"description": "ok"}}}}
    audit.audit(doc, schema_url="s")   # returns rather than recursing forever


def test_unbounded_parameters_are_only_reported_as_a_group():
    """Individually they are a style note. Six of them is a statement about
    how the inputs were specified."""
    doc = spec()
    for n in range(6):
        doc["paths"][f"/search{n}"] = {"get": {
            "parameters": [{"name": "q", "in": "query",
                            "schema": {"type": "string"}}],
            "responses": {"200": {"description": "ok"}}}}
    finding = one(audit.audit(doc, schema_url="s"), "unbounded_input")
    assert finding.metadata["affected"] >= 6


def test_a_handful_of_unbounded_parameters_is_not_a_finding():
    doc = spec()
    doc["paths"]["/search"] = {"get": {
        "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
        "responses": {"200": {"description": "ok"}}}}
    assert "unbounded_input" not in kinds(audit.audit(doc, schema_url="s"))


@pytest.mark.parametrize("schema", [
    {"type": "string", "maxLength": 40},
    {"type": "string", "pattern": "^[a-z]+$"},
    {"type": "string", "enum": ["a", "b"]},
    {"type": "array", "maxItems": 20},
    {"type": "integer", "maximum": 100},
])
def test_a_bounded_parameter_is_not_counted(schema):
    doc = {"openapi": "3.0.3", "paths": {"/x": {"get": {
        "parameters": [{"name": "p", "in": "query", "schema": schema}],
        "responses": {"200": {"description": "ok"}}}}}}
    assert audit.unbounded_inputs(doc) == []


# ---- aggregation: a 300-operation schema is not 300 findings ----------

def test_findings_are_aggregated_per_check_not_per_operation():
    """A 300-operation schema with no security would otherwise produce 300
    findings and drown the report - the same flood gau produced."""
    doc = spec()
    doc.pop("components")
    doc.pop("security")
    doc["paths"] = {f"/r{n}/{{id}}": {"get": {"responses": {"200": {"description": "ok"}}}}
                    for n in range(300)}
    findings = audit.audit(doc, schema_url="s")
    assert len([f for f in findings if f.metadata["kind"] == "no_security"]) == 1
    finding = one(findings, "no_security")
    assert finding.metadata["operations"] == 300
    assert finding.evidence.count("\n") <= audit.MAX_EXAMPLES + 2
    assert "and 292 more" in finding.evidence


def test_the_schema_url_is_the_target_of_every_finding():
    """The finding is about the document, so a reader can go and look at it."""
    doc = spec()
    doc.pop("security")
    doc.pop("components")
    for finding in audit.audit(doc, schema_url="https://t.example/openapi.json"):
        assert finding.target == "https://t.example/openapi.json"
        assert "https://t.example/openapi.json" in finding.evidence


def test_swagger_2_documents_are_audited_too():
    """Swagger 2 is still what most internal APIs publish."""
    doc = {"swagger": "2.0", "info": {"title": "T", "version": "1"},
           "schemes": ["http"],
           "securityDefinitions": {"k": {"type": "apiKey", "in": "query",
                                         "name": "token"}},
           "paths": {"/users/{id}": {"get": {"responses": {"200": {}}}}}}
    assert audit.parse(json.dumps(doc)) is not None
    found = kinds(audit.audit(doc, schema_url="s"))
    assert "weak_scheme" in found
    assert "plaintext_server" in found


# ---- it sends nothing, and it has a place in the run -----------------

def test_the_audit_is_pure():
    import inspect
    src = inspect.getsource(audit.audit)
    for forbidden in ("await", "httpx", "requests.", "fetch", "SafePoC"):
        assert forbidden not in src


def test_the_published_schema_is_kept_so_the_audit_can_read_it():
    """It was fetched and thrown away, so the audit had to hope the crawl
    would fetch it again through the capture proxy."""
    import inspect

    from app.analysis import surface_seed
    src = inspect.getsource(surface_seed.seed_published_surface)
    assert '"published.json"' in src
    assert "OPENAPI" in src


def test_the_published_and_synthesised_schemas_have_different_names():
    """One is the vendor's contract and one is our observation. The audit
    must never confuse them."""
    import inspect

    from app.analysis import openapi_synth, surface_seed
    assert '"observed.json"' in inspect.getsource(openapi_synth)
    assert '"published.json"' in inspect.getsource(surface_seed)


def test_it_runs_with_the_other_analysers():
    import inspect

    from app.analysis import run_analysis
    assert "schema_audit" in inspect.getsource(run_analysis)


def test_the_validator_keeps_its_verdict():
    from app.validation.validator import _ANALYSIS_TOOLS
    assert "schema_audit" in _ANALYSIS_TOOLS


def test_every_class_it_reports_reaches_the_exploit_layer():
    from app.exploit.strategy import plan_for
    doc = spec(servers=[{"url": "http://api.t.example"}])
    doc.pop("security")
    doc.pop("components")
    doc["paths"]["/users"] = {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"type": "object", "properties": {
            "n": {"type": "string"}}}}}}, "responses": {"201": {}}}}
    findings = audit.audit(doc, schema_url="s")
    assert findings
    for finding in findings:
        plan = plan_for({"id": "f", "title": finding.title,
                         "target": finding.target,
                         "vuln_class": finding.metadata["vuln_class"],
                         "severity": finding.severity, "status": "confirmed"})
        assert plan.routes or plan.skipped_because, finding.title
        if finding.severity in ("high", "critical", "medium"):
            assert "no route available" not in plan.skipped_because, \
                f"{finding.metadata['vuln_class']} has no route"
