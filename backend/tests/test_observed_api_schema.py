"""The API schema syphax builds from the traffic it captured.

Most applications publish no OpenAPI document, and the ones that do describe
only part of what they run. VULN-API-CONTRACT - the only catalog item that
reasons about an API as a set of OPERATIONS rather than a set of URLs - applied
only to an asset whose URL names a schema, so on most targets it never ran at
all.

These tests cover the schema built from observed behaviour instead: what gets
templated, what gets excluded, how the wrapper switches between a published
schema and a synthesised one, and the refusal when there is nothing to test.
"""
from __future__ import annotations

import inspect as _inspect
import json

import pytest

from app.analysis import openapi_synth as synth
from app.scans.wrappers.schemathesis import (SchemathesisWrapper, is_schema_url)


JSON = "application/json"


def flow(method, url, status=200, ct=JSON, req_ct=None):
    return {"method": method, "url": url, "status_code": status,
            "response_content_type": ct, "request_content_type": req_ct}


# ---- path templating: one operation, not two hundred -------------------

@pytest.mark.parametrize("path,expected", [
    ("/users/4821", "/users/{id}"),
    ("/users/4821/orders/77", "/users/{id}/orders/{id}"),
    ("/v2/accounts/550e8400-e29b-41d4-a716-446655440000", "/v2/accounts/{id}"),
    ("/files/deadbeefcafe1234", "/files/{id}"),
    # Words stay words. Templating "/api/v1/users" would erase the route.
    ("/api/v1/users", "/api/v1/users"),
    ("/about", "/about"),
    ("/", "/"),
])
def test_identifier_segments_become_one_operation(path, expected):
    assert synth.templated(path) == expected


def test_two_hundred_user_ids_are_one_path():
    """The point of templating: a fuzzer can use /users/{id}. It cannot use
    two hundred sibling paths that differ only by a primary key."""
    flows = [flow("GET", f"https://t.example/api/users/{n}") for n in range(200)]
    doc = synth.build(flows, base_url="https://t.example")
    assert list(doc["paths"]) == ["/api/users/{id}"]
    assert synth.operation_count(doc) == 1


def test_an_id_in_the_path_is_declared_as_a_path_parameter():
    doc = synth.build([flow("GET", "https://t.example/api/users/42")],
                      base_url="https://t.example")
    params = doc["paths"]["/api/users/{id}"]["get"]["parameters"]
    path_params = [p for p in params if p["in"] == "path"]
    assert len(path_params) == 1
    assert path_params[0] == {"name": "id", "in": "path", "required": True,
                              "schema": {"type": "string"}}


# ---- what is an API operation, and what is a stylesheet ----------------

def test_static_assets_are_not_api_operations():
    """A PNG and a stylesheet have no API shape. Describing them would hand
    schemathesis operations whose only possible finding is noise."""
    flows = [flow("GET", "https://t.example/logo.png", ct="image/png"),
             flow("GET", "https://t.example/app.css", ct="text/css"),
             flow("GET", "https://t.example/home", ct="text/html")]
    doc = synth.build(flows, base_url="https://t.example")
    assert doc["paths"] == {}


def test_an_api_path_counts_even_without_a_json_response():
    """An endpoint under /api that answered 401 with an HTML error page is
    still an API operation - and an interesting one."""
    doc = synth.build([flow("GET", "https://t.example/api/v1/admin",
                            status=401, ct="text/html")],
                      base_url="https://t.example")
    assert "/api/v1/admin" in doc["paths"]


def test_json_outside_an_api_path_counts_too():
    doc = synth.build([flow("GET", "https://t.example/graph/data", ct=JSON)],
                      base_url="https://t.example")
    assert "/graph/data" in doc["paths"]


# ---- parameters and bodies come from what was observed -----------------

def test_query_parameters_are_declared_with_an_inferred_type():
    doc = synth.build([flow("GET", "https://t.example/api/s?page=2&q=abc&all=true")],
                      base_url="https://t.example")
    params = {p["name"]: p for p in doc["paths"]["/api/s"]["get"]["parameters"]}
    assert params["page"]["schema"] == {"type": "integer"}
    assert params["q"]["schema"] == {"type": "string"}
    assert params["all"]["schema"] == {"type": "boolean"}
    # Not required: we saw it sent once, which says nothing about necessity.
    assert all(p["required"] is False for p in params.values())


def test_a_write_gets_a_request_body_with_the_observed_content_type():
    doc = synth.build([flow("POST", "https://t.example/api/orders", status=201,
                            req_ct="application/json; charset=utf-8")],
                      base_url="https://t.example")
    body = doc["paths"]["/api/orders"]["post"]["requestBody"]
    assert "application/json" in body["content"]
    assert body["required"] is False


def test_a_read_gets_no_request_body():
    doc = synth.build([flow("GET", "https://t.example/api/orders")],
                      base_url="https://t.example")
    assert "requestBody" not in doc["paths"]["/api/orders"]["get"]


def test_every_observed_status_is_merged_onto_the_one_operation():
    """Two requests to the same operation that answered differently are one
    operation with two documented responses, not two operations."""
    flows = [flow("GET", "https://t.example/api/users/1", status=200),
             flow("GET", "https://t.example/api/users/9", status=404),
             flow("GET", "https://t.example/api/users/7", status=403)]
    doc = synth.build(flows, base_url="https://t.example")
    responses = doc["paths"]["/api/users/{id}"]["get"]["responses"]
    assert set(responses) == {"200", "404", "403"}


def test_methods_on_one_path_are_separate_operations():
    flows = [flow("GET", "https://t.example/api/orders"),
             flow("POST", "https://t.example/api/orders", status=201),
             flow("DELETE", "https://t.example/api/orders/4", status=204)]
    doc = synth.build(flows, base_url="https://t.example")
    assert set(doc["paths"]["/api/orders"]) == {"get", "post"}
    assert synth.operation_count(doc) == 3


def test_methods_the_schema_cannot_describe_are_dropped():
    """CONNECT and OPTIONS from the proxy's own traffic are not operations."""
    flows = [flow("CONNECT", "https://t.example/api/x"),
             flow("OPTIONS", "https://t.example/api/x")]
    assert synth.build(flows, base_url="https://t.example")["paths"] == {}


# ---- the document is honest about what it is ---------------------------

def test_the_schema_says_it_was_synthesised():
    """Handing someone a generated file that looks like the vendor's own
    specification would be a lie with a long half-life."""
    doc = synth.build([flow("GET", "https://t.example/api/x")],
                      base_url="https://t.example")
    description = doc["info"]["description"].lower()
    assert "synthesised from captured traffic" in description
    assert "not the vendor" in description
    assert doc["info"]["version"] == "observed"


def test_it_is_a_valid_openapi_3_document_with_the_target_as_its_server():
    doc = synth.build([flow("GET", "https://t.example/api/x")],
                      base_url="https://t.example/")
    assert doc["openapi"].startswith("3.")
    assert doc["servers"] == [{"url": "https://t.example"}]
    json.dumps(doc)   # serialisable: it is written to disk and read by a tool


def test_the_operation_count_is_bounded():
    """A crawl of a large API must not produce a schema so big that testing
    it spends the whole run. The cap is on operations, not on flows read."""
    flows = [flow("GET", f"https://t.example/api/r{n}/items") for n in range(900)]
    doc = synth.build(flows, base_url="https://t.example")
    assert synth.operation_count(doc) == synth.MAX_OPERATIONS


def test_build_makes_no_request_and_touches_no_database():
    """It reads rows that are already recorded. A schema that re-fetched the
    surface would be a second crawl wearing a different name."""
    src = _inspect.getsource(synth.build)
    body = "\n".join(line for line in src.splitlines()
                     if not line.strip().startswith("#"))
    for forbidden in ("requests.", "httpx.", "urlopen", "await ", "fetch"):
        assert forbidden not in body


# ---- the wrapper: published schema, synthesised schema, or refusal -----

@pytest.mark.parametrize("url,expected", [
    ("https://t.example/openapi.json", True),
    ("https://t.example/swagger/v1/swagger.json", True),
    ("https://t.example/api-docs", True),
    ("https://t.example/spec.yaml", True),
    ("https://t.example/", False),
    ("https://t.example/api/users", False),
])
def test_a_target_that_names_a_schema_is_recognised(url, expected):
    assert is_schema_url(url) is expected


def test_a_published_schema_is_fetched_with_no_url_flag():
    """The target IS the schema; schemathesis resolves the server from it."""
    cmd = SchemathesisWrapper().build_command("https://t.example/openapi.json", [])
    assert cmd[1:3] == ["run", "https://t.example/openapi.json"]
    assert "--url" not in cmd


def test_the_synthesised_schema_is_tested_against_the_live_target(monkeypatch, tmp_path):
    spec = tmp_path / "observed.json"
    spec.write_text('{"openapi": "3.0.3"}')
    monkeypatch.setattr(synth, "synthesised_spec", lambda target: spec)

    cmd = SchemathesisWrapper().build_command("https://t.example/", [])
    assert cmd[2] == str(spec)
    assert "--url" in cmd
    # Trailing slash stripped: schemathesis joins the schema's paths onto it.
    assert cmd[cmd.index("--url") + 1] == "https://t.example"


def test_no_schema_means_the_job_is_refused_not_failed(monkeypatch):
    """Without this the job runs schemathesis against an HTML homepage, the
    parse fails, and a non-zero exit reads in the UI as a failed scan of the
    target rather than as "we never built a schema to test"."""
    monkeypatch.setattr(synth, "synthesised_spec", lambda target: None)
    reason = SchemathesisWrapper().precondition("https://t.example/", [])
    assert reason
    assert "no api schema" in reason.lower()


def test_a_published_schema_is_never_refused(monkeypatch):
    monkeypatch.setattr(synth, "synthesised_spec", lambda target: None)
    assert SchemathesisWrapper().precondition(
        "https://t.example/openapi.json", []) == ""


def test_a_present_schema_is_not_refused(monkeypatch, tmp_path):
    spec = tmp_path / "observed.json"
    spec.write_text('{"openapi": "3.0.3"}')
    monkeypatch.setattr(synth, "synthesised_spec", lambda target: spec)
    assert SchemathesisWrapper().precondition("https://t.example/", []) == ""


def test_an_empty_spec_file_counts_as_no_schema(tmp_path, monkeypatch):
    """A zero-byte file left by a failed write is not a schema."""
    from app.scans import artifacts
    monkeypatch.setattr(artifacts.settings, "data_dir", tmp_path)
    directory = artifacts.ensure(artifacts.artifact_dir("https://t.example",
                                                        artifacts.OPENAPI))
    (directory / "observed.json").write_text("")
    assert synth.synthesised_spec("https://t.example") is None


def test_the_written_spec_is_found_back_from_the_target_string_alone(tmp_path, monkeypatch):
    """The wrapper gets a target, not an engagement id. The artifact layout is
    what lets it find the schema the orchestrator wrote."""
    from app.scans import artifacts
    monkeypatch.setattr(artifacts.settings, "data_dir", tmp_path)
    directory = artifacts.ensure(artifacts.artifact_dir("https://t.example/x",
                                                        artifacts.OPENAPI))
    (directory / "observed.json").write_text('{"openapi": "3.0.3"}')
    found = synth.synthesised_spec("https://t.example/other/path?q=1")
    assert found is not None and found.name == "observed.json"


# ---- it has a place in the run, not a button --------------------------

def test_the_catalog_item_exists_and_is_gated_on_the_base_target():
    from app.methodology.catalog import CATALOG, PHASE_VULN
    item = next(i for i in CATALOG if i.id == "VULN-API-OBSERVED")
    assert item.tool == "schemathesis"
    assert item.phase == PHASE_VULN
    assert item.applies_when == {"is_base": True}


def test_the_class_it_reports_has_an_exploit_route():
    """A finding whose vuln_class the strategy does not know falls through
    routes_for into "no route available" and is discarded without a word."""
    from app.exploit.strategy import AUTHORABLE_CLASSES, TOOL_ROUTES
    from app.validation.classes import SURFACE_CLASSES
    known = set(AUTHORABLE_CLASSES) | set(TOOL_ROUTES) | set(SURFACE_CLASSES)
    assert "api_contract_violation" in known


def test_the_schema_is_built_before_the_contract_tests_are_planned():
    """Built at the mapping -> vuln_analysis transition, like parameters and
    the JavaScript cache. A schema built during finalisation could only ever
    help a second run on the same engagement."""
    from app.orchestrator import loop
    src = _inspect.getsource(loop)
    assert "await _synthesise_api_schema(engagement, run)" in src
    assert (src.index("await _synthesise_api_schema(engagement, run)")
            < src.index("await _run_correlation(engagement, run, executor, runs)"))


def test_the_synthesis_never_fails_the_run():
    """Every pre-phase helper in the loop is wrapped: a schema that could not
    be built is a smaller run, not a dead one."""
    from app.orchestrator import loop
    src = _inspect.getsource(loop._synthesise_api_schema)
    assert "except Exception" in src
    assert "logger.exception" in src
