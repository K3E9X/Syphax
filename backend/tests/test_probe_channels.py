"""Injection channels: widening the oracle past the query string.

The adaptive prober could only reach query parameters. A finding on
`POST /api/login` or on `GET /api/users/1337` therefore had no testable point,
so it was never DECIDED - it stayed "likely" and was reported as a guess. That
is a false-positive problem, not a coverage one: an undecidable finding is
indistinguishable from a wrong one.

Two safety properties are asserted here as hard rules:
  * a body channel exists only for a request we actually observed, so the
    prober never POSTs to an endpoint nobody has seen it POST to;
  * a body probe is measured against the same POST with the ORIGINAL values,
    because every oracle requires the signal to be absent from the baseline.
"""
import json

import pytest

from app.exploit.channels import (
    BODY,
    FORM_CT,
    JSON_CT,
    PATH,
    QUERY,
    BodyChannel,
    Point,
    body_channel,
    body_points,
    encode_body,
    has_injection_point,
    inject_body,
    inject_path,
    injection_points,
    parse_point,
    parse_request,
    path_points,
    query_points,
)
from app.exploit.payload_gen import (
    PROBE_METHODS,
    baseline_request,
    build_request,
    validate_probe,
)

IN_SCOPE = lambda h: h.endswith("target.example.com")
URL = "https://target.example.com/api/users/1337/orders?sort=date"

RAW_POST = (
    "POST /api/login HTTP/1.1\r\n"
    "Host: target.example.com\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "\r\n"
    "username=alice&password=hunter2&remember=1"
)
RAW_JSON_POST = (
    "POST /api/search HTTP/1.1\r\n"
    "Host: target.example.com\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    '{"q": "shoes", "page": 2}'
)


# --------------------------------------------------------------------------
# point addressing
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,channel,name", [
    ("id", QUERY, "id"),
    ("query:id", QUERY, "id"),
    ("body:username", BODY, "username"),
    ("path:3", PATH, "3"),
    ("user.name", QUERY, "user.name"),
    ("filter[id]", QUERY, "filter[id]"),
])
def test_points_parse(raw, channel, name):
    p = parse_point(raw)
    assert p == Point(channel, name)


@pytest.mark.parametrize("raw", [
    "", None, "path:abc", "path:", "body:", "a b", "id;DROP", "x" * 80,
    "header:host",
])
def test_unaddressable_params_are_refused(raw):
    assert parse_point(raw) is None


def test_point_round_trips_through_its_string_form():
    for raw in ("id", "body:username", "path:3"):
        assert str(parse_point(raw)) == raw


# --------------------------------------------------------------------------
# query + path
# --------------------------------------------------------------------------

def test_query_points_are_found():
    assert [p.name for p in query_points("https://t.example/a?id=1&q=x")] == ["id", "q"]
    assert query_points("https://t.example/a") == []


def test_path_points_pick_values_not_routes():
    """Replacing `/api/` with a payload just produces a 404."""
    pts = path_points("https://t.example/api/users/1337/orders")
    assert [p.index for p in pts] == [2]


@pytest.mark.parametrize("url,expected", [
    ("https://t.example/api/v2/users/42", [1, 3]),       # v2 and 42
    ("https://t.example/files/report2023.pdf", [1]),
    ("https://t.example/u/3f2b1c8d9e0a4b5c6d7e8f90", [1]),
    ("https://t.example/x/550e8400-e29b-41d4-a716-446655440000", [1]),
    ("https://t.example/about/contact", []),
])
def test_path_point_selection(url, expected):
    assert [p.index for p in path_points(url)] == expected


def test_inject_path_replaces_the_segment():
    out = inject_path("https://t.example/api/users/1337/orders", 2, "9999")
    assert out == "https://t.example/api/users/9999/orders"


def test_inject_path_percent_encodes_so_traversal_stays_one_segment():
    out = inject_path("https://t.example/api/users/1337", 2, "../../etc/passwd")
    assert out == "https://t.example/api/users/..%2F..%2Fetc%2Fpasswd"
    assert "/etc/passwd" not in out


def test_inject_path_keeps_a_trailing_slash():
    assert inject_path("https://t.example/a/1/", 1, "2") == "https://t.example/a/2/"


@pytest.mark.parametrize("url,index", [
    ("https://t.example/a/1", 9),
    ("https://t.example/a/1", -1),
    ("not-a-url", 0),
    ("", 0),
])
def test_inject_path_refuses_what_does_not_exist(url, index):
    assert inject_path(url, index, "x") is None


# --------------------------------------------------------------------------
# body channel: observed, never invented
# --------------------------------------------------------------------------

def test_a_captured_form_post_becomes_a_channel():
    ch = body_channel({"req": RAW_POST})
    assert ch.method == "POST"
    assert ch.params == {"username": "alice", "password": "hunter2", "remember": "1"}
    assert not ch.is_json


def test_a_captured_json_post_becomes_a_channel():
    ch = body_channel({"req": RAW_JSON_POST})
    assert ch.is_json
    assert ch.params == {"q": "shoes", "page": 2}


def test_no_captured_request_means_no_body_channel():
    """The safety property: we never POST to an endpoint nobody has seen us
    POST to, because a guessed form can create orders and send mail."""
    assert body_channel(None) is None
    assert body_channel({}) is None
    assert body_channel({"req": ""}) is None
    assert body_channel({"req": "garbage that is not a request"}) is None


def test_a_captured_get_is_not_a_body_channel():
    ch = body_channel({"req": "GET /a?x=1 HTTP/1.1\r\nHost: t\r\n\r\n"})
    assert ch is None


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_state_destroying_methods_never_become_a_channel(method):
    """A probe never needs to PUT or DELETE, and those are the methods that
    destroy data on a target the operator asked us to test."""
    raw = (f"{method} /api/users/1 HTTP/1.1\r\nHost: t\r\n"
           "Content-Type: application/json\r\n\r\n" '{"name":"x"}')
    assert body_channel({"req": raw}) is None
    assert method not in PROBE_METHODS


def test_a_post_with_no_body_has_no_field_to_inject():
    assert body_channel({"req": "POST /a HTTP/1.1\r\nHost: t\r\n\r\n"}) is None


def test_analyzers_that_stored_the_pieces_also_work():
    ch = body_channel({"method": "POST", "body": {"q": "x"}})
    assert ch is not None and ch.params == {"q": "x"}
    ch2 = body_channel({"method": "POST", "content_type": FORM_CT, "body": "a=1&b=2"})
    assert ch2.params == {"a": "1", "b": "2"}


def test_parse_request_handles_lf_only_and_junk():
    assert parse_request("POST /a HTTP/1.1\nHost: t\n\nx=1")[0] == "POST"
    assert parse_request("")[0] == ""
    assert parse_request(None)[0] == ""
    assert parse_request("\n\n\n")[0] == ""
    assert parse_request("lowercase /a")[0] == ""


def test_body_points_skip_nested_structures():
    ch = BodyChannel("POST", JSON_CT, {"q": "x", "filters": {"a": 1}, "ids": [1, 2]})
    assert [p.name for p in body_points(ch)] == ["q"]
    assert body_points(None) == []


# --------------------------------------------------------------------------
# body injection + encoding
# --------------------------------------------------------------------------

def test_inject_body_replaces_one_field_and_keeps_the_rest():
    ch = body_channel({"req": RAW_POST})
    out = inject_body(ch, "username", "alice' OR '1'='1")
    assert "password=hunter2" in out
    assert "remember=1" in out
    assert "alice%27+OR+%271%27%3D%271" in out


def test_inject_body_keeps_json_as_json():
    ch = body_channel({"req": RAW_JSON_POST})
    out = inject_body(ch, "q", "{{137*100+11}}")
    parsed = json.loads(out)
    assert parsed == {"q": "{{137*100+11}}", "page": 2}


def test_inject_body_refuses_a_field_we_never_saw():
    """A model-invented parameter is refused before anything is sent."""
    ch = body_channel({"req": RAW_POST})
    assert inject_body(ch, "csrf_token", "x") is None
    assert inject_body(None, "username", "x") is None


def test_encode_body_survives_a_none_value():
    assert "a=" in encode_body(BodyChannel("POST", FORM_CT, {"a": None}), {"a": None})


# --------------------------------------------------------------------------
# all points on a finding
# --------------------------------------------------------------------------

def test_a_query_url_still_has_its_points():
    pts = injection_points("https://t.example/a?id=1")
    assert [str(p) for p in pts] == ["id"]


def test_a_rest_path_now_has_a_point_where_it_had_none():
    """The finding class that could never be decided before."""
    assert has_injection_point("https://t.example/api/users/1337")
    assert [str(p) for p in injection_points("https://t.example/api/users/1337")] \
        == ["path:2"]


def test_a_captured_post_adds_its_body_fields():
    pts = injection_points("https://target.example.com/api/login",
                           {"req": RAW_POST})
    assert [str(p) for p in pts] == ["body:username", "body:password",
                                     "body:remember"]


def test_query_comes_before_body_before_path():
    pts = injection_points(URL, {"req": RAW_POST})
    assert [str(p) for p in pts][0] == "sort"
    assert str(pts[-1]).startswith("path:")


def test_a_finding_with_nothing_to_inject_is_still_rejected():
    assert not has_injection_point("https://t.example/about/contact")
    assert not has_injection_point("")


# --------------------------------------------------------------------------
# validate_probe accepts channel-addressed params
# --------------------------------------------------------------------------

def test_validate_probe_accepts_each_channel():
    for param, channel in (("sort", QUERY), ("body:username", BODY), ("path:3", PATH)):
        probe = validate_probe(
            {"oracle": "reflection", "param": param, "payload": "syphaxmark",
             "expect": "syphaxmark"}, URL, IN_SCOPE)
        assert probe is not None, param
        assert probe["channel"] == channel
        assert probe["param"] == param


def test_validate_probe_still_refuses_junk_params():
    for param in ("", "a b", "path:x", "header:host"):
        assert validate_probe(
            {"oracle": "reflection", "param": param, "payload": "m", "expect": "m"},
            URL, IN_SCOPE) is None


def test_validate_probe_still_refuses_a_destructive_payload_on_a_body_point():
    assert validate_probe(
        {"oracle": "signature", "param": "body:username",
         "payload": "x'; DROP TABLE users; --", "expect": "err"},
        URL, IN_SCOPE) is None


# --------------------------------------------------------------------------
# request building
# --------------------------------------------------------------------------

def probe(param, payload="PROBEMARK", oracle="reflection"):
    p = validate_probe({"oracle": oracle, "param": param, "payload": payload,
                        "expect": payload}, URL, IN_SCOPE)
    assert p is not None, f"validate_probe refused {param}"
    return p


def test_a_query_probe_is_a_get_with_the_param_replaced():
    req = build_request(URL, probe("sort"), "PAYLOAD")
    assert req.method == "GET"
    assert "sort=PAYLOAD" in req.url
    assert req.body is None


def test_a_path_probe_is_a_get_on_the_rewritten_path():
    req = build_request(URL, probe("path:2"), "9999")
    assert req.method == "GET"
    assert "/api/users/9999/orders" in req.url


def test_a_body_probe_is_the_observed_method_with_the_body_replaced():
    ch = body_channel({"req": RAW_POST})
    req = build_request("https://target.example.com/api/login",
                        probe("body:username"), "PAYLOAD", ch)
    assert req.method == "POST"
    assert "username=PAYLOAD" in req.body
    assert req.content_type == FORM_CT


def test_a_body_probe_without_a_channel_sends_nothing():
    assert build_request(URL, probe("body:username"), "P", None) is None


def test_a_body_probe_for_an_unobserved_field_sends_nothing():
    ch = body_channel({"req": RAW_POST})
    assert build_request(URL, probe("body:invented"), "P", ch) is None


def test_a_path_probe_past_the_end_of_the_url_sends_nothing():
    assert build_request(URL, probe("path:9"), "P") is None


def test_the_body_baseline_is_the_same_post_with_original_values():
    """Comparing a POST probe against a GET of the same URL would make any
    difference look like a hit; every oracle needs a true baseline."""
    ch = body_channel({"req": RAW_POST})
    base = baseline_request("https://target.example.com/api/login",
                            probe("body:username"), ch)
    assert base.method == "POST"
    assert "username=alice" in base.body
    assert "password=hunter2" in base.body


def test_the_query_and_path_baselines_are_the_untouched_get():
    for param in ("sort", "path:2"):
        base = baseline_request(URL, probe(param))
        assert base.method == "GET"
        assert base.url == URL
        assert base.body is None


def test_a_body_baseline_without_a_channel_sends_nothing():
    assert baseline_request(URL, probe("body:username"), None) is None


def test_request_labels_show_the_body_so_evidence_is_reproducible():
    ch = body_channel({"req": RAW_POST})
    req = build_request("https://target.example.com/api/login",
                        probe("body:password"), "P", ch)
    assert req.label.startswith("POST https://target.example.com/api/login [")
    assert "password=P" in req.label


# --------------------------------------------------------------------------
# the probe client's own policy
# --------------------------------------------------------------------------

def test_probe_client_allows_only_read_plus_post():
    import asyncio

    from app.exploit.probe_client import ALLOWED_METHODS, ProbeClient
    from app.validation.safe_poc import PolicyError, ScopeError

    assert ALLOWED_METHODS == {"GET", "HEAD", "POST"}
    client = ProbeClient(in_scope=IN_SCOPE)
    loop = asyncio.new_event_loop()
    for method in ("PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"):
        with pytest.raises(PolicyError):
            loop.run_until_complete(client.fetch(URL, method=method))
    with pytest.raises(ScopeError):
        loop.run_until_complete(client.fetch("https://evil.example/", method="GET"))
    loop.close()


def test_safe_poc_policy_is_untouched():
    """The prober got its own client precisely so this stayed GET/HEAD."""
    from app.validation.safe_poc import ALLOWED_METHODS
    assert ALLOWED_METHODS == {"GET", "HEAD"}
