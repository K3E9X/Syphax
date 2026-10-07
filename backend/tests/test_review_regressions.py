"""Regressions from the pre-deployment review of the new analyzers.

Each case below was a real false positive, a real denial of service, or a real
authorization hole, demonstrated by executing the function. A false positive is
expensive: it buries the findings that matter.
"""
import time

import pytest

from app.analysis.api_exposure import (collect_field_names, is_token_endpoint,
                                       pii_values, secret_fields_in,
                                       severity_for_pii)
from app.analysis.auth_posture import (_bypass_variants, carries_secret,
                                       enumeration_phrase, is_auth_url,
                                       weak_min_length)
from app.analysis.dom_sinks import find_sink_hits, listener_without_origin_check
from app.analysis.error_disclosure import _SIGNATURES
from app.analysis.http_posture import (_host_findings, _is_representative,
                                       csp_weaknesses, parse_cookie)
from app.engagements.scope_util import registrable_domain, same_registrable_domain
from app.sandbox.invocation import build_argv, detect_options, split_target


def _sig(body):
    return [label for _k, _s, label, pat in _SIGNATURES if pat.search(body)]


class _Row(dict):
    def __getitem__(self, k):
        return dict.get(self, k)


# ---- authorization: scope must never reach another tenant ------------------

@pytest.mark.parametrize("host", [
    "victim.table.core.windows.net", "victim.file.core.windows.net",
    "b.storage.googleapis.com", "tenant.sharepoint.com",
    "myapp.cloudapp.azure.com", "proj.supabase.co", "a.github.dev",
])
def test_multi_tenant_platforms_never_expand_scope(host):
    assert registrable_domain(host) is None


def test_two_tenants_are_not_the_same_organisation():
    assert not same_registrable_domain("victim.table.core.windows.net",
                                       "other.table.core.windows.net")
    assert not same_registrable_domain("a.storage.googleapis.com",
                                       "b.storage.googleapis.com")
    assert same_registrable_domain("a.datax.iliad.fr", "prospex.datax.iliad.fr")


def test_a_port_does_not_break_the_comparison():
    assert registrable_domain("example.com:8443") == "example.com"


# ---- availability: two regexes froze the event loop for minutes ------------

def test_email_scan_is_linear():
    body = '{"data":"' + "aGVsbG8td29ybGQ" * 20000 + '"}'
    start = time.time()
    pii_values(body[:300_000])
    assert time.time() - start < 2.0          # was 141s


def test_ruby_signature_is_linear():
    pat = next(p for _k, _s, label, p in _SIGNATURES if label == "Ruby stack trace")
    start = time.time()
    pat.search("A" * 200_000)
    assert time.time() - start < 2.0          # was 91s


# ---- http_posture ----------------------------------------------------------

def test_only_a_real_page_judges_the_headers():
    html = _Row(status_code=200, method="GET",
                response_content_type="text/html; charset=utf-8")
    assert _is_representative(html, [["Server", "x"]])
    for row in (_Row(status_code=None, method="GET", response_content_type=None),
                _Row(status_code=304, method="GET", response_content_type="text/css"),
                _Row(status_code=204, method="OPTIONS", response_content_type=None),
                _Row(status_code=301, method="GET", response_content_type="text/html")):
        assert not _is_representative(row, [["ETag", "a"]])


def test_no_page_response_means_no_header_findings():
    out = _host_findings("h", {"headers": None, "url": "https://h/x",
                               "https": True, "cookies": []})
    assert out == []


def test_a_hardened_policy_is_not_called_weak():
    assert csp_weaknesses("default-src 'none'; script-src 'nonce-r4nd0m'") == []


def test_wildcard_subdomain_is_not_any_origin():
    assert csp_weaknesses("script-src 'self' *.cdn.acme.com") == []
    assert csp_weaknesses("script-src *") != []


def test_script_src_attr_does_not_mask_script_src():
    weak = csp_weaknesses("script-src 'unsafe-inline'; script-src-attr 'none'")
    assert any("unsafe-inline" in w for w in weak)


def test_a_cookie_deletion_is_not_an_insecure_cookie():
    assert parse_cookie("sessionid=; Max-Age=0")["deleted"]
    assert parse_cookie("s=; Expires=Thu, 01 Jan 1970 00:00:00 GMT")["deleted"]
    assert not parse_cookie("sessionid=abc; Secure; HttpOnly")["deleted"]
    assert parse_cookie("deleted")["name"] == ""      # no "=" at all


def test_a_cache_id_is_not_a_version():
    base = [["Content-Security-Policy", "default-src 'none'; script-src 'self'"],
            ["X-Frame-Options", "DENY"], ["X-Content-Type-Options", "nosniff"],
            ["Referrer-Policy", "no-referrer"],
            ["Strict-Transport-Security", 'max-age="31536000"']]
    data = {"headers": base + [["Server", "ECAcc (dcd/7D5D)"]],
            "url": "https://h/", "https": True, "cookies": []}
    assert _host_findings("h", data) == []
    data["headers"] = base + [["Server", "nginx/1.12.0"]]
    assert any("version" in f.title for f in _host_findings("h", data))


# ---- api_exposure ----------------------------------------------------------

def _names(doc):
    n, v = set(), set()
    collect_field_names(doc, n, valued=v)
    return n, v


def test_a_schema_declaring_a_password_is_not_a_leak():
    spec = {"components": {"schemas": {"L": {"properties": {
        "password": {"type": "string", "format": "password"}}}}}}
    n, v = _names(spec)
    assert secret_fields_in(n, valued=v, path="/openapi.json") == []


def test_a_validation_error_naming_a_field_is_not_a_leak():
    n, v = _names({"errors": {"password": ["too short"]}})
    assert secret_fields_in(n, valued=v, path="/api/register") == []


def test_a_real_hash_in_a_user_list_is_still_reported():
    n, v = _names({"users": [{"password_hash": "$2b$12$abcdefghijk"}]})
    assert secret_fields_in(n, valued=v, path="/api/users") == ["password_hash"]


@pytest.mark.parametrize("body", [
    '{"etag":"DE34F5A9B8C7D6E5F4A3B2C1"}',     # uppercase hex -> fake IBAN
    '{"order_ref":"170120000000000"}',          # 15 digits -> fake NIR/card
])
def test_an_identifier_is_not_high_severity_personal_data(body):
    counts = pii_values(body)
    assert severity_for_pii(counts, set()) != "high"


def test_a_real_iban_under_an_iban_key_is_high():
    assert severity_for_pii({"iban": 1}, {"iban"}) == "high"


def test_a_package_spec_is_not_an_email():
    assert pii_values('{"imports":{"react":"https://esm.sh/react@18.2.0"}}') == {}


def test_token_path_is_anchored_on_segments():
    assert not is_token_endpoint("/api/authors/1", set())
    assert is_token_endpoint("/oauth/token", set())


# ---- auth_posture ----------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("/static/reset.css", False), ("/blog/password-manager-review", False),
    ("/authors/42", False), ("/api/login", True), ("/login.php", True),
    ("/forgot-password", True), ("/account/reset", True),
])
def test_auth_urls_are_matched_on_segments(url, expected):
    assert is_auth_url(url) is expected


def test_a_csrf_token_is_not_a_credential():
    assert not carries_secret("csrf_token=9f3a&comment=hi", [])
    assert not carries_secret("compass=north&zoom=4", [])
    assert carries_secret("user=a&password=b", [])
    assert carries_secret('{"api_key":"abc"}', [])


def test_login_page_copy_is_not_enumeration():
    assert enumeration_phrase("No account yet? Sign up") is None
    assert enumeration_phrase("Error: account not found") is not None


def test_password_policy_needs_a_password_context():
    assert weak_min_length('<input type="search" name="q" minlength="3">') is None
    assert weak_min_length('<input type="password" minlength="4">') == 4
    assert weak_min_length('<input type="password" minLength={4} />') == 4


def test_the_bypass_header_carries_the_protected_path():
    """Sending "/" asked the proxy for the homepage; the 200 that came back was
    reported as a proven bypass."""
    variants = dict(_bypass_variants("/admin/secret"))
    assert variants["X-Original-URL"]["X-Original-URL"] == "/admin/secret"
    assert variants["X-Rewrite-URL"]["X-Rewrite-URL"] == "/admin/secret"


# ---- dom_sinks -------------------------------------------------------------

def test_a_declaration_list_does_not_taint_the_first_variable():
    code = 'var template="<b>"+t, qs=location.search; el.innerHTML=template;'
    assert find_sink_hits(code) == []


def test_sanitised_output_is_not_dom_xss():
    code = ('const html=DOMPurify.sanitize(raw), route=location.pathname;'
            ' box.innerHTML=html;')
    assert find_sink_hits(code) == []


def test_a_handler_declared_before_registration_is_followed():
    code = ('function onMessage(e){ if(e.origin!=="https://t") return; r(e.data); }\n'
            + "// filler\n" * 40
            + 'window.addEventListener("message", onMessage);')
    assert listener_without_origin_check(code) is None


def test_an_unchecked_handler_is_still_found():
    assert listener_without_origin_check(
        'window.addEventListener("message", function(e){ run(e.data); })')


# ---- error_disclosure ------------------------------------------------------

@pytest.mark.parametrize("body", [
    "var DEBUG = true;",                                  # JS, not Python
    "<p>we throw a System.ArgumentNullException - see docs</p>",
    "/*! bundled at ./node_modules/axios/index.js */",
    "docs: ActiveRecord::Base.connection is memoised",
])
def test_prose_and_bundles_are_not_errors(body):
    assert _sig(body) == []


def test_real_errors_still_match():
    assert _sig("DEBUG = True")
    assert _sig("   at System.Data.SqlClient.Open(")
    assert _sig(r"Could not find file 'C:\inetpub\wwwroot\web.config'")


# ---- invocation ------------------------------------------------------------

def test_a_short_flag_with_dest_is_understood():
    poc = ('p.add_argument("-t", dest="target", required=True)\n'
           'p.add_argument("-p", dest="port", type=int)')
    assert build_argv(poc, "10.0.0.1:22") == ["-t", "10.0.0.1", "-p", "22"]


def test_the_exploit_is_pointed_at_target_not_domain():
    poc = ('p.add_argument("-d","--domain", required=True)\n'
           'p.add_argument("-t","--target", required=True)\n'
           'p.add_argument("--port")')
    assert detect_options(poc)["target"] == "--target"


@pytest.mark.parametrize("bad", ["http://[::1/path", "https://host:99999/",
                                 "https://h:port/"])
def test_a_malformed_target_does_not_raise(bad):
    host, port, url = split_target(bad)
    assert host and url
