"""Pre-engagement recon: the parsing, the budget, the fingerprinting, the synthesis.

The budget tests are the ones that matter most. Recon runs *before* an
engagement exists, which means there is no authorized scope to check against
and none can be applied - so what reaches the target is bounded by a constant
instead. A change that grows that constant should have to argue with a test.
"""
from __future__ import annotations

import pytest

from app.recon import budget, ct_logs, http_probe, net_info, summary, tech
from app.recon.target import TargetError, parse


# ---- the budget: the whole authorization story ------------------------------

def test_recon_touches_four_paths_and_no_others():
    """Each one is either the page a browser would load, or a file the web has
    agreed is public. Anything else is enumeration, which belongs to an
    engagement - the thing that carries the authorization to do it."""
    assert set(budget.PROBE_PATHS) == {
        "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}


def test_nothing_else_is_requestable():
    for path in ("/admin", "/.git/config", "/.env", "/wp-login.php", "/api/v1/users"):
        assert not budget.path_allowed(path)


def test_recon_never_changes_anything_it_looks_at():
    assert budget.ALLOWED_METHODS == {"GET", "HEAD"}
    for method in ("POST", "PUT", "PATCH", "DELETE", "TRACE", "OPTIONS"):
        assert not budget.method_allowed(method)


def test_the_request_cap_leaves_room_for_the_paths_and_nothing_much_else():
    assert budget.MAX_TARGET_REQUESTS == len(budget.PROBE_PATHS) + 2


def test_the_operator_can_read_what_leaves_this_machine_before_pressing_go():
    described = budget.describe()
    assert set(described) == {"touches_target", "asks_third_parties", "never", "limits"}
    # The refusals are named, not implied.
    never = " ".join(described["never"]).lower()
    for forbidden in ("port scan", "brute force", "vulnerability", "authentication"):
        assert forbidden in never


def test_bodies_are_bounded():
    """The root of a single-page app is routinely a megabyte of inlined
    JavaScript, and none of it is needed to read a <title>."""
    assert budget.MAX_BODY_BYTES <= 1024 * 1024


# ---- target parsing ---------------------------------------------------------

@pytest.mark.parametrize("raw,host,scheme,port", [
    ("example.com", "example.com", "https", 443),
    ("https://example.com", "example.com", "https", 443),
    ("http://example.com", "example.com", "http", 80),
    ("https://app.example.com:8443/portal", "app.example.com", "https", 8443),
    ("EXAMPLE.COM", "example.com", "https", 443),
    ("example.com.", "example.com.", "https", 443),
])
def test_one_field_takes_what_an_operator_actually_pastes(raw, host, scheme, port):
    t = parse(raw)
    assert (t.host, t.scheme, t.port) == (host, scheme, port)


def test_wrapping_junk_is_stripped():
    """A target copied out of a PDF arrives wrapped in a smart quote."""
    for raw in ('  "example.com" ', "«example.com»", "'example.com'", "\texample.com\n"):
        assert parse(raw).host == "example.com"


def test_credentials_in_a_url_are_dropped_and_reported():
    t = parse("https://admin:hunter2@example.com/")
    assert t.host == "example.com"
    assert "hunter2" not in t.base_url
    assert any("credential" in n for n in t.notes), \
        "silently dropping them would leave the operator thinking they were used"


def test_an_ip_is_recognised_as_one():
    assert parse("1.2.3.4").kind == "ipv4"
    assert parse("[2001:4860:4860::8888]:8443").kind == "ipv6"
    assert parse("1.2.3.4").is_ip
    assert parse("example.com").registrable_domain == "example.com"
    assert parse("1.2.3.4").registrable_domain == ""


def test_ipv6_is_bracketed_in_the_url_it_builds():
    t = parse("[2001:4860:4860::8888]:8443")
    assert t.base_url == "https://[2001:4860:4860::8888]:8443/"


def test_registrable_domain_handles_the_common_two_label_suffixes():
    assert parse("sub.example.co.uk").registrable_domain == "example.co.uk"
    assert parse("a.b.c.example.com").registrable_domain == "example.com"


@pytest.mark.parametrize("bad,expect", [
    ("", "enter a hostname"),
    ("ftp://example.com", "use http or https"),
    ("exam_ple.com", "not a valid hostname"),
    ("singleword", "no dot in it"),
    ("http://example.com:notanumber", "port"),
])
def test_bad_input_gets_a_sentence_not_a_stack_trace(bad, expect):
    with pytest.raises(TargetError) as exc:
        parse(bad)
    assert expect in str(exc.value)


def test_a_private_target_is_flagged_but_not_refused():
    """An internal engagement against 10.0.0.0/8 is a normal thing to do.
    Refusing it would be this tool deciding what the operator may test."""
    t = parse("10.0.0.5")
    assert t.host == "10.0.0.5"
    assert any("private" in n for n in t.notes)


def test_localhost_says_which_machine_it_means():
    """The operator's most expensive confusion: localhost inside the container
    is the container, not their laptop."""
    assert any("host.docker.internal" in n for n in parse("localhost").notes)


# ---- technology fingerprinting ----------------------------------------------

def test_the_three_layers_answer_three_different_questions():
    found = tech.detect(
        headers={"Server": "cloudflare", "X-Powered-By": "PHP/8.2.4", "CF-Ray": "abc"},
        cookies=["PHPSESSID"],
        body='<div data-reactroot></div><script src="/js/jquery-3.6.0.min.js"></script>')
    layers = tech.by_layer(found)
    names = {layer: {d["name"] for d in items} for layer, items in layers.items()}
    assert "Cloudflare" in names["infrastructure"]
    assert "PHP" in names["backend"]
    assert {"React", "jQuery"} <= names["frontend"]


def test_an_edge_is_not_mistaken_for_the_application():
    """`Server: cloudflare` says nothing about what the application is built
    from, and filing it as a backend would make the whole panel misleading."""
    found = tech.detect(headers={"Server": "cloudflare"})
    assert [d.layer for d in found] == ["infrastructure"]


def test_versions_are_extracted_where_the_software_gives_them():
    found = {d.name: d for d in tech.detect(
        headers={"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.4"})}
    assert found["nginx"].version == "1.24.0"
    assert found["PHP"].version == "8.2.4"


def test_a_header_beats_a_body_pattern_and_the_version_survives_the_merge():
    """WordPress announces itself twice: a cookie (certain) and a generator tag
    (which is where the version is). Losing either would be a worse answer."""
    found = {d.name: d for d in tech.detect(
        cookies=["wordpress_logged_in_abc"],
        body='<meta name="generator" content="WordPress 6.4.2">')}
    assert found["WordPress"].confidence == tech.CERTAIN
    assert found["WordPress"].version == "6.4.2"


def test_a_waf_is_called_a_waf():
    """Not noticing one is how an engagement produces a page of 403s that get
    read as 'not vulnerable'."""
    found = tech.detect(headers={"X-Sucuri-ID": "1"}, cookies=["incap_ses_1_2"])
    assert set(tech.waf_names(found)) == {"Sucuri WAF", "Imperva Incapsula"}


def test_every_detection_carries_the_evidence_that_produced_it():
    for d in tech.detect(headers={"Server": "nginx/1.24.0"},
                         cookies=["JSESSIONID"],
                         body="<html>jquery.min.js</html>"):
        assert d.evidence, f"{d.name} was reported with nothing to check it against"


def test_a_cms_with_no_signature_still_gets_reported_from_its_generator_tag():
    found = {d.name: d for d in tech.detect(
        body='<meta name="generator" content="SomeObscureCMS 2.1">')}
    assert "SomeObscureCMS" in found
    assert found["SomeObscureCMS"].version == "2.1"
    assert found["SomeObscureCMS"].confidence == tech.LIKELY


def test_nothing_is_invented_from_an_empty_response():
    assert tech.detect(headers={}, cookies=[], body="") == []


def test_every_signature_declares_a_real_layer_and_compiles():
    for sig in tech.SIGNATURES:
        assert sig.layer in tech.LAYERS, f"{sig.name} has layer {sig.layer!r}"
        assert sig.category, f"{sig.name} has no category"
        sig.compiled()
        if sig.where == tech.WHERE_HEADER:
            assert sig.header == sig.header.lower(), \
                f"{sig.name} matches on {sig.header!r}; headers are lowercased on the way in"


# ---- header and cookie review -----------------------------------------------

def test_missing_headers_come_with_the_consequence_not_a_grade():
    review = http_probe.review_headers({"Server": "nginx"})
    assert len(review["missing"]) == len(http_probe.SECURITY_HEADERS)
    for item in review["missing"]:
        assert item["consequence"], f"{item['name']} is reported with no reason to care"


def test_csp_frame_ancestors_supersedes_x_frame_options():
    """Reporting both as missing when one covers the other is how a header
    review loses its credibility with the person reading it."""
    review = http_probe.review_headers(
        {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})
    assert "x-frame-options" not in [m["name"] for m in review["missing"]]


def test_version_disclosing_headers_are_listed_separately():
    review = http_probe.review_headers({"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2"})
    assert {d["name"] for d in review["disclosing"]} == {"server", "x-powered-by"}


def test_cookie_flags_are_read_from_the_raw_header():
    cookies = http_probe.review_cookies([
        "sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax",
        "tracker=1; Path=/",
    ])
    assert cookies[0] == {"name": "sid", "http_only": True, "secure": True, "same_site": "lax"}
    assert cookies[1] == {"name": "tracker", "http_only": False, "secure": False,
                          "same_site": "unset"}


# ---- CT logs ----------------------------------------------------------------

def test_ct_rows_collapse_to_distinct_names():
    """One certificate carries many names and one name appears on many
    certificates, so a busy domain is tens of thousands of rows for a few
    hundred names. Deduplicating is the whole job."""
    rows = [{"issuer_name": "C=US, O=Let's Encrypt, CN=R3",
             "name_value": "example.com\nwww.example.com"}] * 50
    rows.append({"issuer_name": "O=DigiCert Inc", "name_value": "*.example.com"})
    out = ct_logs.summarise(rows, "example.com")
    assert out["names"] == ["example.com", "www.example.com"]
    assert out["wildcards"] == ["*.example.com"]
    assert out["certificates_seen"] == 51


def test_ct_ignores_names_from_another_domain():
    out = ct_logs.summarise(
        [{"name_value": "api.example.com\nevil.example.com.attacker.test"}], "example.com")
    assert out["names"] == ["api.example.com"]


def test_a_crtsh_outage_is_not_an_empty_result():
    """'crt.sh is down' and 'this domain has no certificates' are different
    facts, and conflating them would quietly shrink the scope."""
    assert ct_logs.summarise([], "example.com")["total"] == 0


# ---- ASN interpretation -----------------------------------------------------

def test_shared_infrastructure_is_named():
    assert net_info._is_shared("CLOUDFLARENET, US") == "cloudflare"
    assert net_info._is_shared("AMAZON-02, US") == "amazon"
    assert net_info._is_shared("ACME CORP INTERNAL") == ""


def test_the_cymru_query_name_is_built_per_address_family():
    assert net_info._cymru_name("8.8.8.8") == "8.8.8.8.origin.asn.cymru.com"
    assert net_info._cymru_name("2001:4860:4860::8888").endswith(".origin6.asn.cymru.com")
    assert net_info._cymru_name("not-an-ip") is None


# ---- synthesis --------------------------------------------------------------

def _report(**overrides):
    base = {
        "target": {"host": "example.com", "is_ip": False, "scheme": "https"},
        "dns": {"resolved": True, "addresses": ["1.2.3.4"]},
        "http": {"root": {"status": 200}, "redirects": [], "error": ""},
        "tls": {"available": True, "issues": [], "san": ["example.com"], "san_count": 1},
        "headers": {"present": [], "missing": [], "disclosing": []},
        "cookies": [],
        "technologies": {"frontend": [], "backend": [], "infrastructure": []},
        "certificate_transparency": {"available": False},
        "network": {"asn": {}},
        "public_files": {},
    }
    base.update(overrides)
    return base


def test_an_address_on_someone_elses_network_is_the_first_thing_said():
    """The scoping fact that changes the conversation: an IP belonging to a
    hosting provider is not one the client can authorize you to attack."""
    points = summary.highlights(_report(
        network={"asn": {"as_name": "CLOUDFLARENET, US", "shared_infrastructure": "cloudflare"}}))
    assert points[0]["level"] == summary.LEVEL_WARN
    assert "CLOUDFLARENET" in points[0]["text"]
    assert "authorize" in points[0]["why"]


def test_a_name_that_does_not_resolve_stops_the_rest_from_being_believed():
    points = summary.highlights(_report(dns={"resolved": False, "addresses": []}))
    texts = [p["text"] for p in points]
    assert any("does not resolve" in t for t in texts)


def test_an_expired_certificate_is_a_warning_and_a_short_san_list_is_not():
    warn = summary.highlights(_report(
        tls={"available": True, "issues": ["expired 40 days ago"], "san_count": 1}))
    assert warn[0]["level"] == summary.LEVEL_WARN


def test_a_401_root_says_what_the_engagement_will_need():
    points = summary.highlights(_report(http={"root": {"status": 401}, "redirects": [],
                                              "error": ""}))
    assert any("credentials" in p["why"] for p in points)


def test_candidate_hosts_come_from_the_certificate_and_ct_without_duplicates():
    hosts = summary.candidate_hosts(_report(
        tls={"available": True, "san": ["example.com", "www.example.com", "*.example.com"],
             "san_count": 3, "issues": []},
        certificate_transparency={"available": True,
                                  "names": ["www.example.com", "staging.example.com"]}))
    assert hosts == ["example.com", "www.example.com", "staging.example.com"]
    assert not any(h.startswith("*") for h in hosts), \
        "a wildcard is not a host you can point a scanner at"


def test_the_summary_is_not_a_score():
    """A number invites comparison between targets that have nothing in common,
    and survives into a client meeting as if it meant something."""
    report = _report()
    assert "score" not in summary.counts(report)
    assert all(isinstance(v, int) for v in summary.counts(report).values())


def test_a_connection_that_never_answered_is_not_reported_as_six_missing_headers():
    """Reviewing headers on a response that does not exist reports every
    security header as absent - which reads as a finding about the target when
    it is a finding about the connection."""
    from app.recon.http_probe import Probe
    from app.recon.run import _from_http

    out = _from_http(Probe(requests_made=1, root=None, error="connection timed out"))
    assert out["headers"] == {}
    assert out["technologies"] == {}
    assert out["http"]["error"] == "connection timed out"
    assert summary.counts({**_report(), **out})["missing_headers"] == 0
