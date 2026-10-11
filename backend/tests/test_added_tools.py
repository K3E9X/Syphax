"""The tools added on request, and the two reasons the other four were not.

Six were proposed. Two earned a place; this covers both, and records the
grounds for the four that did not so the decision is in the tree rather than
only in a commit message.
"""
from __future__ import annotations

import json

import pytest

from app.scans.wrappers.s3scanner import (S3ScannerWrapper, exists,
                                          keyword_for, permissions_of,
                                          severity_for)


def record(**kw):
    base = {"name": "acme-data", "provider": "aws", "exists": True}
    base.update(kw)
    return json.dumps(base).encode()


# ---- s3scanner: six providers, and the grants, not just the name -----

@pytest.mark.parametrize("target,expected", [
    ("https://www.acme.com/x", "acme"),
    ("https://shop.acme.com", "acme"),
    ("https://acme.co.uk", "acme"),
    ("acme.com", "acme"),
])
def test_the_brand_is_derived_from_the_target(target, expected):
    """Bucket discovery is a permutation of a brand, so getting the brand
    wrong means scanning someone else's names."""
    assert keyword_for(target) == expected


def test_a_target_with_no_brand_refuses_the_job():
    wrapper = S3ScannerWrapper()
    assert keyword_for("") == ""
    assert wrapper.precondition("", []) != ""


def test_all_six_providers_are_asked_for():
    cmd = S3ScannerWrapper().build_command("https://acme.com", [])
    assert "-provider" in cmd
    assert cmd[cmd.index("-provider") + 1] == "all"
    assert cmd[cmd.index("-bucket") + 1] == "acme"


def test_no_credential_is_ever_passed():
    """Anonymous only: this is reconnaissance against public configuration,
    not authenticated enumeration of someone's cloud account."""
    cmd = S3ScannerWrapper().build_command("https://acme.com", [])
    joined = " ".join(cmd).lower()
    for forbidden in ("-key", "-secret", "access-key", "-profile", "-token"):
        assert forbidden not in joined


@pytest.mark.parametrize("perms,expected", [
    ({"allusers": ["write"], "authusers": []}, "critical"),
    ({"allusers": ["read"], "authusers": []}, "high"),
    ({"allusers": [], "authusers": ["write"]}, "high"),
    ({"allusers": [], "authusers": ["read"]}, "medium"),
    ({"allusers": [], "authusers": []}, "info"),
])
def test_the_severity_follows_who_may_do_what(perms, expected):
    """Anonymous write is the worst thing a bucket can offer: whatever
    consumes it now has an attacker-controlled input."""
    assert severity_for(perms) == expected


def test_both_output_shapes_are_read():
    """A wrapper that only understands the shape in front of it today
    reports nothing after the next upgrade - which is how two tools in this
    image failed silently for a month."""
    nested = permissions_of({"permissions": {"AllUsers": {"Read": True,
                                                          "Write": False}}})
    flat = permissions_of({"perm_all_users_read": "true"})
    assert nested["allusers"] == ["read"]
    assert flat["allusers"] == ["read"]


def test_a_bucket_that_does_not_exist_is_not_a_finding():
    assert not exists({"name": "nope", "exists": False})
    result = S3ScannerWrapper().parse(record(exists=False), b"", 0, "https://acme.com")
    assert result.findings == []


def test_a_writable_bucket_is_critical_and_says_why():
    out = S3ScannerWrapper().parse(
        record(permissions={"AllUsers": {"Read": True, "Write": True}}),
        b"", 0, "https://acme.com")
    assert len(out.findings) == 1
    finding = out.findings[0]
    assert finding.severity == "critical"
    assert finding.metadata["vuln_class"] == "exposed_bucket"
    assert "supply chain" in finding.description
    assert "acme-data" in finding.evidence


def test_a_bucket_that_grants_nothing_is_recorded_as_surface():
    """It exists. The next engagement starts from the inventory this one
    leaves, so it belongs in the report - as recon, not as a weakness."""
    out = S3ScannerWrapper().parse(record(), b"", 0, "https://acme.com")
    assert out.findings[0].severity == "info"
    assert out.findings[0].metadata["vuln_class"] == "recon"


def test_a_malformed_line_costs_one_bucket_not_the_scan():
    stream = b"\n".join([record(name="a"), b"{not json", record(name="b")])
    out = S3ScannerWrapper().parse(stream, b"", 0, "https://acme.com")
    assert len(out.findings) == 2


def test_it_is_registered_everywhere_a_tool_has_to_be():
    from app.methodology.catalog import CATALOG, PHASE_RECON
    from app.scans.wrappers import _WRAPPERS, preflight
    from app.validation.classes import TOOL_VULN_CLASS

    assert "s3scanner" in _WRAPPERS
    assert TOOL_VULN_CLASS["s3scanner"] == "exposed_bucket"
    assert any(r["tool"] == "s3scanner" for r in preflight())
    item = next(i for i in CATALOG if i.id == "RECON-BUCKETS")
    assert item.tool == "s3scanner"
    assert item.phase == PHASE_RECON
    assert item.applies_when == {"is_host": True}


def test_it_does_not_replace_cloud_enum():
    """They answer the same question differently: cloud_enum permutes names
    across three providers, this one checks grants across six. Dropping
    either would lose coverage."""
    from app.methodology.catalog import CATALOG
    tools = {i.tool for i in CATALOG}
    assert {"cloud_enum", "s3scanner"} <= tools


# ---- the credentials a spray should actually try ---------------------

def test_the_fingerprint_chooses_the_credentials():
    """Twelve generic pairs were sprayed at every login form whatever the
    application was. Grafana ships admin/admin, Tomcat ships tomcat/s3cret,
    and the fingerprint that would have said so was already in the database
    and unread."""
    from app.exploit.vendor_creds import for_technologies
    assert ("tomcat", "s3cret") in for_technologies(["Apache Tomcat/9.0.71"])
    assert ("guest", "guest") in for_technologies(["RabbitMQ 3.12"])
    assert ("admin", "Harbor12345") in for_technologies(["Harbor"])


def test_an_unknown_stack_falls_back_to_the_generic_list():
    """The default must stay what it was: this changes which credentials are
    tried on a KNOWN product, not what happens otherwise."""
    from app.exploit.auth_brute import DEFAULT_CREDS, MAX_PAIRS_PER_ENDPOINT
    from app.exploit.vendor_creds import for_technologies, spray_list
    assert for_technologies(["vercel", "hsts"]) == []
    assert spray_list(["vercel"], DEFAULT_CREDS,
                      limit=MAX_PAIRS_PER_ENDPOINT) == DEFAULT_CREDS


def test_the_vendor_pairs_come_first():
    """They are the ones with a real chance, and the budget is the scarce
    thing."""
    from app.exploit.auth_brute import DEFAULT_CREDS
    from app.exploit.vendor_creds import spray_list
    pairs = spray_list(["Grafana 9.5.1", "Jenkins"], DEFAULT_CREDS, limit=12)
    assert pairs[0] == ("admin", "admin")
    assert ("jenkins", "jenkins") in pairs[:4]


def test_the_attempt_budget_is_unchanged():
    """This is a spray, not a brute force. The cap is on attempts against
    someone's login endpoint and must not grow because the list did."""
    from app.exploit.auth_brute import DEFAULT_CREDS, MAX_PAIRS_PER_ENDPOINT
    from app.exploit.vendor_creds import spray_list
    assert MAX_PAIRS_PER_ENDPOINT == len(DEFAULT_CREDS) == 12
    many = spray_list(["tomcat", "jenkins", "gitlab", "weblogic", "nexus"],
                      DEFAULT_CREDS, limit=MAX_PAIRS_PER_ENDPOINT)
    assert len(many) == MAX_PAIRS_PER_ENDPOINT


def test_no_pair_is_tried_twice():
    from app.exploit.auth_brute import DEFAULT_CREDS
    from app.exploit.vendor_creds import spray_list
    pairs = spray_list(["grafana", "sonarqube", "cacti"], DEFAULT_CREDS, limit=12)
    assert len(pairs) == len(set(pairs))


def test_the_finding_names_the_product_it_matched():
    """"admin/admin worked" and "Grafana's documented default worked" are
    the same fact and not the same report."""
    import inspect

    from app.exploit import auth_brute
    src = inspect.getsource(auth_brute._spray_endpoint)
    assert "matched" in src
    assert "fingerprint_matched" in src


def test_the_spray_still_needs_active_exploitation():
    import inspect

    from app.exploit import auth_brute
    src = inspect.getsource(auth_brute.run_auth_spray)
    assert "allow_active_exploit" in src


def test_every_vendor_entry_is_usable():
    from app.exploit.vendor_creds import VENDOR_CREDS
    assert len(VENDOR_CREDS) >= 30
    for marker, pairs in VENDOR_CREDS.items():
        assert marker == marker.lower().strip(), marker
        assert pairs, marker
        for user, pwd in pairs:
            assert isinstance(user, str) and isinstance(pwd, str), marker


# ---- the four that were not added, and why ---------------------------

def test_nord_stream_is_present_but_double_gated():
    """The operator chose to add it. nord-stream deploys pipelines into the
    client's own CI and can lift branch protections, so being installed is
    not the same as being runnable: the engagement must DECLARE the
    destructive and persistence capabilities before the worker will spawn it,
    and the wrapper refuses again without an operator-supplied platform and
    token. Two independent gates, because the cost of a mistake is a change to
    someone else's production CI."""
    from app.exploit.capabilities import CAP_DESTRUCTIVE, CAP_PERSISTENCE
    from app.scans.wrappers import _WRAPPERS
    w = _WRAPPERS["nord_stream"]
    assert set(w.requires_capability) == {CAP_DESTRUCTIVE, CAP_PERSISTENCE}
    # gate two: no operator options -> refused with a reason.
    assert w.precondition("https://t.example/", [])
    assert w.precondition("https://t.example/", ["github", "--token", "x"]) == ""


def test_the_capability_gate_is_enforced_before_the_process_exists():
    """requires_capability is meaningless unless something checks it. The
    worker refuses the job before spawning, so launching it directly cannot
    step around the declaration - and it fails closed."""
    import inspect

    from app import workers
    src = inspect.getsource(workers)
    assert "_missing_capability" in src
    assert "requires_capability" in inspect.getsource(workers._missing_capability)
    assert "unreadable authorisation is a refusal" in src


def test_grafana_scanner_is_a_second_opinion_not_a_replacement():
    """The operator asked for it alongside nuclei, not instead. Both run: the
    nuclei items stay, and the Grafana scanner is gated on the fingerprint so
    it only fires where Grafana was actually seen."""
    from app.methodology.catalog import CATALOG
    assert [i for i in CATALOG if i.tool == "nuclei"]        # still there
    item = next(i for i in CATALOG if i.id == "VULN-GRAFANA")
    assert item.tool == "grafana_scanner"
    assert item.applies_when == {"tech_any": ["grafana"]}


def test_the_grafana_wrapper_fails_loud_not_silent():
    """It is an unverified single-maintainer format. If it clearly ran but the
    output did not map, it must surface the raw output for review rather than
    return nothing that reads as a clean bill of health."""
    from app.scans.wrappers.grafana_scanner import GrafanaScannerWrapper
    out = GrafanaScannerWrapper().parse(
        b"Grafana instance detected, unfamiliar output", b"", 0, "https://g")
    assert len(out.findings) == 1
    assert out.findings[0].metadata.get("needs_manual_review")


def test_the_aws_blast_radius_is_already_covered_in_house():
    """CloudPEASS enumerates a compromised principal's permissions, which
    needs a live cloud credential - and for AWS, the case that actually
    occurs here, intel/cloud_creds already probes it read-only behind the
    same gate."""
    import inspect

    from app.intel import cloud_creds
    src = inspect.getsource(cloud_creds)
    assert "allow_active_exploit" in src
    assert "GetCallerIdentity" in src or "get_caller_identity" in src


# ---- CVE-2026-46333: detect and stage, never auto-fire ----------------

@pytest.mark.parametrize("uname,candidate", [
    ("Linux h 6.11.0-19-generic #19 SMP x86_64 GNU/Linux", True),
    ("Linux h 6.1.0-21-amd64 x86_64 GNU/Linux", True),
    ("Linux h 6.16.2 x86_64", False),      # patched
    ("Linux h 5.15.0-91-generic x86_64", False),   # out of family
    ("Darwin host 23.1.0", False),         # not Linux
    ("", False),
])
def test_the_vulnerable_kernel_range_is_detected(uname, candidate):
    from app.exploit.kernel_privesc import cve_candidate, kernel_version
    assert cve_candidate(kernel_version(uname)) is candidate


def test_the_detection_module_delivers_no_exploit():
    """Detect-and-stage, not auto-fire: there is no exploit delivery in this
    module. The weaponised path was declined - a kernel exploit runs only
    through the operator-approved staging flow. Checked by behaviour, not by
    grepping prose: the module exposes only detection, and the functions that
    would upload or run a binary do not exist on it."""
    from app.exploit import kernel_privesc
    assert hasattr(kernel_privesc, "kernel_version")
    assert hasattr(kernel_privesc, "cve_candidate")
    for delivery in ("delivery_command", "available_binary", "root_read_proven",
                     "EXPLOIT_DIR", "BINARIES"):
        assert not hasattr(kernel_privesc, delivery), (
            f"delivery code leaked back in: {delivery}")
    # and it imports nothing that executes
    import inspect
    src = inspect.getsource(kernel_privesc)
    assert "import base64" not in src
    assert "import subprocess" not in src


def test_a_vulnerable_kernel_is_reported_as_a_lead_carrying_the_cve():
    """The lead carries cve_id so the public-PoC search stages the exploit -
    the same human-in-the-loop path every third-party PoC takes."""
    import inspect

    from app.exploit import proof
    src = inspect.getsource(proof)
    assert "kernel_privesc_lead" in src
    assert "CVE_ID" in src
    # it must be a FINDING, not an exploit invocation
    assert "available_binary" not in src
    assert "delivery_command" not in src


def test_the_staging_search_consumes_the_cve_lead():
    """The link that makes detect-and-stage work: analyze_public_exploits
    reads cve_id off findings, so a CVE-2026-46333 lead reaches it."""
    import inspect

    from app.analysis import public_exploits
    from app.exploit.kernel_privesc import CVE_ID
    assert CVE_ID == "CVE-2026-46333"
    assert 'cve_id' in inspect.getsource(public_exploits.analyze_public_exploits)


def test_the_lead_is_not_over_confident():
    """It is a version-range match, not a demonstration. "likely", not
    "confirmed" - the sandbox run is what would confirm it."""
    import inspect

    from app.exploit import proof
    src = inspect.getsource(proof)
    block = src[src.index("kernel_privesc_lead") - 600:src.index("kernel_privesc_lead") + 200]
    assert '"likely"' in block
