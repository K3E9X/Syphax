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

def test_no_tool_that_modifies_the_clients_infrastructure_was_added():
    """nord-stream extracts CI/CD secrets by DEPLOYING pipelines: it pushes
    commits and can disable branch protections. That is a change to systems
    outside the engagement's target, needing its own credentials and its own
    written authorisation. Scope is the authorisation, and it is not
    grantable."""
    from app.scans.wrappers import _WRAPPERS
    assert "nord-stream" not in _WRAPPERS
    assert "nordstream" not in _WRAPPERS


def test_no_local_privilege_escalation_exploit_was_bundled():
    """ssh-keysign-pwn is CVE-2026-46333, a local kernel privesc. It needs an
    unprivileged shell on the host. syphax tests remote targets over HTTP and
    never has a foothold, so there is nothing for it to run on - and if the
    CVE appears in a fingerprint, the public-PoC search already finds that
    repository and stages it for review."""
    from app.scans.wrappers import _WRAPPERS
    assert "ssh-keysign-pwn" not in _WRAPPERS
    assert "sshkeysign" not in _WRAPPERS


def test_grafana_is_covered_by_the_scanner_that_is_maintained():
    """A single-vendor scanner with 30 commits and no releases is a worse bet
    than nuclei, whose Grafana templates are updated by other people. The
    nuclei items that would carry them run on every target."""
    from app.methodology.catalog import CATALOG
    nuclei_items = [i for i in CATALOG if i.tool == "nuclei"]
    assert len(nuclei_items) >= 5
    assert any(i.applies_when.get("always") for i in nuclei_items)


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
