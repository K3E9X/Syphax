"""Taxonomy: what class a finding gets, and what nikto's severity means.

Two false-positive sources are covered here.

1. Nine registered tools had no entry in the tool -> vuln_class map, so their
   findings were classed "unknown", which is not a class the validator can
   re-check. They fell to the heuristic branch and were reported as "likely"
   weaknesses: "Live host: target" shipped at likely/0.5 next to a real SQLi,
   and counted in the false-positive-rate denominator.

2. nikto rates nothing, and the wrapper stamped severity="low" on every line
   it printed. Since the heuristic branch derives its confidence from severity
   alone, a Git config directory and an X-Powered-By header were the same
   finding as far as the validator was concerned.
"""
import pytest

from app.scans.wrappers import _WRAPPERS
from app.scans.wrappers.nikto import DEFAULT_SEVERITY, class_for, severity_for
from app.validation.classes import (
    SURFACE_CLASSES,
    TOOL_VULN_CLASS,
    is_surface,
    vuln_class_of,
)


class FakeFinding:
    def __init__(self, metadata=None):
        self.metadata = metadata


# --------------------------------------------------------------------------
# tool -> class coverage
# --------------------------------------------------------------------------

def test_every_registered_wrapper_has_a_class():
    """A tool absent from the map produces "unknown" findings, which the
    validator cannot re-check and therefore reports as likely."""
    missing = sorted(set(_WRAPPERS) - set(TOOL_VULN_CLASS))
    assert missing == [], f"tools with no vuln_class: {missing}"


def test_no_registered_wrapper_falls_through_to_unknown():
    for tool in _WRAPPERS:
        assert vuln_class_of(FakeFinding(), tool) != "unknown"


@pytest.mark.parametrize("tool", ["httpx", "whatweb", "wafw00f", "subfinder",
                                  "dnsx", "naabu", "nmap", "gau", "katana",
                                  "ffuf"])
def test_recon_tools_are_surface_classes(tool):
    """Recon output describes the surface; it is never a weakness."""
    assert is_surface(vuln_class_of(FakeFinding(), tool))


@pytest.mark.parametrize("tool", ["sqlmap", "commix", "dalfox", "nikto",
                                  "testssl", "wpscan", "nuclei"])
def test_vuln_tools_are_not_surface_classes(tool):
    assert not is_surface(vuln_class_of(FakeFinding(), tool))


def test_finding_metadata_class_wins_over_the_tool_default():
    f = FakeFinding({"vuln_class": "sql_injection"})
    assert vuln_class_of(f, "httpx") == "sql_injection"


def test_unregistered_tool_still_degrades_to_unknown():
    assert vuln_class_of(FakeFinding(), "some-future-tool") == "unknown"
    assert is_surface("unknown")


def test_is_surface_tolerates_none_and_case():
    assert is_surface(None)
    assert is_surface("Fingerprint")
    assert not is_surface("sql_injection")


def test_surface_set_is_the_one_the_report_filters_on():
    from app.reporting.report import _RECON_CLASSES
    assert _RECON_CLASSES is SURFACE_CLASSES


# --------------------------------------------------------------------------
# nikto severity
# --------------------------------------------------------------------------

NIKTO_CASES = [
    ("/.git/config: Git config file found", "high"),
    ("/wp-config.php.bak: Backup config file found", "high"),
    ("/backup.sql: Database dump found", "high"),
    ("Default account found for 'Admin' (admin:admin)", "high"),
    ("Directory traversal: /cgi-bin/../../../etc/passwd", "high"),
    ("/cgi-bin/test.cgi: Remote command execution possible", "high"),
    ("/phpinfo.php: Output from the phpinfo() function was found.", "medium"),
    ("/server-status: Apache server-status is exposed", "medium"),
    ("HTTP method PUT is allowed, files may be uploaded", "medium"),
    ("Apache/2.2.8 appears to be outdated", "medium"),
    ("The anti-clickjacking X-Frame-Options header is not present.", "low"),
    ("Strict-Transport-Security header not defined", "low"),
    ("Retrieved x-powered-by header: PHP/5.4.1", "info"),
    ("No CGI Directories found (use '-C all' to force check all)", "info"),
]


@pytest.mark.parametrize("msg,expected", NIKTO_CASES)
def test_nikto_severity_is_read_from_the_message(msg, expected):
    assert severity_for(msg) == expected


def test_nikto_severity_is_not_flat():
    """The bug this replaces: one severity for every finding."""
    assert len({severity_for(m) for m, _ in NIKTO_CASES}) >= 4


def test_nikto_unknown_wording_keeps_the_conservative_default():
    assert severity_for("some message nikto has not printed before") == DEFAULT_SEVERITY
    assert severity_for("") == DEFAULT_SEVERITY
    assert severity_for(None) == DEFAULT_SEVERITY


def test_nikto_banner_noise_is_classed_as_surface():
    """Header leaks are inventory, so they must not reach section 3 of the
    report as "likely misconfiguration"."""
    assert is_surface(class_for("Retrieved x-powered-by header: PHP/5.4.1"))
    assert is_surface(class_for("Entry /admin/ in robots.txt returned a non-forbidden code"))


def test_nikto_real_exposure_is_not_classed_as_surface():
    assert not is_surface(class_for("/.git/config: Git config file found"))
    assert not is_surface(class_for("HTTP method PUT is allowed"))


def test_nikto_class_matches_the_weakness():
    assert class_for("SQL injection in id parameter") == "sql_injection"
    assert class_for("Cross site scripting (XSS) in q") == "xss"
    assert class_for("HTTP method DELETE is allowed") == "dangerous_http_method"
    assert class_for("X-Content-Type-Options header is not set") == "missing_security_header"


def test_nikto_wrapper_emits_the_rated_severity_and_class():
    from app.scans.wrappers.nikto import NiktoWrapper
    payload = (b'{"host":"t.example.com","vulnerabilities":['
               b'{"msg":"/.git/config: Git config file found","url":"https://t.example.com/.git/config"},'
               b'{"msg":"Retrieved x-powered-by header: PHP/5.4.1","url":"https://t.example.com/"}]}')
    findings = NiktoWrapper().parse(payload, b"", 0, "https://t.example.com").findings
    assert [f.severity for f in findings] == ["high", "info"]
    assert findings[0].metadata["vuln_class"] == "information_disclosure"
    assert findings[1].metadata["vuln_class"] == "fingerprint"
