"""Guards for three defects that silently degraded the client deliverable.

Each of these shipped a wrong answer rather than an error, which is the worst
failure mode for a pentest report.
"""
import json

from app.reporting.report import false_positive_rate
from app.scans.wrappers.wpscan import WpscanWrapper
from app.validation.validator import _EXPOSED_SIGNATURES, _signature_present


# ---- 1. the FP rate every report printed as 0% -------------------------------
def test_false_positive_rate_is_derived_from_the_counts():
    # summary() returns only {status: count}; the rate must be computed from it,
    # not read from a key nobody sets.
    assert false_positive_rate({"confirmed": 3, "false_positive": 1}) == 25.0
    assert false_positive_rate({"confirmed": 2, "likely": 2, "false_positive": 1}) == 20.0
    assert false_positive_rate({"confirmed": 4}) == 0.0


def test_false_positive_rate_handles_empty_and_garbage():
    assert false_positive_rate({}) == 0.0                      # no findings, no division
    assert false_positive_rate({"confirmed": None, "false_positive": None}) == 0.0


# ---- 2. signatures that confirmed "exposed" on any HTML page -----------------
_ORDINARY_HTML = '<html><body><a href="/x?a=1">hi</a><p>a=b</p></body></html>'


def test_env_signature_rejects_an_ordinary_html_page():
    sig = dict(_EXPOSED_SIGNATURES)[".env"]
    # The old signature was "=", so every HTML page confirmed ".env is readable".
    assert not _signature_present(sig, _ORDINARY_HTML)
    assert _signature_present(sig, "APP_KEY=base64:xxx\nDB_PASSWORD=hunter2\n")


def test_htaccess_signature_rejects_an_ordinary_html_page():
    sig = dict(_EXPOSED_SIGNATURES)[".htaccess"]
    # The old signature was "", so any HTTP 200 with a body confirmed it.
    assert not _signature_present(sig, _ORDINARY_HTML)
    assert _signature_present(sig, "RewriteEngine On\nRewriteRule ^a$ /b [L]\n")


def test_signature_present_accepts_plain_substrings_too():
    assert _signature_present("[core]", "[core]\n\trepositoryformatversion = 0")
    assert not _signature_present("[core]", _ORDINARY_HTML)
    assert _signature_present("", "any body")        # empty = presence is enough
    assert not _signature_present("", "")


# ---- 3. wpscan CVEs excluded from enrichment by a key mismatch ---------------
def _wpscan_finding(cve_refs):
    data = {"plugins": {"foo": {"version": {"number": "1.0"}, "vulnerabilities": [
        {"title": "RCE", "references": {"cve": cve_refs}}]}}}
    out = WpscanWrapper().parse(json.dumps(data).encode(), b"", 0, "https://t")
    return next(f for f in out.findings if "RCE" in f.title)


def test_wpscan_emits_cve_id_like_every_other_wrapper():
    # Consumers read metadata["cve_id"] as a normalised string; wpscan only wrote
    # metadata["cve"] as a bare list, so its CVEs were silently skipped.
    assert _wpscan_finding(["2021-24741"]).metadata["cve_id"] == "CVE-2021-24741"
    assert _wpscan_finding(["CVE-2021-24741"]).metadata["cve_id"] == "CVE-2021-24741"


def test_wpscan_without_cve_sets_no_cve_id():
    meta = _wpscan_finding([]).metadata
    assert "cve_id" not in meta
    assert meta["cve"] == []


# ---- 4. recon lines were listed as client findings ---------------------------
class _F:
    def __init__(self, severity, vuln_class="xss", status="likely"):
        self.severity, self.vuln_class, self.status = severity, vuln_class, status


def test_recon_and_info_lines_are_not_client_findings():
    from app.reporting.report import is_reportable
    # "Technology: nginx" / "Live host: ..." used to sit in section 3 next to a
    # critical, because the validator marks unmapped recon lines `likely`.
    assert not is_reportable(_F("info", "recon"))
    assert not is_reportable(_F("medium", "fingerprint"))
    assert not is_reportable(_F("low", "content_discovery"))
    assert not is_reportable(_F("info", "xss"))          # info never reports
    assert is_reportable(_F("high", "xss"))
    assert is_reportable(_F("critical", "sql_injection"))


# ---- 5. findings with an off-list severity vanished from the report ----------
def test_unknown_severity_is_folded_in_not_dropped():
    from app.reporting.report import _by_severity, norm_severity
    assert norm_severity("Critical") == "critical"       # case
    assert norm_severity("warning") == "info"            # unknown -> info
    assert norm_severity(None) == "info"

    buckets = _by_severity([_F("Critical"), _F("warning"), _F("high")])
    # every finding lands in one of the five printed buckets; none is lost
    assert sum(len(v) for v in buckets.values()) == 3
    assert set(buckets) == {"critical", "high", "medium", "low", "info"}


# ---- 6. a real XSS on the second parameter was recorded as a false positive --
def test_reflection_probe_covers_every_parameter():
    from app.validation.validator import marker_variants
    variants = marker_variants("https://t/a?id=1&q=x&z=3", "MARK")
    assert [p for p, _ in variants] == ["id", "q", "z"]
    # each URL carries the marker in exactly its own parameter
    assert "id=MARK&q=x&z=3" in variants[0][1]
    assert "id=1&q=MARK&z=3" in variants[1][1]
    assert marker_variants("https://t/a", "MARK") == []


def test_reflection_probe_is_bounded():
    from app.validation.validator import MAX_REFLECTION_PARAMS, marker_variants
    url = "https://t/a?" + "&".join(f"p{i}=1" for i in range(30))
    assert len(marker_variants(url, "MARK")) == MAX_REFLECTION_PARAMS
