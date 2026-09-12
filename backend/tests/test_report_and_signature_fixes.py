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
