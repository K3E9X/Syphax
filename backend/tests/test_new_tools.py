"""The six tools added for coverage the existing set could not reach.

Each parser is exercised against output captured from the real tool where the
output format was verifiable (arjun 2.2.7, schemathesis 4.27.0), and against
representative documented output otherwise. The parametrised malformed-input
suite in test_wrapper_parsers.py covers all six for crashes automatically.

Why these six, in one line each:
  arjun         adds INJECTION POINTS - every injection test needs a parameter
  schemathesis  the API's own OpenAPI contract as the oracle
  retire.js     the CLIENT libraries, which nothing else in the image rates
  jsluice       a real JS parser instead of a regex pass
  git-dumper    acts on an exposed .git instead of only reporting it
  trufflehog    verifies a secret against its provider: proven, not guessed
"""
import json
from pathlib import Path

import pytest

from app.scans.wrappers import get_wrapper
from app.scans.wrappers.arjun import ArjunWrapper, parse_params, with_params
from app.scans.wrappers.gitdumper import GitDumperWrapper, dump_url, notable_files
from app.scans.wrappers.jsluice import JsluiceWrapper, absolute
from app.scans.wrappers.retirejs import RetireJsWrapper, cve_ids, norm_severity
from app.scans.wrappers.schemathesis import (
    SchemathesisWrapper,
    failures_of,
    meaning_of,
)
from app.scans.wrappers.trufflehog import (
    TruffleHogWrapper,
    redact,
    severity_for,
    source_location,
)

TARGET = "https://target.example.com/"


def test_all_six_are_registered():
    for name in ("arjun", "schemathesis", "retirejs", "jsluice",
                 "gitdumper", "trufflehog"):
        w = get_wrapper(name)
        assert w.name == name
        assert w.binary


# ==========================================================================
# arjun - captured from arjun 2.2.7
# ==========================================================================

ARJUN_OUT = (
    b"\x1b[1;97m[*]\x1b[0m Scanning 0/1: http://t.example/\n"
    b"\x1b[1;97m[*]\x1b[0m Probing the target for stability\n"
    b"\x1b[1;92m[\xe2\x9c\x93]\x1b[0m parameter detected: debug, based on: body length\n"
    b"\x1b[1;92m[\xe2\x9c\x93]\x1b[0m parameter detected: id, based on: body length\n"
    b"\x1b[1;32m[+]\x1b[0m Parameters found: debug, id\n"
)


def test_arjun_parses_its_coloured_console_output():
    """arjun's -oJ opens the file with mode w+ and cannot write to a pipe
    (io.UnsupportedOperation: not seekable), so stdout is what we have."""
    assert parse_params(ARJUN_OUT.decode()) == [("debug", "body length"),
                                                ("id", "body length")]


def test_arjun_findings_carry_the_parameter_as_an_injection_point():
    findings = ArjunWrapper().parse(ARJUN_OUT, b"", 0, TARGET).findings
    # one per parameter, plus the combined endpoint
    assert len(findings) == 3
    assert findings[0].target == "https://target.example.com/?debug=1"
    assert findings[-1].target == "https://target.example.com/?debug=1&id=1"
    assert all(f.severity == "info" for f in findings)
    assert findings[0].metadata["asset_kind"] == "endpoint"


def test_arjun_parameters_are_surface_not_weakness():
    """A discovered parameter is an injection point, not a finding."""
    from app.validation.classes import is_surface
    for f in ArjunWrapper().parse(ARJUN_OUT, b"", 0, TARGET).findings:
        assert is_surface(f.metadata["vuln_class"])


def test_arjun_summary_line_alone_is_enough():
    out = b"[+] Parameters found: token, redirect_to\n"
    assert [p for p, _ in parse_params(out.decode())] == ["token", "redirect_to"]


def test_arjun_reports_nothing_when_it_found_nothing():
    out = b"[*] Scanning 0/1: http://t.example/\n[-] No parameters were discovered.\n"
    assert ArjunWrapper().parse(out, b"", 0, TARGET).findings == []


def test_arjun_never_duplicates_a_parameter():
    out = ARJUN_OUT.decode() + "\n[+] Parameters found: debug, id\n"
    assert len(parse_params(out)) == 2


def test_with_params_preserves_an_existing_query():
    assert with_params("https://t.example/a?x=1", ["y"]) == \
        "https://t.example/a?x=1&y=1"
    assert with_params("not-a-url", ["y"]) == "not-a-url"
    assert with_params("https://t.example/a", []) == "https://t.example/a"


def test_arjun_command_is_rate_limited():
    cmd = ArjunWrapper().build_command(TARGET, [])
    assert "--rate-limit" in cmd
    assert "--stable" in cmd   # calibrate before deciding anything changed


# ==========================================================================
# schemathesis - captured from schemathesis 4.27.0 NDJSON events
# ==========================================================================

ST_FAILURE = {
    "ScenarioFinished": {
        "phase": "fuzzing",
        "status": "failure",
        "recorder": {
            "label": "GET /boom",
            "cases": {"F5LDhb": {"value": {"method": "GET", "path": "/boom"}}},
            "interactions": {"F5LDhb": {"request": {
                "method": "GET", "uri": "http://t.example/boom?n=1"}}},
            "checks": {"F5LDhb": [
                {"name": "not_a_server_error", "status": "failure",
                 "failure_info": {"failure": {
                     "type": "ServerError", "operation": "GET /boom",
                     "title": "Server error", "message": "", "severity": "critical"}}},
                {"name": "status_code_conformance", "status": "failure",
                 "failure_info": {"failure": {
                     "type": "UndefinedStatusCode", "operation": "GET /boom",
                     "title": "Undocumented HTTP status code",
                     "message": "Received: 500\nDocumented: 200, 422",
                     "severity": "medium"}}},
                {"name": "content_type_conformance", "status": "success"},
            ]},
        },
    }
}
ST_SUCCESS = {"ScenarioFinished": {"status": "success", "recorder": {
    "label": "GET /ok", "checks": {"x": [{"name": "not_a_server_error",
                                          "status": "success"}]}}}}


def ndjson(*events):
    return ("Schemathesis v4.27.0\n"        # the banner shares stdout
            + "\n".join(json.dumps(e) for e in events) + "\n").encode()


def test_schemathesis_extracts_only_failed_checks():
    fails = failures_of(ST_FAILURE)
    assert [f["check"] for f in fails] == ["not_a_server_error",
                                           "status_code_conformance"]
    assert failures_of(ST_SUCCESS) == []


def test_schemathesis_ignores_every_other_event_type():
    for event in ({"EngineStarted": {}}, {"PhaseFinished": {"x": 1}},
                  {"NonFatalError": {"value": {"type": "ConnectionError"}}}):
        assert failures_of(event) == []


def test_schemathesis_findings_from_real_events():
    findings = SchemathesisWrapper().parse(
        ndjson(ST_FAILURE, ST_SUCCESS), b"", 1, "http://t.example/openapi.json"
    ).findings
    assert len(findings) == 2
    assert findings[0].severity == "medium"
    assert findings[0].metadata["vuln_class"] == "unhandled_error"
    assert findings[0].target == "http://t.example/boom?n=1"
    assert findings[1].severity == "low"
    assert findings[1].metadata["vuln_class"] == "api_contract_violation"
    assert "Documented: 200, 422" in findings[1].evidence


def test_schemathesis_reports_one_finding_per_check_and_operation():
    """Property-based testing generates hundreds of cases per operation; the
    report needs the defect, not every case that hit it."""
    findings = SchemathesisWrapper().parse(
        ndjson(ST_FAILURE, ST_FAILURE, ST_FAILURE), b"", 1, TARGET).findings
    assert len(findings) == 2


def test_ignored_auth_is_the_one_high_severity_check():
    """An endpoint that ignores the auth it declares is an access-control
    break; a schema mismatch is not."""
    assert meaning_of("ignored_auth") == ("high", "broken_authentication")
    for check in ("response_schema_conformance", "status_code_conformance",
                  "content_type_conformance", "negative_data_rejection"):
        severity, _ = meaning_of(check)
        assert severity == "low"


def test_an_unknown_check_degrades_conservatively():
    assert meaning_of("some_future_check") == ("low", "api_contract_violation")
    assert meaning_of("") == ("low", "api_contract_violation")


def test_schemathesis_does_not_run_the_phase_that_writes():
    """The coverage phase sends PUT/DELETE/TRACE to every operation, which is
    a write against a live target."""
    cmd = SchemathesisWrapper().build_command("http://t.example/openapi.json", [])
    assert "--phases" in cmd
    phases = cmd[cmd.index("--phases") + 1]
    assert "coverage" not in phases
    assert "fuzzing" in phases
    assert "--output-sanitize" in cmd     # keep credentials out of the report
    assert "--rate-limit" in cmd


def test_schemathesis_only_applies_to_a_schema_url():
    """Pointing it at the home page produces a load error every engagement."""
    from app.methodology.catalog import CATALOG_BY_ID, applies
    item = CATALOG_BY_ID["VULN-API-CONTRACT"]
    schema = {"is_host": False, "url": "https://t.example/openapi.json", "tech": []}
    home = {"is_host": False, "url": "https://t.example/", "tech": []}
    assert applies(item, schema)
    assert not applies(item, home)


# ==========================================================================
# retire.js
# ==========================================================================

RETIRE_OUT = json.dumps({
    "version": "5.7.0",
    "data": [{
        "file": "/data/artifacts/t.example/js/jquery-1.7.2.min-abc1234567.js",
        "results": [{
            "component": "jquery", "version": "1.7.2",
            "vulnerabilities": [
                {"severity": "medium", "below": "1.9.0b1",
                 "identifiers": {"CVE": ["CVE-2012-6708"],
                                 "summary": "Selector interpreted as HTML"}},
                {"severity": "high", "below": "3.5.0",
                 "identifiers": {"issue": "XSS via self-closing tags"}},
            ],
        }],
    }],
    "messages": [], "errors": [],
}).encode()


def test_retirejs_findings_carry_the_library_version_and_cve():
    findings = RetireJsWrapper().parse(RETIRE_OUT, b"", 0, TARGET).findings
    assert len(findings) == 2
    assert findings[0].severity == "medium"
    assert findings[0].metadata["component"] == "jquery"
    assert findings[0].metadata["version"] == "1.7.2"
    assert findings[0].metadata["cve_id"] == "CVE-2012-6708"
    assert findings[1].severity == "high"
    assert findings[1].metadata["cve_id"] == ""     # this one has no CVE


def test_retirejs_class_is_a_real_weakness_not_surface():
    from app.validation.classes import is_surface
    for f in RetireJsWrapper().parse(RETIRE_OUT, b"", 0, TARGET).findings:
        assert f.metadata["vuln_class"] == "vulnerable_component"
        assert not is_surface(f.metadata["vuln_class"])


def test_retirejs_empty_scan_reports_nothing():
    empty = json.dumps({"version": "5.7.0", "data": [], "errors": []}).encode()
    assert RetireJsWrapper().parse(empty, b"", 0, TARGET).findings == []


def test_retirejs_deduplicates_the_same_library_across_bundles():
    doubled = json.dumps({"data": [
        {"file": "a.js", "results": [{"component": "jquery", "version": "1.7.2",
          "vulnerabilities": [{"severity": "medium",
                               "identifiers": {"CVE": ["CVE-2012-6708"]}}]}]},
        {"file": "b.js", "results": [{"component": "jquery", "version": "1.7.2",
          "vulnerabilities": [{"severity": "medium",
                               "identifiers": {"CVE": ["CVE-2012-6708"]}}]}]},
    ]}).encode()
    assert len(RetireJsWrapper().parse(doubled, b"", 0, TARGET).findings) == 1


def test_retirejs_unknown_severity_is_not_dropped():
    assert norm_severity("moderate") == "medium"
    assert norm_severity(None) == "medium"
    assert norm_severity("HIGH") == "high"


def test_retirejs_reads_cve_lists_and_single_values():
    assert cve_ids({"identifiers": {"CVE": ["CVE-1", "CVE-2"]}}) == ["CVE-1", "CVE-2"]
    assert cve_ids({"identifiers": {"CVE": "CVE-3"}}) == ["CVE-3"]
    assert cve_ids({"identifiers": {}}) == []
    assert cve_ids({}) == []


def test_retirejs_does_not_fail_the_job_on_a_finding():
    cmd = RetireJsWrapper().build_command(TARGET, [])
    assert "--exitwith" in cmd and cmd[cmd.index("--exitwith") + 1] == "0"


# ==========================================================================
# jsluice
# ==========================================================================

JSLUICE_URLS = (
    b'{"url":"/api/v2/users","queryParams":["page","limit"],"bodyParams":[],'
    b'"method":"GET","type":"fetch","filename":"app-abc.js"}\n'
    b'{"url":"https://target.example.com/api/orders","queryParams":[],'
    b'"bodyParams":["item_id","qty"],"method":"POST","type":"fetch"}\n'
)
JSLUICE_SECRETS = (
    b'{"kind":"gcp","data":{"private_key":"-----BEGIN","client_email":"x@y"},'
    b'"filename":"app-abc.js","severity":"high"}\n'
)


def test_jsluice_endpoints_become_absolute_endpoint_assets():
    findings = JsluiceWrapper().parse(JSLUICE_URLS, b"", 0, TARGET).findings
    assert len(findings) == 2
    assert findings[0].target == "https://target.example.com/api/v2/users"
    assert findings[0].metadata["params"] == ["page", "limit"]
    assert findings[0].metadata["asset_kind"] == "endpoint"
    assert findings[1].metadata["method"] == "POST"
    assert findings[1].metadata["params"] == ["item_id", "qty"]


def test_jsluice_endpoint_params_are_what_the_prober_needs():
    """The endpoint has no query string, so before this the adaptive prober
    had nothing to inject into."""
    findings = JsluiceWrapper().parse(JSLUICE_URLS, b"", 0, TARGET).findings
    assert "?" not in findings[1].target
    assert findings[1].metadata["params"]


def test_jsluice_secrets_never_echo_the_credential():
    findings = JsluiceWrapper().parse(JSLUICE_SECRETS, b"", 0, TARGET).findings
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "-----BEGIN" not in findings[0].evidence
    assert "client_email" in findings[0].evidence   # the shape, not the value


def test_jsluice_absolute_resolution():
    assert absolute("/a", "https://t.example/deep/page") == "https://t.example/a"
    assert absolute("https://other/a", TARGET) == "https://other/a"
    assert absolute("", TARGET) == TARGET
    assert absolute("/a", "not-a-url") == "/a"


def test_jsluice_subcommand_comes_from_the_options():
    w = JsluiceWrapper()
    assert w.build_command(TARGET, [])[1] == "urls"
    assert w.build_command(TARGET, ["secrets"])[1] == "secrets"


# ==========================================================================
# git-dumper
# ==========================================================================

def test_dump_url_normalises_whatever_it_is_given():
    assert dump_url("https://t.example") == "https://t.example/.git/"
    assert dump_url("https://t.example/") == "https://t.example/.git/"
    assert dump_url("https://t.example/.git/config") == "https://t.example/.git/"
    assert dump_url("https://t.example/app/.git/") == "https://t.example/app/.git/"
    assert dump_url("") == ""


def test_notable_files_flags_the_ones_that_matter():
    paths = [Path("/d/README.md"), Path("/d/.env"), Path("/d/app/config.php"),
             Path("/d/src/index.js"), Path("/d/id_rsa")]
    found = notable_files(paths)
    assert any(".env" in f for f in found)
    assert any("config.php" in f for f in found)
    assert any("id_rsa" in f for f in found)
    assert not any("index.js" in f for f in found)


def test_gitdumper_reports_nothing_when_nothing_was_recovered(tmp_path, monkeypatch):
    """A .git that answered 200 for every object but yielded no tree is not a
    finding - saying so is the point."""
    import app.scans.artifacts as artifacts
    monkeypatch.setattr(artifacts.settings, "data_dir", tmp_path)
    assert GitDumperWrapper().parse(b"", b"", 0, TARGET).findings == []


def test_gitdumper_reports_the_recovered_tree(tmp_path, monkeypatch):
    import app.scans.artifacts as artifacts
    monkeypatch.setattr(artifacts.settings, "data_dir", tmp_path)
    out = artifacts.ensure(artifacts.git_dir(TARGET))
    (out / "index.php").write_text("<?php")
    (out / ".env").write_text("DB_PASSWORD=secret")
    findings = GitDumperWrapper().parse(b"", b"", 0, TARGET).findings
    assert len(findings) == 1
    assert findings[0].severity == "critical"    # a config file came out
    assert findings[0].metadata["files"] == 2
    assert findings[0].metadata["vuln_class"] == "source_code_disclosure"


def test_gitdumper_without_a_config_file_is_high_not_critical(tmp_path, monkeypatch):
    import app.scans.artifacts as artifacts
    monkeypatch.setattr(artifacts.settings, "data_dir", tmp_path)
    out = artifacts.ensure(artifacts.git_dir(TARGET))
    (out / "index.php").write_text("<?php")
    assert GitDumperWrapper().parse(b"", b"", 0, TARGET).findings[0].severity == "high"


# ==========================================================================
# trufflehog
# ==========================================================================

TH_VERIFIED = json.dumps({
    "DetectorName": "AWS", "DetectorType": 2, "Verified": True,
    "Raw": "AKIAIOSFODNN7EXAMPLE",
    "SourceMetadata": {"Data": {"Filesystem": {
        "file": "/data/artifacts/t.example/git/config/prod.env", "line": 12}}},
}).encode()
TH_UNVERIFIED = json.dumps({
    "DetectorName": "Slack", "Verified": False, "Raw": "xoxb-1234567890-abcdef",
    "SourceMetadata": {"Data": {"Filesystem": {"file": "/d/js/app.js", "line": 3}}},
}).encode()


def test_a_verified_secret_is_confirmed_not_likely():
    """The reason trufflehog is here: js_recon reports the same shapes as
    "likely" because a regex cannot tell a rotated key from a live one."""
    f = TruffleHogWrapper().parse(TH_VERIFIED, b"", 0, TARGET).findings[0]
    assert f.severity == "critical"
    assert f.metadata["verified"] is True
    assert f.metadata["status"] == "confirmed"
    assert f.metadata["confidence"] > 0.95


def test_an_unverified_secret_is_no_stronger_than_the_regex_pass():
    f = TruffleHogWrapper().parse(TH_UNVERIFIED, b"", 0, TARGET).findings[0]
    assert f.severity == "low"
    assert f.metadata["status"] == "likely"


def test_the_validator_treats_a_verified_secret_as_proven():
    import asyncio

    from app.validation.validator import FindingValidator
    f = TruffleHogWrapper().parse(TH_VERIFIED, b"", 0, TARGET).findings[0]
    res = asyncio.new_event_loop().run_until_complete(
        FindingValidator(safe_poc=None).validate(f, "trufflehog", "secret_exposure"))
    assert res.status.value == "confirmed"
    assert res.method == "provider-verified (trufflehog)"

    from app.validation.corroboration import is_oracle
    assert is_oracle(res.method)


def test_the_credential_is_never_written_into_the_finding():
    f = TruffleHogWrapper().parse(TH_VERIFIED, b"", 0, TARGET).findings[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence
    assert "AKIA" in f.evidence            # enough to recognise it
    assert "prod.env" in f.evidence        # and to go find it
    assert ":12" in f.evidence


def test_redact_keeps_the_shape_and_loses_the_secret():
    assert redact("AKIAIOSFODNN7EXAMPLE") == "AKIA...MPLE (20 chars)"
    assert redact("short") == "*****"
    assert redact("") == ""


def test_severity_tracks_blast_radius():
    assert severity_for("AWS", True) == "critical"
    assert severity_for("postgres", True) == "critical"
    assert severity_for("SomeSaaS", True) == "high"
    assert severity_for("AWS", False) == "low"


def test_source_location_reads_every_source_kind():
    assert "app.js:3" in source_location(
        {"Data": {"Filesystem": {"file": "app.js", "line": 3}}})
    assert "commit abcdef1234" in source_location(
        {"Data": {"Git": {"file": "a.py", "line": 1, "commit": "abcdef1234567890"}}})
    assert source_location({}) == ""
    assert source_location({"Data": "not a dict"}) == ""


def test_trufflehog_runs_in_verified_mode(tmp_path, monkeypatch):
    import app.scans.artifacts as artifacts
    monkeypatch.setattr(artifacts.settings, "data_dir", tmp_path)
    artifacts.write_artifact(artifacts.git_dir(TARGET), "prod.env", "K=v")
    cmd = TruffleHogWrapper().build_command(TARGET, [])
    assert "--results=verified" in cmd
    assert str(artifacts.git_dir(TARGET)) in cmd


def test_trufflehog_scans_only_directories_that_have_files(tmp_path, monkeypatch):
    import app.scans.artifacts as artifacts
    monkeypatch.setattr(artifacts.settings, "data_dir", tmp_path)
    assert TruffleHogWrapper().scan_paths(TARGET) == []
    artifacts.write_artifact(artifacts.js_dir(TARGET), "app.js", "var a=1")
    assert TruffleHogWrapper().scan_paths(TARGET) == [str(artifacts.js_dir(TARGET))]


def test_trufflehog_deduplicates_the_same_secret():
    findings = TruffleHogWrapper().parse(
        TH_VERIFIED + b"\n" + TH_VERIFIED, b"", 0, TARGET).findings
    assert len(findings) == 1
