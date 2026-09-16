"""Why nothing was confirmed.

"0 confirmed" is the most confusing line this tool prints: the operator reads
it as "the scanner is broken" when it usually means an oracle existed but a
switch they never set kept it from running, or the input it needs was never
captured.

Both facts were already known and both were thrown away. run_cve_checks
returned {"skipped": 1, "reason": "allow_active_exploit is off"} into a dict
nobody rendered; the file-reading tools scanned an empty directory and found
nothing, which is indistinguishable from there being nothing to find.
"""
import pytest

from app.validation.limits import (
    ACTIVE_ONLY_CLASSES,
    CAPTURE_FED_CLASSES,
    Limit,
    limits_for,
    summary_line,
    unverified_classes_of,
)


def keys(limits):
    return {l.key for l in limits}


# --------------------------------------------------------------------------
# only report a limit that actually bit
# --------------------------------------------------------------------------

def test_a_fully_enabled_run_reports_nothing():
    assert limits_for(allow_active_exploit=True,
                      unverified_classes=["cve"], captured_js_files=3) == []


def test_a_gate_that_blocked_nothing_is_not_mentioned():
    """Noise here teaches the operator to skip the whole panel: with no
    finding that needed an active check, the gate cost nothing."""
    limits = limits_for(allow_active_exploit=False,
                        unverified_classes=["fingerprint", "recon"],
                        captured_js_files=1)
    assert limits == []


def test_nothing_unverified_means_nothing_to_explain():
    assert limits_for(allow_active_exploit=False, unverified_classes=[],
                      captured_js_files=0) == []


# --------------------------------------------------------------------------
# the gate the operator actually hit
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cls", ["cve", "sql_injection", "xss", "ssrf", "rce"])
def test_active_exploit_off_is_named_for_classes_it_blocks(cls):
    limits = limits_for(allow_active_exploit=False, unverified_classes=[cls],
                        captured_js_files=1)
    assert "active_exploit_off" in keys(limits)


def test_the_message_names_the_setting_and_what_to_do():
    limit = limits_for(allow_active_exploit=False, unverified_classes=["cve"],
                       captured_js_files=1)[0]
    assert "allow_active_exploit" in limit.sentence
    assert "Turn it on" in limit.sentence


def test_an_interrupted_run_says_so_rather_than_blaming_a_setting():
    limits = limits_for(allow_active_exploit=True, unverified_classes=["cve"],
                        captured_js_files=1, stop_reason="exploit_denied")
    assert "run_ended_early" in keys(limits)
    assert "exploit_denied" in [l for l in limits if l.key == "run_ended_early"][0].sentence


@pytest.mark.parametrize("reason", ["stopped", "cancelled", "exploit_denied"])
def test_every_early_end_is_covered(reason):
    limits = limits_for(allow_active_exploit=True, unverified_classes=["cve"],
                        captured_js_files=1, stop_reason=reason)
    assert "run_ended_early" in keys(limits)


def test_a_normal_end_is_not_reported_as_an_interruption():
    limits = limits_for(allow_active_exploit=True, unverified_classes=["cve"],
                        captured_js_files=1, stop_reason="coverage_saturated")
    assert "run_ended_early" not in keys(limits)


# --------------------------------------------------------------------------
# the file-reading tools with nothing to read
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cls", sorted(CAPTURE_FED_CLASSES))
def test_no_captured_javascript_is_named(cls):
    """retire.js, jsluice and trufflehog read files. With none captured they
    report nothing, which looks exactly like finding nothing."""
    limits = limits_for(allow_active_exploit=True, unverified_classes=[cls],
                        captured_js_files=0)
    assert "no_captured_javascript" in keys(limits)
    assert "proxy" in [l for l in limits if l.key == "no_captured_javascript"][0].sentence


def test_captured_javascript_clears_that_limit():
    limits = limits_for(allow_active_exploit=True,
                        unverified_classes=["vulnerable_component"],
                        captured_js_files=12)
    assert "no_captured_javascript" not in keys(limits)


# --------------------------------------------------------------------------
# missing tools
# --------------------------------------------------------------------------

def test_an_absent_tool_is_named():
    limits = limits_for(allow_active_exploit=True, unverified_classes=[],
                        captured_js_files=1, tools_unavailable=["naabu"])
    assert "tool_missing:naabu" in keys(limits)


def test_absent_tools_are_listed_once_each_and_sorted():
    limits = limits_for(allow_active_exploit=True, unverified_classes=[],
                        captured_js_files=1,
                        tools_unavailable=["naabu", "naabu", "jsluice", ""])
    missing = [l.key for l in limits if l.key.startswith("tool_missing")]
    assert missing == ["tool_missing:jsluice", "tool_missing:naabu"]


# --------------------------------------------------------------------------
# shaping
# --------------------------------------------------------------------------

def test_unverified_classes_reads_only_undecided_findings():
    class F:
        def __init__(self, status, cls):
            self.status, self.vuln_class = status, cls

    got = unverified_classes_of([
        F("likely", "cve"), F("unconfirmed", "xss"),
        F("confirmed", "sql_injection"), F("false_positive", "ssrf"),
    ])
    assert sorted(got) == ["cve", "xss"]


def test_class_matching_is_case_insensitive():
    assert limits_for(allow_active_exploit=False, unverified_classes=["CVE"],
                      captured_js_files=1)


def test_summary_line_is_empty_when_nothing_limited_the_run():
    assert summary_line([]) == ""


def test_summary_line_carries_every_reason():
    limits = limits_for(allow_active_exploit=False, unverified_classes=["cve"],
                        captured_js_files=0, tools_unavailable=["naabu"])
    line = summary_line(limits)
    assert "allow_active_exploit" in line and "naabu" in line


def test_a_limit_is_json_ready_for_the_report_meta():
    limit = Limit("k", "what", "why", "fix")
    assert limit.to_public() == {"key": "k", "what": "what", "why": "why",
                                 "fix": "fix", "sentence": "what why fix"}


def test_the_class_sets_do_not_overlap():
    assert not (ACTIVE_ONLY_CLASSES & CAPTURE_FED_CLASSES)


# --------------------------------------------------------------------------
# the report says the same thing as the console
# --------------------------------------------------------------------------

def test_the_report_prints_the_limits_next_to_the_unverified_findings():
    from app.reporting.report import _markdown

    class E:
        id, target_url, target_host = "e1", "https://t.example/", "t.example"
        scope_hosts = ["t.example"]

    class VF:
        severity, status, method = "high", "likely", "scanner-match (nuclei)"
        title, target, vuln_class = "possible SQLi", "https://t.example/a", "sql_injection"
        confidence, poc, evidence, tool = 0.6, "", "", "nuclei"
        metadata = {}

    limits = limits_for(allow_active_exploit=False,
                        unverified_classes=["sql_injection"], captured_js_files=1)
    md = _markdown(E(), [VF()], [], ["nuclei"], [], [], {},
                   {"confirmed": 0, "likely": 1}, "High", limits)
    assert "verified less than it could have" in md
    assert "allow_active_exploit" in md


def test_the_report_omits_the_section_when_nothing_limited_it():
    from app.reporting.report import _markdown

    class E:
        id, target_url, target_host = "e1", "https://t.example/", "t.example"
        scope_hosts = ["t.example"]

    class VF:
        severity, status, method = "high", "likely", "scanner-match (nuclei)"
        title, target, vuln_class = "x", "https://t.example/a", "sql_injection"
        confidence, poc, evidence, tool = 0.6, "", "", "nuclei"
        metadata = {}

    md = _markdown(E(), [VF()], [], ["nuclei"], [], [], {},
                   {"confirmed": 0, "likely": 1}, "High", [])
    assert "verified less than it could have" not in md
