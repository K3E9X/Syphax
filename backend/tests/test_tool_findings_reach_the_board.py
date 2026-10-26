"""Real tool output has to reach the blackboard.

The operator ran several engagements and found nothing, and this was a large
part of why. The central producer read `metadata["vuln_class"]`,
`metadata["status"]` and `metadata["confidence"]` - and a RAW tool finding has
none of the three. Those are assigned later, by validation. So:

    sqlmap confirms an injection  ->  class None, confidence 0.0  ->  no lead
    dalfox confirms a reflected XSS ->  class None                ->  no lead
    nuclei matches a CVE template ->  confidence 0.0              ->  no lead

The board therefore got nothing at all from the tool half of a run, which is
most of it. The strategist had no advice, the planner fell back to the plain
methodology order, and the whole agentic layer was inert on exactly the runs
where the scanners HAD found something.

These tests parse the tools' real output formats, so a parser change or a
metadata change breaks them rather than silently emptying the board again.
"""
from __future__ import annotations

import json

import pytest

from app.orchestrator.blackboard import (CVE, INJECTABLE, lead_confidence,
                                         lead_for_finding)
from app.scans.wrappers import get_wrapper

SQLMAP_OUT = b"""sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3119=3119
---
"""

DALFOX_OUT = (b'{"type":"V","inject_type":"inHTML-URL","poc_type":"plain",'
              b'"method":"GET","data":"https://t/s?q=%3Csvg%3E","param":"q",'
              b'"payload":"<svg onload=alert(1)>","evidence":"6 line reflected",'
              b'"cwe":"CWE-79","severity":"high","message_str":"reflected"}\n')


def _nuclei(template, severity, tags, extra=None):
    obj = {"template-id": template,
           "info": {"name": template, "severity": severity, "tags": tags},
           "type": "http", "host": "t.example",
           "matched-at": "https://t.example/api", "matcher-status": True}
    obj.update(extra or {})
    return json.dumps(obj).encode() + b"\n"


def _leads(tool, out, target):
    res = get_wrapper(tool).parse(out, b"", 0, target)
    return [(f, lead_for_finding(f, tool)) for f in res.findings]


# ---- the three that produced nothing ----------------------------------

def test_a_confirmed_sqlmap_injection_reaches_the_board():
    got = _leads("sqlmap", SQLMAP_OUT, "https://t/p?id=1")
    assert got, "sqlmap's own output no longer parses into a finding"
    finding, lead = got[0]
    assert lead is not None, (
        "sqlmap confirmed an injection and the board got nothing - the "
        "strategist then has no reason to send sqlmap anywhere")
    kind, value, data = lead
    assert kind == INJECTABLE
    assert value == "https://t/p?id=1"
    assert data["vuln_class"] == "sql_injection"
    assert data["tool"] == "sqlmap"


def test_a_confirmed_dalfox_xss_reaches_the_board():
    got = _leads("dalfox", DALFOX_OUT, "https://t/s?q=1")
    assert got
    _finding, lead = got[0]
    assert lead is not None
    assert lead[0] == INJECTABLE
    assert lead[2]["vuln_class"] == "xss"


def test_a_nuclei_cve_becomes_one_cve_lead():
    """Keyed on the CVE, not the URL: one CVE on forty endpoints is one fact."""
    got = _leads("nuclei", _nuclei("CVE-2021-44228", "critical", ["cve", "rce"],
                                   {"cve-id": ["CVE-2021-44228"]}),
                 "https://t.example/api")
    assert got
    _finding, lead = got[0]
    assert lead is not None
    assert lead[0] == CVE
    assert "CVE-2021-44228" in lead[1]


# ---- the class comes from the tool, as validation derives it ----------

@pytest.mark.parametrize("tool,expected_class", [
    ("sqlmap", "sql_injection"),
    ("dalfox", "xss"),
    ("commix", "command_injection"),
    ("nosqli", "nosql_injection"),
])
def test_the_class_is_derived_from_the_tool_when_the_finding_omits_it(
        tool, expected_class):
    """Raw tool findings carry no vuln_class; the tool name is the class, and
    the producer must derive it exactly as classes.vuln_class_of does."""
    from app.validation.classes import TOOL_VULN_CLASS
    assert TOOL_VULN_CLASS[tool] == expected_class


# ---- confidence, when the finding has none ----------------------------

@pytest.mark.parametrize("tool", ["sqlmap", "dalfox", "commix", "nosqli"])
def test_a_confirming_tool_does_not_need_a_confidence_field(tool):
    """None of them emits a maybe: sqlmap prints an injection point only once
    it has one, dalfox reports type V for verified."""
    class _F:
        metadata: dict = {}
        severity = "high"
    assert lead_confidence(_F(), tool) >= 0.6


@pytest.mark.parametrize("severity,chased", [
    ("critical", True), ("high", True), ("medium", True),
    ("low", False), ("info", False),
])
def test_a_nuclei_hit_carries_its_severity_as_its_weight(severity, chased):
    """A matched template is deterministic, so severity is the weight. info
    and low stay below the floor: that is inventory, and letting it steer the
    exploitation budget is how a run chases noise."""
    class _F:
        metadata = {"vuln_class": "exposed_resource"}

    _F.severity = severity
    conf = lead_confidence(_F(), "nuclei")
    assert (conf >= 0.6) is chased


def test_an_explicit_confidence_still_wins():
    class _F:
        metadata = {"confidence": 0.95}
        severity = "info"
    assert lead_confidence(_F(), "nuclei") == 0.95


@pytest.mark.parametrize("bad", ["x", None, [], {}])
def test_a_broken_confidence_falls_back_rather_than_crashing(bad):
    class _F:
        severity = "high"
    _F.metadata = {"confidence": bad}
    assert 0.0 <= lead_confidence(_F(), "sqlmap") <= 1.0


# ---- what must still be ignored ---------------------------------------

def test_a_nuclei_tech_detect_is_not_a_lead():
    got = _leads("nuclei", _nuclei("tech-detect", "info", ["tech"]),
                 "https://t.example/")
    for _finding, lead in got:
        assert lead is None, "inventory must not steer the exploitation budget"


def test_an_unknown_tool_with_no_class_posts_nothing():
    """classes.vuln_class_of falls back to 'unknown', which chains nowhere."""
    class _F:
        metadata: dict = {}
        severity = "high"
        target = "https://t/x"
        title = "something"
    assert lead_for_finding(_F(), "some-new-tool") is None


# ---- the diagnosis can see all of this --------------------------------

def test_the_diagnostic_reports_the_agentic_chain():
    """A run that confirmed an injection, posted nothing and gave the
    strategist no advice looked identical to a run that found nothing. It is
    one command now."""
    import inspect

    from app import diagnose_run
    src = inspect.getsource(diagnose_run._agentic_section)
    for subject in ("flows", "leads", "primary_auth", "Strategist"):
        assert subject in src, f"the diagnosis cannot see {subject}"
