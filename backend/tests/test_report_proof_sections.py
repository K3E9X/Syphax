"""Proven vs unverified in the report.

A finding an oracle confirmed and a finding nothing re-checked used to be
printed identically, in the same list, one after the other. The reader had no
way to tell "we reproduced this against the target" from "a scanner matched a
pattern" - and the methodology section claimed every reported finding carried
a safe proof-of-exploit, which was not true of the scanner lines.
"""
import pytest

from app.reporting.report import (
    _markdown,
    is_proven,
    partition_by_proof,
)


class VF:
    def __init__(self, title="f", status="confirmed", method="tool-confirmed (sqlmap)",
                 severity="high", confidence=0.95, vuln_class="sql_injection",
                 poc="payload", target="https://t.example.com/a", tool="sqlmap",
                 metadata=None):
        self.title, self.status, self.method = title, status, method
        self.severity, self.confidence, self.vuln_class = severity, confidence, vuln_class
        self.poc, self.target, self.tool = poc, target, tool
        self.metadata = metadata or {}


class E:
    id = "eng-1"
    target_url = "https://t.example.com/"
    target_host = "t.example.com"
    scope_hosts = ["t.example.com"]


def render(findings, vsum=None):
    return _markdown(E(), findings, [], ["sqlmap"], [], [], {},
                     vsum or {"confirmed": 1, "likely": 1, "false_positive": 0},
                     "High")


# --------------------------------------------------------------------------
# is_proven
# --------------------------------------------------------------------------

@pytest.mark.parametrize("method", [
    "tool-confirmed (sqlmap)", "safe-poc (reflection)",
    "safe-poc (exposed-resource)", "analysis (payload-probe)", "proof-replay",
])
def test_an_oracle_confirmation_is_proven(method):
    assert is_proven(VF(status="confirmed", method=method))


@pytest.mark.parametrize("method", [
    "scanner-match (nuclei)", "analysis (js-recon)", "inventory (httpx)", "llm",
])
def test_a_pattern_match_is_not_proven(method):
    assert not is_proven(VF(status="confirmed", method=method))


@pytest.mark.parametrize("status", ["likely", "unconfirmed", "false_positive"])
def test_only_a_confirmed_status_can_be_proven(status):
    assert not is_proven(VF(status=status, method="tool-confirmed (sqlmap)"))


def test_partition_splits_the_set():
    proven = VF(title="sqli")
    guess = VF(title="headers", status="likely", method="scanner-match (nuclei)",
               tool="nuclei")
    split = partition_by_proof([proven, guess])
    assert [f.title for f in split["proven"]] == ["sqli"]
    assert [f.title for f in split["unverified"]] == ["headers"]


def test_partition_loses_nothing():
    items = [VF(title=str(i), status="likely", method="scanner-match") for i in range(5)]
    split = partition_by_proof(items)
    assert len(split["proven"]) + len(split["unverified"]) == 5


# --------------------------------------------------------------------------
# the rendered report
# --------------------------------------------------------------------------

def test_both_sections_exist_and_are_numbered_once():
    md = render([VF(), VF(status="likely", method="scanner-match (nuclei)")])
    assert md.count("## 3. Proven Findings") == 1
    assert md.count("## 4. Unverified Findings") == 1
    for heading in ("## 5. Attack Chains", "## 6. Remediation Priority",
                    "## 7. Appendix"):
        assert md.count(heading) == 1


def test_a_proven_finding_lands_in_section_three():
    md = render([VF(title="proven-sqli")])
    proven_section = md.split("## 3. Proven Findings")[1].split("## 4.")[0]
    assert "proven-sqli" in proven_section


def test_an_unverified_finding_lands_in_section_four():
    md = render([VF(title="guessed-thing", status="likely",
                    method="scanner-match (nuclei)", tool="nuclei")])
    unverified = md.split("## 4. Unverified Findings")[1].split("## 5.")[0]
    assert "guessed-thing" in unverified
    proven_section = md.split("## 3. Proven Findings")[1].split("## 4.")[0]
    assert "guessed-thing" not in proven_section


def test_an_unverified_finding_is_not_labelled_proof_of_exploit():
    md = render([VF(title="guess", status="likely", method="scanner-match",
                    poc="matched a template")])
    assert "**Evidence:**" in md
    assert "**Proof of exploit:**" not in md


def test_a_proven_finding_is_labelled_proof_of_exploit():
    md = render([VF(poc="sqlmap payload x OR 1=1")])
    assert "**Proof of exploit:**" in md


def test_empty_sections_say_so():
    md = render([VF()])
    assert "_Every reported finding was proven._" in md
    md2 = render([VF(status="likely", method="scanner-match")])
    assert "_Nothing could be proven with a safe proof-of-exploit._" in md2


def test_the_methodology_no_longer_claims_everything_was_proven():
    md = render([VF(status="likely", method="scanner-match")])
    assert "every reported finding was validated with a safe proof-of-exploit" not in md
    assert "reported separately" in md


def test_the_executive_summary_counts_both_kinds():
    md = render([VF(), VF(), VF(status="likely", method="scanner-match")])
    assert "**2 finding(s) were proven**" in md
    assert "1 were reported by a scanner" in md


def test_corroboration_reasoning_is_printed_when_present():
    md = render([VF(status="likely", method="scanner-match",
                    metadata={"corroboration": {"note": "3 independent tools agree."}})])
    assert "**Corroboration:** 3 independent tools agree." in md


def test_remediation_priority_puts_proof_first_at_equal_severity():
    guess = VF(title="unproven-high", status="likely", method="scanner-match",
               severity="high", confidence=0.9)
    proven = VF(title="proven-high", severity="high", confidence=0.95)
    md = render([guess, proven])
    prio = md.split("## 6. Remediation Priority")[1]
    assert prio.index("proven-high") < prio.index("unproven-high")


def test_no_findings_at_all_still_renders():
    md = render([], vsum={})
    assert "## 3. Proven Findings" in md
    assert "No findings could be validated" in md
