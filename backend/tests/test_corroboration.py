"""Cross-tool corroboration.

Findings used to be judged one at a time. The data to do better was already
there - a scan runs a dozen tools and several touch the same URL - but nothing
compared their verdicts. So two independent tools agreeing scored the same as
one tool guessing, and a pattern match whose oracle-based sibling was actively
DISPROVEN at the same target still shipped as "likely".
"""
import pytest

from app.validation.corroboration import (
    AGREEMENT_BONUS,
    CONTRADICTED_CONFIDENCE,
    LONE_SOURCE_PENALTY,
    MAX_UNPROVEN_CONFIDENCE,
    MIN_PENALISED_CONFIDENCE,
    Signal,
    apply,
    corroborate,
    group_key,
    is_oracle,
    normalise_target,
    signal_of,
)
from app.validation.models import ValidationStatus

URL = "https://target.example.com/search.php"


def sig(tool, status="likely", conf=0.6, method="scanner-match", target=URL,
        cls="xss"):
    return Signal(tool=tool, vuln_class=cls, target=target, status=status,
                  confidence=conf, method=f"{method} ({tool})")


# --------------------------------------------------------------------------
# grouping
# --------------------------------------------------------------------------

@pytest.mark.parametrize("a,b", [
    ("https://h.example/a.php?id=1", "https://h.example/a.php"),
    ("https://H.EXAMPLE/a.php", "https://h.example/a.php"),
    ("https://h.example:443/a.php", "https://h.example/a.php"),
    ("http://h.example:80/a.php", "http://h.example/a.php"),
    ("https://h.example/a/", "https://h.example/a"),
    ("https://h.example/a.php#frag", "https://h.example/a.php"),
])
def test_the_same_resource_groups_together(a, b):
    """sqlmap keeps the query, nuclei drops it, nikto keeps the port."""
    assert normalise_target(a) == normalise_target(b)


@pytest.mark.parametrize("a,b", [
    ("https://h.example/a.php", "https://h.example/b.php"),
    ("https://h.example/a.php", "https://other.example/a.php"),
    ("https://h.example:8443/a", "https://h.example/a"),
    ("http://h.example/a", "https://h.example/a"),
])
def test_different_resources_do_not_group(a, b):
    assert normalise_target(a) != normalise_target(b)


def test_normalise_tolerates_junk():
    assert normalise_target("") == ""
    assert normalise_target(None) == ""
    assert normalise_target("target.example.com/") == "target.example.com"


def test_group_key_separates_classes_at_one_url():
    assert group_key(sig("a", cls="xss")) != group_key(sig("a", cls="sql_injection"))


# --------------------------------------------------------------------------
# oracle detection
# --------------------------------------------------------------------------

@pytest.mark.parametrize("method", [
    "tool-confirmed (sqlmap)", "safe-poc (reflection)",
    "safe-poc (exposed-resource)", "proof-replay", "baseline (catch-all)",
    "analysis (payload-probe)", "SAFE-POC (reflection)",
])
def test_oracle_methods_are_recognised(method):
    assert is_oracle(method)


@pytest.mark.parametrize("method", [
    "scanner-match (nuclei)", "inventory (httpx)", "analysis (js-recon)",
    "llm", "", None,
])
def test_pattern_methods_are_not_oracles(method):
    assert not is_oracle(method)


# --------------------------------------------------------------------------
# agreement
# --------------------------------------------------------------------------

def test_two_independent_tools_raise_confidence():
    adj = corroborate([sig("nuclei"), sig("nikto")])
    assert len(adj) == 2
    for a in adj.values():
        assert a.confidence == pytest.approx(0.6 + AGREEMENT_BONUS)
        assert a.independent == 2
        assert "independent tools" in a.note


def test_more_tools_raise_it_further():
    three = corroborate([sig("nuclei"), sig("nikto"), sig("dalfox")])
    assert three[0].confidence == pytest.approx(0.6 + 2 * AGREEMENT_BONUS)


def test_one_noisy_tool_firing_five_times_is_still_one_voice():
    """Five nuclei templates on one URL is not five opinions."""
    adj = corroborate([sig("nuclei", conf=0.6) for _ in range(5)])
    for a in adj.values():
        assert a.independent == 1
        assert a.confidence < 0.6


def test_agreement_never_reaches_the_confirmed_band():
    many = [sig(f"tool{i}", conf=0.7) for i in range(8)]
    adj = corroborate(many)
    for a in adj.values():
        assert a.confidence <= MAX_UNPROVEN_CONFIDENCE
        assert a.status == ValidationStatus.LIKELY.value


def test_tools_at_different_urls_do_not_corroborate():
    adj = corroborate([sig("nuclei", target="https://h.example/a"),
                       sig("nikto", target="https://h.example/b")])
    for a in adj.values():
        assert a.independent == 1


# --------------------------------------------------------------------------
# contradiction
# --------------------------------------------------------------------------

def test_an_oracle_disproof_demotes_the_pattern_match():
    """The reason this module exists: nuclei says XSS, the safe-PoC reflection
    check says the marker never came back. The oracle wins."""
    adj = corroborate([
        sig("nuclei", conf=0.65),
        sig("dalfox", status="false_positive", conf=0.0, method="safe-poc"),
    ])
    a = adj[0]
    assert a.status == ValidationStatus.UNCONFIRMED.value
    assert a.confidence <= CONTRADICTED_CONFIDENCE
    assert a.demoted is True
    assert "could not reproduce" in a.note


def test_a_non_oracle_false_positive_does_not_demote_anything():
    """A scanner that merely failed to match is not evidence of absence."""
    adj = corroborate([
        sig("nuclei", conf=0.65),
        sig("nikto", status="false_positive", conf=0.0, method="scanner-match"),
    ])
    assert adj[0].demoted is False


def test_an_oracle_confirmation_is_not_demoted_by_another_oracles_disproof():
    """Proof outranks a failed re-check: we keep the confirmation."""
    adj = corroborate([
        sig("sqlmap", status="confirmed", conf=0.95, method="tool-confirmed",
            cls="sql_injection"),
        sig("nuclei", status="false_positive", conf=0.0, method="safe-poc",
            cls="sql_injection"),
    ])
    assert adj.get(0) is None or adj[0].status == ValidationStatus.CONFIRMED.value


def test_a_disproof_elsewhere_leaves_this_target_alone():
    adj = corroborate([
        sig("nuclei", conf=0.65, target="https://h.example/a"),
        sig("dalfox", status="false_positive", method="safe-poc",
            target="https://h.example/b"),
    ])
    assert adj[0].demoted is False


# --------------------------------------------------------------------------
# proven sibling
# --------------------------------------------------------------------------

def test_a_guess_inherits_ground_from_a_proven_sibling():
    adj = corroborate([
        sig("nuclei", conf=0.5),
        sig("dalfox", status="confirmed", conf=0.95, method="tool-confirmed"),
    ])
    assert adj[0].confidence >= 0.8
    assert "proved" in adj[0].note
    assert adj[0].status == ValidationStatus.LIKELY.value  # still not proof


def test_the_proven_finding_itself_is_left_confirmed():
    adj = corroborate([
        sig("nuclei", conf=0.5),
        sig("dalfox", status="confirmed", conf=0.95, method="tool-confirmed"),
    ])
    assert 1 not in adj or adj[1].status == ValidationStatus.CONFIRMED.value


# --------------------------------------------------------------------------
# lone source
# --------------------------------------------------------------------------

def test_a_lone_pattern_match_loses_confidence():
    adj = corroborate([sig("nuclei", conf=0.6)])
    assert adj[0].confidence == pytest.approx(0.6 - LONE_SOURCE_PENALTY)
    assert "Single heuristic source" in adj[0].note


def test_a_lone_finding_never_drops_out_of_sight():
    adj = corroborate([sig("nuclei", conf=0.05)])
    assert adj[0].confidence == MIN_PENALISED_CONFIDENCE


def test_a_lone_oracle_confirmation_is_not_penalised():
    adj = corroborate([sig("sqlmap", status="confirmed", conf=0.95,
                           method="tool-confirmed")])
    assert 0 not in adj


def test_a_lone_safe_poc_confirmation_is_not_penalised():
    adj = corroborate([sig("ffuf", status="confirmed", conf=0.95,
                           method="safe-poc")])
    assert 0 not in adj


def test_closed_statuses_are_never_adjusted():
    adj = corroborate([
        sig("nuclei", status="false_positive", conf=0.0),
        sig("nikto", status="unconfirmed", conf=0.3),
    ])
    assert adj == {}


def test_empty_input():
    assert corroborate([]) == {}


# --------------------------------------------------------------------------
# apply() over ValidatedFinding-shaped objects
# --------------------------------------------------------------------------

class VF:
    def __init__(self, tool, status="likely", confidence=0.6,
                 method="scanner-match", target=URL, vuln_class="xss"):
        self.tool, self.status, self.confidence = tool, status, confidence
        self.method, self.target, self.vuln_class = method, target, vuln_class
        self.metadata = {"existing": True}


def test_apply_writes_status_confidence_and_reasoning():
    items = [VF("nuclei", confidence=0.65),
             VF("dalfox", status="false_positive", confidence=0.0,
                method="safe-poc (reflection)")]
    changed = apply(items)
    assert changed == 1
    assert items[0].status == "unconfirmed"
    corr = items[0].metadata["corroboration"]
    assert corr["demoted"] is True
    assert items[0].metadata["existing"] is True  # nothing else clobbered


def test_apply_leaves_untouched_findings_without_a_corroboration_key():
    items = [VF("sqlmap", status="confirmed", confidence=0.95,
                method="tool-confirmed (sqlmap)")]
    assert apply(items) == 0
    assert "corroboration" not in items[0].metadata


def test_apply_tolerates_missing_attributes():
    class Bare:
        metadata = None
        status = "likely"
        confidence = None
        tool = None
        target = None
        vuln_class = None
        method = None

    s = signal_of(Bare())
    assert s.confidence == 0.0
    assert s.status == "likely"
    assert apply([Bare()]) == 1


def test_apply_is_idempotent():
    items = [VF("nuclei", confidence=0.6), VF("nikto", confidence=0.6)]
    apply(items)
    first = [f.confidence for f in items]
    apply(items)
    assert [f.confidence for f in items] == first
