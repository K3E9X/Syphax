"""The shadow judge: run a second opinion alongside the real one and measure it.

The point of this whole thing is to be able to evaluate a new model - Jev, or
whatever comes next - WITHOUT putting it on the path that decides whether a
finding is real. So the two properties that matter most are:

  * the shadow can never move a verdict. It writes metadata and nothing else.
  * "agreement" distinguishes the two directions of disagreement, because they
    have opposite costs: a shadow that would ship a false positive and one that
    would drop a real finding are not the same error, and a single agreement
    percentage hides which one a candidate makes.
"""
from __future__ import annotations


from app.validation import shadow
from app.validation.second_opinion import (build_jev_request, parse_jev_response,
                                           resolve)


class FakeFinding:
    def __init__(self, **kw):
        self.id = kw.get("id", "f1")
        self.title = kw.get("title", "SQLi in /login")
        self.vuln_class = kw.get("vuln_class", "sql_injection")
        self.severity = kw.get("severity", "high")
        self.status = kw.get("status", "likely")
        self.confidence = kw.get("confidence", 0.6)
        self.evidence = kw.get("evidence", "error: syntax near ''")
        self.target = kw.get("target", "https://app.example.com/login")


# ---- direction of disagreement ----------------------------------------------

def test_a_false_positive_ruling_over_a_likely_is_stricter():
    """The shadow would have dropped a finding the base kept."""
    assert shadow.classify("likely", "false_positive") == shadow.SHADOW_STRICTER


def test_a_confirmed_ruling_over_an_unconfirmed_is_looser():
    """The shadow would have promoted a finding the base held back - the error
    that ships a false positive."""
    assert shadow.classify("unconfirmed", "confirmed") == shadow.SHADOW_LOOSER


def test_the_same_verdict_agrees():
    assert shadow.classify("likely", "likely") == shadow.AGREE


# ---- materiality ------------------------------------------------------------

def test_a_different_verdict_class_always_changes_the_report():
    assert shadow.is_material("likely", 0.6, "false_positive", 0.6)


def test_a_small_confidence_wobble_within_a_verdict_is_not_material():
    assert not shadow.is_material("likely", 0.70, "likely", 0.72)


def test_a_confidence_gap_wide_enough_to_cross_a_threshold_is_material():
    assert shadow.is_material("likely", 0.70, "likely", 0.50)


# ---- the summary line, which is the deliverable ------------------------------

def _comp(base, sh, conf=0.7):
    return shadow.compare_one(
        finding_id="x", title="t", vuln_class="xss", severity="high",
        base_status=base, base_confidence=conf,
        shadow_status=sh, shadow_confidence=conf)


def test_the_summary_counts_the_two_directions_apart():
    report = shadow.build_report("jev", [
        _comp("likely", "likely"),
        _comp("likely", "likely"),
        _comp("unconfirmed", "confirmed"),   # looser
        _comp("likely", "false_positive"),   # stricter
    ])
    s = report.summary()
    assert s["agree"] == 2
    assert s["shadow_looser"] == 1
    assert s["shadow_stricter"] == 1
    assert s["agreement_rate"] == 0.5
    assert s["material_disagreements"] == 2


def test_the_verdict_line_says_which_way_the_disagreements_go():
    """Raw agreement rate flatters a model that only ever disagrees by shipping
    a false positive. The one-liner has to name the direction."""
    report = shadow.build_report("jev", [
        _comp("likely", "likely"),
        _comp("unconfirmed", "confirmed"),
    ])
    line = report.summary()["verdict"]
    assert "1 looser (would ship more)" in line
    assert "would have changed the report" in line


def test_full_agreement_says_nothing_would_have_changed():
    report = shadow.build_report("llm", [_comp("likely", "likely")])
    assert "no disagreement would have changed the report" in report.summary()["verdict"]


def test_nothing_to_compare_is_stated_not_a_zero_percent():
    """An empty run is 'nothing judgeable', not 'the shadow agreed 0% of the
    time' - which would read as total disagreement."""
    report = shadow.build_report("jev", [])
    assert report.summary()["compared"] == 0
    assert "nothing to compare" in report.summary()["verdict"]


# ---- the shadow never moves a verdict ---------------------------------------

class RecordingRepo:
    """A ValidatedFindingRepository that fails the test if the verdict is
    touched. The whole safety argument is that the shadow only ever calls
    set_metadata; this makes calling update_verdict a hard error."""
    def __init__(self, findings):
        self._findings = findings
        self.metadata_writes = []

    async def list(self, engagement_id):
        return self._findings

    async def set_metadata(self, vf_id, patch):
        self.metadata_writes.append((vf_id, patch))

    async def update_verdict(self, *a, **k):  # pragma: no cover - must never run
        raise AssertionError("the shadow judge moved a verdict")


async def test_the_shadow_records_but_never_moves_a_verdict(monkeypatch):
    findings = [FakeFinding(id="a", status="likely", severity="high"),
                FakeFinding(id="b", status="unconfirmed", severity="critical")]
    repo = RecordingRepo(findings)
    monkeypatch.setattr("app.validation.storage.ValidatedFindingRepository",
                        lambda: repo)

    async def opinion(vf):
        return {"verdict": "false_positive", "confidence": 0.9, "reason": "no"}

    summary = await shadow.run_shadow_judge("e1", second_opinion=opinion,
                                            backend="jev")
    assert summary["compared"] == 2
    # It recorded a comparison on each finding, under shadow_judge, and never
    # called update_verdict (RecordingRepo would have raised).
    assert len(repo.metadata_writes) == 2
    assert all("shadow_judge" in patch for _, patch in repo.metadata_writes)


async def test_a_shadow_backend_that_raises_never_fails_the_run(monkeypatch):
    """The model is under evaluation. It must not be able to take down the run
    it is being evaluated against."""
    repo = RecordingRepo([FakeFinding(status="likely", severity="high")])
    monkeypatch.setattr("app.validation.storage.ValidatedFindingRepository",
                        lambda: repo)

    async def broken(vf):
        raise RuntimeError("jev exploded")

    summary = await shadow.run_shadow_judge("e1", second_opinion=broken,
                                            backend="jev")
    assert summary["errors"] == 1
    assert summary["compared"] == 0


async def test_only_judgeable_findings_are_compared(monkeypatch):
    """Same gate the real judge uses, so the two look at the same findings and
    the agreement number means something."""
    findings = [
        FakeFinding(id="ok", status="likely", severity="high"),
        FakeFinding(id="confirmed-already", status="confirmed", severity="high"),
        FakeFinding(id="low", status="likely", severity="low"),
        FakeFinding(id="no-evidence", status="likely", severity="high", evidence=""),
    ]
    repo = RecordingRepo(findings)
    monkeypatch.setattr("app.validation.storage.ValidatedFindingRepository",
                        lambda: repo)

    async def opinion(vf):
        return {"verdict": "likely", "confidence": 0.6}

    summary = await shadow.run_shadow_judge("e1", second_opinion=opinion,
                                            backend="llm")
    assert summary["compared"] == 1
    assert repo.metadata_writes[0][0] == "ok"


# ---- Jev adapter (pure parts; the endpoint is unreachable from here) ---------

def test_jev_is_asked_for_a_typed_choice_over_the_four_verdicts():
    req = build_jev_request(FakeFinding())
    assert req["choice"]["options"] == list(shadow._RANK.keys())
    assert "Evidence:" in req["input"]


def test_jev_response_reads_the_chosen_option_and_its_probability():
    """Jev returns per-option probabilities; the confidence is the one for the
    option it picked, which is better calibrated than a number an LLM writes."""
    out = parse_jev_response({"choice": "false_positive",
                              "probabilities": {"false_positive": 0.93, "likely": 0.04}})
    assert out == {"verdict": "false_positive", "confidence": 0.93, "reason": ""}


def test_jev_response_falls_back_to_a_flat_confidence_field():
    out = parse_jev_response({"value": "confirmed", "confidence": 0.8})
    assert out["verdict"] == "confirmed" and out["confidence"] == 0.8


def test_an_unreadable_jev_response_is_no_opinion_not_a_guess():
    """A shadow that misreads its backend is worse than one that stays quiet:
    it would report disagreement that never happened."""
    for bad in ({}, {"choice": "banana"}, {"nonsense": 1}, [], None):
        assert parse_jev_response(bad) is None


def test_jev_is_off_unless_configured(monkeypatch):
    monkeypatch.delenv("JEV_BASE_URL", raising=False)
    monkeypatch.delenv("JEV_API_KEY", raising=False)
    fn, why = resolve("jev")
    assert fn is None
    assert "unset" in why


def test_jev_resolves_once_configured(monkeypatch):
    monkeypatch.setenv("JEV_BASE_URL", "https://api.typesafe.ai")
    monkeypatch.setenv("JEV_API_KEY", "k")
    fn, label = resolve("jev")
    assert callable(fn) and label == "jev"


def test_an_unknown_backend_is_named_not_silently_ignored():
    fn, why = resolve("gpt5")
    assert fn is None and "unknown shadow backend" in why
