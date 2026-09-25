"""Run a second judge alongside the real one, and record where they disagree.

You cannot put a ten-day-old proprietary model on the path that decides whether
a finding is real. But you can run it in the dark, next to the judge that is
already trusted, and measure whether it would have agreed - which is exactly
what you need before you would ever consider switching.

So this mirrors llm_judge's selection loop, asks a SECOND opinion for the same
findings, and writes the comparison into each finding's metadata under
`shadow_judge`. It never calls update_verdict. The authoritative verdict is
whatever the real judge already set; nothing here can move it. The only output
is a record of agreement.

The second opinion is a plain callable, not a hardcoded backend, for two
reasons. It keeps the model under evaluation out of the critical path by
construction - a shadow that raises is caught and the run is untouched. And it
lets the same harness score any candidate: today the existing LLM judge at a
different temperature (a sanity baseline that needs no new service), tomorrow
Jev, next month whatever comes after it.

What "agreement" means here is deliberately not just "same string". A judge that
rules `false_positive` where the base said `likely` is being STRICTER - it would
have removed a finding from the report. One that rules `confirmed` where the base
said `unconfirmed` is being LOOSER - it would have promoted one. Those two errors
have very different costs to a pentest report, so they are counted apart. Raw
agreement rate hides that a model agrees 90% of the time and disagrees only ever
in the direction that ships a false positive.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

# Same ranking the real judge uses: lower index = stronger claim that the
# finding is real. Kept independent of llm_judge._RANK so a change there is a
# visible change here, not a silent one.
_RANK = {"confirmed": 0, "likely": 1, "unconfirmed": 2, "false_positive": 3}

AGREE = "agree"
SHADOW_STRICTER = "shadow_stricter"   # shadow would drop/weaken vs the base
SHADOW_LOOSER = "shadow_looser"       # shadow would promote/strengthen vs the base

# How close two confidences have to be to count as "the same number". A shadow
# that says 0.71 where the base said 0.70 has not disagreed about anything.
CONF_EPSILON = 0.15


def _rank(status: str) -> int:
    return _RANK.get(status, 1)


@dataclass(frozen=True)
class Comparison:
    """One finding, judged twice."""
    finding_id: str
    title: str
    vuln_class: str
    severity: str
    base_status: str
    base_confidence: float
    shadow_status: str
    shadow_confidence: float
    agreement: str
    # True when the two verdicts differ in a way that would change the report:
    # a finding kept vs dropped, or promoted vs held. A confidence wobble within
    # the same verdict is not one of these.
    material: bool
    shadow_reason: str = ""

    def to_public(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "base": {"status": self.base_status, "confidence": self.base_confidence},
            "shadow": {"status": self.shadow_status,
                       "confidence": self.shadow_confidence,
                       "reason": self.shadow_reason},
            "agreement": self.agreement,
            "material": self.material,
        }


def classify(base_status: str, shadow_status: str) -> str:
    """Which way the two verdicts diverge, if they do."""
    b, s = _rank(base_status), _rank(shadow_status)
    if s == b:
        return AGREE
    return SHADOW_STRICTER if s > b else SHADOW_LOOSER


def is_material(base_status: str, base_conf: float,
                shadow_status: str, shadow_conf: float) -> bool:
    """Would acting on the shadow verdict change what ships?

    A different verdict class is always material. The same class with a
    confidence gap wide enough to cross a reporting threshold is too; a small
    wobble is not.
    """
    if base_status != shadow_status:
        return True
    return abs(float(base_conf) - float(shadow_conf)) >= CONF_EPSILON


def compare_one(*, finding_id: str, title: str, vuln_class: str, severity: str,
                base_status: str, base_confidence: float,
                shadow_status: str, shadow_confidence: float,
                shadow_reason: str = "") -> Comparison:
    return Comparison(
        finding_id=finding_id, title=title, vuln_class=vuln_class,
        severity=severity,
        base_status=base_status, base_confidence=round(float(base_confidence), 3),
        shadow_status=shadow_status,
        shadow_confidence=round(float(shadow_confidence), 3),
        agreement=classify(base_status, shadow_status),
        material=is_material(base_status, base_confidence,
                             shadow_status, shadow_confidence),
        shadow_reason=(shadow_reason or "")[:300],
    )


@dataclass
class ShadowReport:
    """The whole comparison for one engagement."""
    backend: str
    compared: int = 0
    comparisons: List[Comparison] = field(default_factory=list)
    errors: int = 0

    @property
    def agree(self) -> int:
        return sum(1 for c in self.comparisons if c.agreement == AGREE)

    @property
    def stricter(self) -> int:
        return sum(1 for c in self.comparisons if c.agreement == SHADOW_STRICTER)

    @property
    def looser(self) -> int:
        return sum(1 for c in self.comparisons if c.agreement == SHADOW_LOOSER)

    @property
    def material_disagreements(self) -> int:
        return sum(1 for c in self.comparisons
                   if c.agreement != AGREE and c.material)

    @property
    def agreement_rate(self) -> float:
        return round(self.agree / self.compared, 3) if self.compared else 0.0

    def summary(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "compared": self.compared,
            "errors": self.errors,
            "agree": self.agree,
            "shadow_stricter": self.stricter,
            "shadow_looser": self.looser,
            "material_disagreements": self.material_disagreements,
            "agreement_rate": self.agreement_rate,
            # The line worth reading. Raw agreement flatters a model that only
            # ever disagrees by shipping a false positive; this says which way
            # the disagreements go and whether any of them would change the
            # report.
            "verdict": self._one_line(),
        }

    def _one_line(self) -> str:
        if not self.compared:
            return "nothing to compare - no findings were judgeable this run"
        parts = [f"{self.backend} agreed with the judge on "
                 f"{self.agree}/{self.compared} ({int(self.agreement_rate * 100)}%)"]
        if self.material_disagreements:
            parts.append(
                f"{self.material_disagreements} disagreement(s) would have "
                f"changed the report: {self.looser} looser (would ship more), "
                f"{self.stricter} stricter (would drop more)")
        else:
            parts.append("no disagreement would have changed the report")
        return "; ".join(parts) + "."


def build_report(backend: str, comparisons: Sequence[Comparison],
                 errors: int = 0) -> ShadowReport:
    report = ShadowReport(backend=backend, compared=len(comparisons),
                          comparisons=list(comparisons), errors=errors)
    return report


# --------------------------------------------------------------------------- #
# Async runner. Thin: everything worth testing is above this line.

# Same gate the real judge applies, so the two look at the same findings.
_JUDGEABLE_STATUS = {"likely", "unconfirmed"}
_JUDGEABLE_SEV = {"critical", "high", "medium"}
MAX_SHADOW = 40


async def run_shadow_judge(engagement_id: str, *, second_opinion,
                           backend: str) -> Dict[str, Any]:
    """Judge the same findings a second time and record the comparison.

    `second_opinion` is an async callable taking a finding and returning
    {"verdict", "confidence", "reason"} or None. It never touches the verdict:
    this function only ever calls set_metadata.
    """
    import logging

    from app import events
    from app.audit import audit
    from app.validation.storage import ValidatedFindingRepository

    log = logging.getLogger("syphax.validation.shadow")
    repo = ValidatedFindingRepository()
    findings = await repo.list(engagement_id)

    comparisons: List[Comparison] = []
    errors = 0
    for vf in findings:
        if len(comparisons) >= MAX_SHADOW:
            break
        if vf.status not in _JUDGEABLE_STATUS or (vf.severity or "").lower() not in _JUDGEABLE_SEV:
            continue
        if not (vf.evidence or "").strip():
            continue
        try:
            opinion = await second_opinion(vf)
        except Exception as exc:  # noqa: BLE001 - a shadow must never fail a run
            errors += 1
            log.warning("[%s] shadow backend %s failed on %s: %s",
                        engagement_id, backend, vf.id, exc)
            continue
        if not opinion or not opinion.get("verdict"):
            continue

        comp = compare_one(
            finding_id=vf.id, title=vf.title, vuln_class=vf.vuln_class,
            severity=vf.severity,
            base_status=vf.status, base_confidence=vf.confidence,
            shadow_status=str(opinion["verdict"]),
            shadow_confidence=float(opinion.get("confidence", 0.5)),
            shadow_reason=str(opinion.get("reason", "")),
        )
        comparisons.append(comp)

        # Recorded on the finding, so an operator reading it sees the second
        # opinion next to the verdict that actually shipped - and can tell at a
        # glance whether the new model would have agreed on THIS one.
        try:
            await repo.set_metadata(vf.id, {"shadow_judge": {
                "backend": backend, **comp.to_public()}})
        except Exception:  # noqa: BLE001 - the comparison is the deliverable, not the write
            log.exception("[%s] could not store shadow comparison for %s",
                          engagement_id, vf.id)

    report = build_report(backend, comparisons, errors)
    summary = report.summary()
    await events.emit(engagement_id, events.THOUGHT,
                      "Shadow judge: " + summary["verdict"],
                      level=events.LEVEL_INFO)
    await audit("validation.shadow_judge", engagement_id=engagement_id, **summary)
    log.info("[%s] shadow-judge: %s", engagement_id, summary)
    return summary
