"""Cross-tool corroboration: judge a finding against its neighbours.

Every finding used to be judged alone. The data to do better was already
there - a scan uses a dozen tools and several of them touch the same URL - but
nothing compared their verdicts, so:

  * two independent tools reporting the same weakness at the same place scored
    exactly the same as one tool guessing;
  * a finding whose oracle-based sibling was actively DISPROVEN at that same
    target still shipped as "likely";
  * a lone heuristic match (a scanner's own pattern, never re-checked) scored
    as high as a safe-PoC confirmation of the same class.

This module runs once over the whole validated set, groups the findings by
(vuln_class, target-without-query) and adjusts confidence - and, where an
oracle contradicts a guess, status. It is deliberately pure: `corroborate()`
takes plain records and returns adjustments, so the arbitration rules are
testable without a database.

What it will NOT do: promote anything to CONFIRMED. Agreement between two
pattern-matchers is not proof, so an unproven finding is capped below the
confirmed band no matter how many tools agree.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple
from urllib.parse import urlparse

from app.validation.models import ValidationStatus

# Methods that decided the verdict by observing the target rather than by
# matching a pattern: an active tool oracle, a safe re-fetch, an adaptive
# probe with a baseline, a replayed stored proof, or the catch-all baseline
# (which is a disproof oracle).
ORACLE_PREFIXES = (
    "tool-confirmed",
    "provider-verified",
    "safe-poc",
    "proof-replay",
    "baseline",
    "analysis (payload-probe)",
    "analysis (cve-checks)",
)

OPEN_STATUSES = {ValidationStatus.CONFIRMED.value, ValidationStatus.LIKELY.value}

# Confidence added per extra independent tool that agrees.
AGREEMENT_BONUS = 0.12
# Confidence removed from a finding whose only support is one scanner pattern.
LONE_SOURCE_PENALTY = 0.1
# An unproven finding never enters the confirmed band (floor 0.95), whatever
# agrees with it. Agreement between guesses is not proof.
MAX_UNPROVEN_CONFIDENCE = 0.9
# Floor for a penalised lone finding: still reportable, visibly weaker.
MIN_PENALISED_CONFIDENCE = 0.25
# Confidence a guess inherits when an oracle proved the same class at the same
# target through another tool.
PROVEN_SIBLING_CONFIDENCE = 0.8
# Confidence a contradicted guess is left with.
CONTRADICTED_CONFIDENCE = 0.3


@dataclass(frozen=True)
class Signal:
    """One validated finding, reduced to what arbitration needs."""
    tool: str
    vuln_class: str
    target: str
    status: str
    confidence: float
    method: str = ""


@dataclass(frozen=True)
class Adjustment:
    """What to change on one signal. `status`/`confidence` are absolute."""
    status: str
    confidence: float
    note: str
    tools: Tuple[str, ...] = ()
    independent: int = 1
    demoted: bool = False

    def to_metadata(self, base_confidence: float) -> Dict[str, object]:
        return {
            "note": self.note,
            "tools": list(self.tools),
            "independent": self.independent,
            "demoted": self.demoted,
            # The per-finding verdict before arbitration. Re-running over an
            # already-adjusted set must not compound the bonus, and the report
            # can show what the single-source score was.
            "base_confidence": round(base_confidence, 3),
        }


def is_oracle(method: str) -> bool:
    m = (method or "").strip().lower()
    return any(m.startswith(p) for p in ORACLE_PREFIXES)


def normalise_target(target: str) -> str:
    """Same resource seen by two tools -> same key.

    sqlmap reports `https://h/a.php?id=1`, nuclei reports `https://h/a.php`,
    nikto reports `https://h:443/a.php`. Drop the query, the fragment, a
    default port, a trailing slash and the host's case.
    """
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        return raw.lower().rstrip("/")
    p = urlparse(raw)
    host = (p.hostname or "").lower()
    if p.port and not ((p.scheme == "https" and p.port == 443)
                       or (p.scheme == "http" and p.port == 80)):
        host = f"{host}:{p.port}"
    path = (p.path or "/").rstrip("/") or "/"
    return f"{p.scheme}://{host}{path}"


def group_key(signal: Signal) -> Tuple[str, str]:
    return (str(signal.vuln_class or "unknown").strip().lower(),
            normalise_target(signal.target))


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return round(max(low, min(high, value)), 3)


def corroborate(signals: Sequence[Signal]) -> Dict[int, Adjustment]:
    """Arbitrate a whole validated set.

    Returns {index in `signals`: Adjustment} for the signals that change.
    Anything absent from the result is left exactly as it was.
    """
    groups: Dict[Tuple[str, str], List[int]] = {}
    for i, s in enumerate(signals):
        groups.setdefault(group_key(s), []).append(i)

    out: Dict[int, Adjustment] = {}
    for key, idxs in groups.items():
        vuln_class, target = key
        members = [signals[i] for i in idxs]

        # Who agrees there is an issue here, counted by distinct tool so one
        # noisy tool firing five templates is still one voice.
        agreeing = sorted({s.tool for s in members if s.status in OPEN_STATUSES})
        # An oracle that looked at the target and said no.
        contradicted_by = sorted({
            s.tool for s in members
            if s.status == ValidationStatus.FALSE_POSITIVE.value and is_oracle(s.method)
        })
        proven_by = sorted({
            s.tool for s in members
            if s.status == ValidationStatus.CONFIRMED.value and is_oracle(s.method)
        })

        for i in idxs:
            s = signals[i]
            if s.status not in OPEN_STATUSES:
                continue
            oracle = is_oracle(s.method)

            # 1. An oracle disproved this class at this exact target, and this
            # finding is only a pattern match. The oracle wins.
            if contradicted_by and not oracle:
                out[i] = Adjustment(
                    status=ValidationStatus.UNCONFIRMED.value,
                    confidence=min(s.confidence, CONTRADICTED_CONFIDENCE),
                    note=(f"{', '.join(contradicted_by)} checked {vuln_class} at this "
                          "target and could not reproduce it; this is a pattern "
                          "match only, so it needs a human rather than a report line."),
                    tools=tuple(agreeing), independent=len(agreeing), demoted=True,
                )
                continue

            # 2. Proof exists for this class at this target, from another tool.
            others_proven = [t for t in proven_by if t != s.tool]
            if others_proven and not oracle:
                out[i] = Adjustment(
                    status=s.status,
                    confidence=_clamp(max(s.confidence, PROVEN_SIBLING_CONFIDENCE),
                                      high=MAX_UNPROVEN_CONFIDENCE),
                    note=(f"{', '.join(others_proven)} proved {vuln_class} at this "
                          "target with a safe proof-of-exploit."),
                    tools=tuple(agreeing), independent=len(agreeing),
                )
                continue

            # 3. Independent agreement raises confidence, never to proof.
            if len(agreeing) >= 2:
                bonus = AGREEMENT_BONUS * (len(agreeing) - 1)
                ceiling = 1.0 if oracle else MAX_UNPROVEN_CONFIDENCE
                out[i] = Adjustment(
                    status=s.status,
                    confidence=_clamp(s.confidence + bonus, high=ceiling),
                    note=(f"{len(agreeing)} independent tools report {vuln_class} at "
                          f"this target ({', '.join(agreeing)})."),
                    tools=tuple(agreeing), independent=len(agreeing),
                )
                continue

            # 4. One tool, one pattern, nothing re-checked it.
            if not oracle:
                out[i] = Adjustment(
                    status=s.status,
                    confidence=_clamp(s.confidence - LONE_SOURCE_PENALTY,
                                      low=MIN_PENALISED_CONFIDENCE),
                    note=(f"Single heuristic source ({s.tool}); no other tool and no "
                          "oracle corroborated it."),
                    tools=tuple(agreeing), independent=1,
                )
    return out


def base_confidence_of(finding) -> float:
    """The finding's own confidence, before any previous arbitration."""
    md = getattr(finding, "metadata", None) or {}
    prior = md.get("corroboration") or {}
    if isinstance(prior, dict) and prior.get("base_confidence") is not None:
        try:
            return float(prior["base_confidence"])
        except (TypeError, ValueError):
            pass
    return float(getattr(finding, "confidence", 0.0) or 0.0)


def signal_of(finding) -> Signal:
    return Signal(
        tool=str(getattr(finding, "tool", "") or ""),
        vuln_class=str(getattr(finding, "vuln_class", "") or ""),
        target=str(getattr(finding, "target", "") or ""),
        status=str(getattr(finding, "status", "") or ""),
        confidence=base_confidence_of(finding),
        method=str(getattr(finding, "method", "") or ""),
    )


def apply(findings: Iterable) -> int:
    """Arbitrate ValidatedFindings in place. Returns how many changed.

    Writes the reasoning to `metadata["corroboration"]` so the report and the
    UI can say why a finding scored what it scored.
    """
    items = list(findings)
    signals = [signal_of(f) for f in items]
    adjustments = corroborate(signals)
    for i, adj in adjustments.items():
        f = items[i]
        f.status = adj.status
        f.confidence = adj.confidence
        md = dict(getattr(f, "metadata", None) or {})
        md["corroboration"] = adj.to_metadata(signals[i].confidence)
        f.metadata = md
    return len(adjustments)
