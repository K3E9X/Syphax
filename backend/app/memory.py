"""Cross-engagement memory: what worked before, on this kind of stack.

Every run currently starts from nothing. A human pentester does not: they
remember that this WordPress plugin version fell to a particular CVE, that this
WAF ate the generic payloads until a given tamper, that a given endpoint shape
is usually where the authorization gap is. This is that memory.

What it stores is deliberately narrow - outcomes, not raw findings:

    (technology fingerprint, vuln_class) -> did it hold up, how often

Two properties make it safe to act on:

  * it only records what was CONFIRMED or killed as a false positive. A
    "likely" is an opinion; storing opinions would compound them into
    confident nonsense over time.
  * it is advisory. It reorders and suggests; nothing here bypasses the scope
    gate, the active-exploit gate or the oracle. A lesson that turns out wrong
    costs a probe, not a wrong report.

No embeddings and no model: the join key is the fingerprint, which the
tools already give us. That keeps it explainable - you can read why the planner
prioritised something.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from app import db

logger = logging.getLogger("syphax.memory")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS lessons (
    id            BIGSERIAL PRIMARY KEY,
    technology    TEXT NOT NULL,      -- normalised fingerprint, e.g. 'wordpress'
    vuln_class    TEXT NOT NULL,
    confirmed     INTEGER NOT NULL DEFAULT 0,
    refuted       INTEGER NOT NULL DEFAULT 0,
    last_seen     DOUBLE PRECISION NOT NULL,
    -- Kept for the report/UI: the most recent thing that actually worked.
    example_title TEXT,
    example_cve   TEXT,
    UNIQUE (technology, vuln_class)
);
CREATE INDEX IF NOT EXISTS idx_lessons_tech ON lessons(technology);
"""

db.register_schema(SCHEMA_SQL)

# A lesson needs a few observations before it should steer anything; one
# confirmed finding on one target is an anecdote.
MIN_OBSERVATIONS = 2
# Below this, history says the class was mostly noise on this stack.
MIN_PRECISION = 0.5
MAX_SUGGESTIONS = 12


# --------------------------------------------------------------------------- #
# Pure core (unit-tested)

@dataclass(frozen=True)
class Lesson:
    technology: str
    vuln_class: str
    confirmed: int
    refuted: int
    last_seen: float = 0.0
    example_title: Optional[str] = None
    example_cve: Optional[str] = None

    @property
    def observations(self) -> int:
        return self.confirmed + self.refuted

    @property
    def precision(self) -> float:
        """Share of observations that held up. 0.0 when nothing is recorded."""
        return (self.confirmed / self.observations) if self.observations else 0.0

    @property
    def actionable(self) -> bool:
        """Enough evidence, and evidence that points somewhere."""
        return (self.observations >= MIN_OBSERVATIONS
                and self.precision >= MIN_PRECISION
                and self.confirmed > 0)

    def to_public(self) -> Dict[str, Any]:
        return {
            "technology": self.technology, "vuln_class": self.vuln_class,
            "confirmed": self.confirmed, "refuted": self.refuted,
            "observations": self.observations, "precision": round(self.precision, 2),
            "actionable": self.actionable, "last_seen": self.last_seen,
            "example_title": self.example_title, "example_cve": self.example_cve,
        }


def normalise_tech(value: Any) -> str:
    """Fold a fingerprint onto a stable join key.

    Tools report the same stack many ways ('WordPress 6.2', 'wordpress',
    'WordPress'); a version in the key would make every lesson a singleton.
    """
    tech = str(value or "").strip().lower()
    if tech.startswith("waf:"):                     # keep WAF names distinct
        return "waf:" + tech[4:].split("/")[0].strip()
    # drop a trailing version: "apache/2.4.49" -> "apache", "nginx 1.24" -> "nginx"
    tech = tech.split("/")[0]
    parts = [p for p in tech.replace(",", " ").split() if not p[:1].isdigit()]
    return " ".join(parts)[:60].strip()


def outcome_of(status: Any) -> Optional[str]:
    """Map a validated status onto what memory records, or None to ignore it.

    Only the two ends count: a 'likely' is an opinion, and remembering opinions
    would compound them into confident nonsense.
    """
    s = str(status or "").strip().lower()
    if s == "confirmed":
        return "confirmed"
    if s == "false_positive":
        return "refuted"
    return None


def rank_lessons(lessons: Sequence[Lesson],
                 technologies: Sequence[str]) -> List[Lesson]:
    """Actionable lessons matching this stack, most trustworthy first."""
    wanted = {normalise_tech(t) for t in (technologies or [])}
    wanted.discard("")
    matched = [l for l in lessons
               if l.actionable and normalise_tech(l.technology) in wanted]
    matched.sort(key=lambda l: (-l.precision, -l.confirmed, l.vuln_class))
    return matched[:MAX_SUGGESTIONS]


def suggested_classes(lessons: Sequence[Lesson],
                      technologies: Sequence[str]) -> List[str]:
    """Vuln classes worth prioritising on this stack, in order."""
    out: List[str] = []
    for lesson in rank_lessons(lessons, technologies):
        if lesson.vuln_class not in out:
            out.append(lesson.vuln_class)
    return out


# --------------------------------------------------------------------------- #

async def record_engagement(engagement_id: str) -> Dict[str, int]:
    """Fold one finished engagement's verdicts into the shared memory.

    Called after validation, so verdicts are final. Idempotent per engagement
    would need a marker; re-running an engagement's validation re-counts, which
    is acceptable: the ratio matters, not the absolute count.
    """
    from app.orchestrator.state import EngagementState
    from app.validation.storage import ValidatedFindingRepository

    techs = [normalise_tech(t) for t in await EngagementState(engagement_id).technologies()]
    techs = sorted({t for t in techs if t})
    if not techs:
        return {"skipped": 1, "reason": "no fingerprints to attach lessons to"}

    findings = await ValidatedFindingRepository().list(engagement_id)
    written = 0
    for vf in findings:
        outcome = outcome_of(vf.status)
        if outcome is None or not (vf.vuln_class or "").strip():
            continue
        cve = (vf.metadata or {}).get("cve_id") if vf.metadata else None
        for tech in techs:
            await _bump(tech, vf.vuln_class.strip().lower(), outcome,
                        vf.title, cve)
            written += 1
    logger.info("[%s] memory: %d lesson update(s) over %d technology(ies)",
                engagement_id, written, len(techs))
    return {"updates": written, "technologies": len(techs)}


async def _bump(technology: str, vuln_class: str, outcome: str,
                title: Optional[str], cve: Optional[str]) -> None:
    confirmed = 1 if outcome == "confirmed" else 0
    refuted = 1 if outcome == "refuted" else 0
    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO lessons (technology, vuln_class, confirmed, refuted,
                                 last_seen, example_title, example_cve)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            ON CONFLICT (technology, vuln_class) DO UPDATE SET
                confirmed = lessons.confirmed + EXCLUDED.confirmed,
                refuted   = lessons.refuted   + EXCLUDED.refuted,
                last_seen = EXCLUDED.last_seen,
                -- only overwrite the example when this one actually worked
                example_title = CASE WHEN EXCLUDED.confirmed > 0
                                     THEN EXCLUDED.example_title
                                     ELSE lessons.example_title END,
                example_cve   = CASE WHEN EXCLUDED.confirmed > 0
                                     THEN EXCLUDED.example_cve
                                     ELSE lessons.example_cve END
            """,
            technology, vuln_class, confirmed, refuted, time.time(),
            (title or "")[:200] if confirmed else None,
            cve if confirmed else None,
        )


async def all_lessons() -> List[Lesson]:
    try:
        async with db.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM lessons ORDER BY confirmed DESC")
    except Exception:  # noqa: BLE001 - memory is advisory; never block a run
        return []
    return [Lesson(technology=r["technology"], vuln_class=r["vuln_class"],
                   confirmed=r["confirmed"], refuted=r["refuted"],
                   last_seen=r["last_seen"], example_title=r["example_title"],
                   example_cve=r["example_cve"]) for r in rows]


async def advice_for(technologies: Sequence[str]) -> List[Dict[str, Any]]:
    """What past engagements suggest looking at first on this stack."""
    return [l.to_public() for l in rank_lessons(await all_lessons(), technologies)]
