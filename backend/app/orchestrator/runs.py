"""Orchestrator run tracking.

A 'run' is one autonomous engagement execution: the plan->execute->ingest
loop. The API enqueues it on the worker and polls this table for live status;
a stop request flips `stop_requested`, which the loop checks each iteration.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app import db

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS runs (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL,
    status          TEXT NOT NULL,        -- queued | running | completed | failed | stopped
    phase           TEXT,
    iterations      INTEGER NOT NULL DEFAULT 0,
    jobs_launched   INTEGER NOT NULL DEFAULT 0,
    stop_requested  BOOLEAN NOT NULL DEFAULT FALSE,
    started_at      DOUBLE PRECISION,
    finished_at     DOUBLE PRECISION,
    created_at      DOUBLE PRECISION NOT NULL,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_engagement ON runs(engagement_id);
CREATE INDEX IF NOT EXISTS idx_runs_created    ON runs(created_at DESC);

-- Why the run ended (saturated | time_budget | job_budget | no_tools |
-- max_iterations | stopped | exploit_denied | error). Added post-v1.
ALTER TABLE runs ADD COLUMN IF NOT EXISTS stop_reason TEXT;

-- Last sign of life from the loop. Without it a worker that died left the run
-- stuck at 'running' forever, and start_run's "one active run" guard then
-- refused every new run on that engagement with a 409 that never cleared.
ALTER TABLE runs ADD COLUMN IF NOT EXISTS heartbeat_at DOUBLE PRECISION;
"""

db.register_schema(SCHEMA_SQL)


# A loop touches its heartbeat every iteration, and an iteration waits at most
# ITERATION_WAIT_CAP (45 min) for its batch. Three times that is comfortably
# past the slowest legitimate iteration and still reclaims the same day.
STALE_AFTER_SECONDS = 3 * 45 * 60


def is_stale(status: Optional[str], heartbeat_at: Optional[float],
             now: Optional[float] = None) -> bool:
    """Does this run claim to be active while nothing is driving it?

    A run with no heartbeat at all predates the column (or died before its
    first iteration); treat it as stale so it cannot block the engagement.
    """
    if status not in ("queued", "running"):
        return False
    if heartbeat_at is None:
        return True
    return ((now if now is not None else time.time()) - heartbeat_at) > STALE_AFTER_SECONDS


def new_run_id() -> str:
    return f"run_{int(time.time() * 1000)}"


@dataclass
class Run:
    id: str
    engagement_id: str
    status: str
    phase: Optional[str] = None
    iterations: int = 0
    jobs_launched: int = 0
    stop_requested: bool = False
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    created_at: float = 0.0
    error: Optional[str] = None
    stop_reason: Optional[str] = None
    heartbeat_at: Optional[float] = None

    def to_public(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "status": self.status,
            "phase": self.phase,
            "iterations": self.iterations,
            "jobs_launched": self.jobs_launched,
            "stop_requested": self.stop_requested,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "created_at": self.created_at,
            "error": self.error,
            "stop_reason": self.stop_reason,
            "heartbeat_at": self.heartbeat_at,
            "stale": is_stale(self.status, self.heartbeat_at),
        }


class RunRepository:
    async def create(self, run: Run) -> None:
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO runs (id, engagement_id, status, phase, iterations,
                    jobs_launched, stop_requested, started_at, finished_at, created_at, error)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                """,
                run.id, run.engagement_id, run.status, run.phase, run.iterations,
                run.jobs_launched, run.stop_requested, run.started_at,
                run.finished_at, run.created_at, run.error,
            )

    async def update(self, run: Run) -> None:
        async with db.acquire() as conn:
            await conn.execute(
                """
                UPDATE runs SET status=$1, phase=$2, iterations=$3, jobs_launched=$4,
                    stop_requested=$5, started_at=$6, finished_at=$7, error=$8,
                    stop_reason=$9, heartbeat_at=$10
                WHERE id=$11
                """,
                run.status, run.phase, run.iterations, run.jobs_launched,
                run.stop_requested, run.started_at, run.finished_at, run.error,
                run.stop_reason, run.heartbeat_at, run.id,
            )

    async def beat(self, run_id: str) -> None:
        """Record a sign of life. Cheap enough to call every iteration."""
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE runs SET heartbeat_at=$1 WHERE id=$2", time.time(), run_id)

    async def reclaim_stale(self, engagement_id: str) -> int:
        """Close out runs that claim to be active but have no live loop.

        Returns how many were reclaimed. Their coverage rows stay, which is what
        lets the next run continue instead of redoing the work.
        """
        cutoff = time.time() - STALE_AFTER_SECONDS
        async with db.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE runs
                   SET status='failed',
                       stop_reason=COALESCE(stop_reason, 'interrupted'),
                       error=COALESCE(error, 'run interrupted: the worker stopped '
                                             'reporting; coverage was kept'),
                       finished_at=COALESCE(finished_at, $1)
                 WHERE engagement_id=$2
                   AND status IN ('queued','running')
                   AND (heartbeat_at IS NULL OR heartbeat_at < $3)
                """,
                time.time(), engagement_id, cutoff,
            )
        try:
            return int(str(result).split()[-1])
        except (IndexError, ValueError):
            return 0

    async def get(self, run_id: str) -> Optional[Run]:
        async with db.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM runs WHERE id=$1", run_id)
        return _row(row) if row else None

    async def latest_for_engagement(self, engagement_id: str) -> Optional[Run]:
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM runs WHERE engagement_id=$1 ORDER BY created_at DESC LIMIT 1",
                engagement_id,
            )
        return _row(row) if row else None

    async def stop_requested(self, run_id: str) -> bool:
        async with db.acquire() as conn:
            val = await conn.fetchval("SELECT stop_requested FROM runs WHERE id=$1", run_id)
        return bool(val)

    async def request_stop(self, run_id: str) -> bool:
        async with db.acquire() as conn:
            result = await conn.execute(
                "UPDATE runs SET stop_requested=TRUE WHERE id=$1 AND status IN ('queued','running')",
                run_id,
            )
        try:
            return int(result.split()[-1]) > 0
        except (IndexError, ValueError):
            return False


def _row(row) -> Run:
    return Run(
        id=row["id"],
        engagement_id=row["engagement_id"],
        status=row["status"],
        phase=row["phase"],
        iterations=row["iterations"],
        jobs_launched=row["jobs_launched"],
        stop_requested=row["stop_requested"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        created_at=row["created_at"],
        error=row["error"],
        stop_reason=row["stop_reason"] if "stop_reason" in row else None,
        heartbeat_at=row["heartbeat_at"] if "heartbeat_at" in row else None,
    )
