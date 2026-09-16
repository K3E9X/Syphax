"""Persistence for scan jobs (Postgres). Shares DATABASE_URL with the proxy capture."""
from __future__ import annotations

import json
import time
from typing import List, Optional

from app import db
from app.scans.models import Job, JobStatus, findings_from_json, findings_to_json

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS jobs (
    id              TEXT PRIMARY KEY,
    tool            TEXT NOT NULL,
    target          TEXT NOT NULL,
    args_json       TEXT NOT NULL,
    status          TEXT NOT NULL,
    created_at      DOUBLE PRECISION NOT NULL,
    started_at      DOUBLE PRECISION,
    finished_at     DOUBLE PRECISION,
    exit_code       INTEGER,
    stdout          BYTEA,
    stderr          BYTEA,
    findings_json   TEXT,
    flow_id         TEXT,
    error           TEXT,
    engagement_id   TEXT,
    catalog_item_id TEXT
);

-- For databases created before these columns existed.
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS engagement_id   TEXT;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS catalog_item_id TEXT;

CREATE INDEX IF NOT EXISTS idx_jobs_created    ON jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status     ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_engagement ON jobs(engagement_id);
"""

db.register_schema(SCHEMA_SQL)


class JobRepository:
    """Async repository for scan jobs. Borrows a connection from the shared pool."""

    async def create(self, job: Job) -> None:
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO jobs (
                    id, tool, target, args_json, status, created_at, started_at,
                    finished_at, exit_code, stdout, stderr, findings_json, flow_id, error,
                    engagement_id, catalog_item_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                """,
                job.id,
                job.tool,
                job.target,
                json.dumps(job.args),
                job.status.value,
                job.created_at,
                job.started_at,
                job.finished_at,
                job.exit_code,
                job.stdout,
                job.stderr,
                findings_to_json(job.findings),
                job.flow_id,
                job.error,
                job.engagement_id,
                job.catalog_item_id,
            )

    async def update(self, job: Job) -> None:
        async with db.acquire() as conn:
            await conn.execute(
                """
                UPDATE jobs SET
                    status = $1,
                    started_at = $2,
                    finished_at = $3,
                    exit_code = $4,
                    stdout = $5,
                    stderr = $6,
                    findings_json = $7,
                    error = $8
                WHERE id = $9
                """,
                job.status.value,
                job.started_at,
                job.finished_at,
                job.exit_code,
                job.stdout,
                job.stderr,
                findings_to_json(job.findings),
                job.error,
                job.id,
            )

    async def get(self, job_id: str) -> Optional[Job]:
        async with db.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM jobs WHERE id = $1", job_id)
        return _row_to_job(row) if row else None

    async def list(self, *, limit: int = 100, offset: int = 0) -> List[Job]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                limit,
                offset,
            )
        return [_row_to_job(row) for row in rows]

    async def list_by_engagement(self, engagement_id: str, *, limit: int = 1000) -> List[Job]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM jobs WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2",
                engagement_id,
                limit,
            )
        return [_row_to_job(row) for row in rows]

    async def count(self) -> int:
        async with db.acquire() as conn:
            return int(await conn.fetchval("SELECT COUNT(*) FROM jobs"))

    async def delete_by_tool(self, engagement_id: str, tool: str) -> int:
        """Remove an engagement's jobs for a given tool (used to make the
        synthetic 'logic' analysis idempotent across re-runs)."""
        async with db.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM jobs WHERE engagement_id=$1 AND tool=$2", engagement_id, tool
            )
        try:
            return int(result.split()[-1])
        except (IndexError, ValueError):
            return 0

    async def delete(self, job_id: str) -> bool:
        async with db.acquire() as conn:
            result = await conn.execute("DELETE FROM jobs WHERE id = $1", job_id)
        try:
            return int(result.split()[-1]) > 0
        except (IndexError, ValueError):
            return False


def _row_to_job(row) -> Job:
    try:
        args = json.loads(row["args_json"] or "[]")
    except json.JSONDecodeError:
        args = []
    stdout = row["stdout"]
    stderr = row["stderr"]
    if isinstance(stdout, memoryview):
        stdout = bytes(stdout)
    if isinstance(stderr, memoryview):
        stderr = bytes(stderr)
    return Job(
        id=row["id"],
        tool=row["tool"],
        target=row["target"],
        args=args,
        status=JobStatus(row["status"]),
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        exit_code=row["exit_code"],
        stdout=stdout or b"",
        stderr=stderr or b"",
        findings=findings_from_json(row["findings_json"]),
        flow_id=row["flow_id"],
        error=row["error"],
        engagement_id=row["engagement_id"] if "engagement_id" in row else None,
        catalog_item_id=row["catalog_item_id"] if "catalog_item_id" in row else None,
    )


def new_job_id() -> str:
    return f"job_{int(time.time()*1000)}"
