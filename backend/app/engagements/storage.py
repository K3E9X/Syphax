"""Postgres persistence for engagements."""
from __future__ import annotations

import json
from typing import List, Optional

from app import db
from app.engagements.models import (
    Engagement,
    EngagementStatus,
    VerificationMethod,
    scope_from_json,
    scope_to_json,
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS engagements (
    id                   TEXT PRIMARY KEY,
    target_url           TEXT NOT NULL,
    target_host          TEXT NOT NULL,
    scope_hosts_json     TEXT NOT NULL,
    status               TEXT NOT NULL,
    verification_token   TEXT NOT NULL,
    verification_method  TEXT,
    title                TEXT,
    notes                TEXT,
    created_at           DOUBLE PRECISION NOT NULL,
    verified_at          DOUBLE PRECISION,
    closed_at            DOUBLE PRECISION,
    attested_at          DOUBLE PRECISION,
    budget_requests      INTEGER,
    budget_seconds       INTEGER,
    require_exploit_approval BOOLEAN NOT NULL DEFAULT FALSE,
    secondary_auth_json  TEXT,
    primary_auth_json    TEXT,
    allow_active_exploit BOOLEAN NOT NULL DEFAULT FALSE,
    allow_sql_os_cmd     BOOLEAN NOT NULL DEFAULT FALSE,
    allow_data_proof     BOOLEAN NOT NULL DEFAULT FALSE,
    user_agent_mode      TEXT,
    user_agent           TEXT,
    exploit_capabilities_json TEXT
);

ALTER TABLE engagements ADD COLUMN IF NOT EXISTS require_exploit_approval BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS secondary_auth_json TEXT;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS primary_auth_json TEXT;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS allow_active_exploit BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS allow_sql_os_cmd BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS allow_data_proof BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS user_agent_mode TEXT;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS exploit_capabilities_json TEXT;

CREATE INDEX IF NOT EXISTS idx_engagements_created ON engagements(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_engagements_status  ON engagements(status);
CREATE INDEX IF NOT EXISTS idx_engagements_host    ON engagements(target_host);
"""

db.register_schema(SCHEMA_SQL)


class EngagementRepository:
    async def create(self, e: Engagement) -> None:
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO engagements (
                    id, target_url, target_host, scope_hosts_json, status,
                    verification_token, verification_method, title, notes,
                    created_at, verified_at, closed_at, attested_at,
                    budget_requests, budget_seconds, require_exploit_approval,
                    secondary_auth_json, primary_auth_json,
                    allow_active_exploit, allow_sql_os_cmd, allow_data_proof,
                    user_agent_mode, user_agent, exploit_capabilities_json
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
                """,
                e.id,
                e.target_url,
                e.target_host,
                scope_to_json(e.scope_hosts),
                e.status.value,
                e.verification_token,
                e.verification_method.value if e.verification_method else None,
                e.title,
                e.notes,
                e.created_at,
                e.verified_at,
                e.closed_at,
                e.attested_at,
                e.budget_requests,
                e.budget_seconds,
                e.require_exploit_approval,
                json.dumps(e.secondary_auth or []),
                json.dumps(e.primary_auth or []),
                e.allow_active_exploit,
                e.allow_sql_os_cmd,
                e.allow_data_proof,
                e.user_agent_mode or None,
                e.user_agent or None,
                json.dumps(e.exploit_capabilities or []),
            )

    async def update(self, e: Engagement) -> None:
        async with db.acquire() as conn:
            await conn.execute(
                """
                UPDATE engagements SET
                    target_url = $1,
                    target_host = $2,
                    scope_hosts_json = $3,
                    status = $4,
                    verification_token = $5,
                    verification_method = $6,
                    title = $7,
                    notes = $8,
                    verified_at = $9,
                    closed_at = $10,
                    attested_at = $11,
                    budget_requests = $12,
                    budget_seconds = $13,
                    require_exploit_approval = $14,
                    allow_active_exploit = $15,
                    allow_sql_os_cmd = $16,
                    allow_data_proof = $17,
                    user_agent_mode = $18,
                    user_agent = $19,
                    exploit_capabilities_json = $20
                WHERE id = $21
                """,
                e.target_url,
                e.target_host,
                scope_to_json(e.scope_hosts),
                e.status.value,
                e.verification_token,
                e.verification_method.value if e.verification_method else None,
                e.title,
                e.notes,
                e.verified_at,
                e.closed_at,
                e.attested_at,
                e.budget_requests,
                e.budget_seconds,
                e.require_exploit_approval,
                e.allow_active_exploit,
                e.allow_sql_os_cmd,
                e.allow_data_proof,
                e.user_agent_mode or None,
                e.user_agent or None,
                json.dumps(e.exploit_capabilities or []),
                e.id,
            )

    async def get(self, engagement_id: str) -> Optional[Engagement]:
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM engagements WHERE id = $1", engagement_id
            )
        return _row_to_engagement(row) if row else None

    async def list(self, *, limit: int = 100, offset: int = 0) -> List[Engagement]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM engagements ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                limit,
                offset,
            )
        return [_row_to_engagement(r) for r in rows]

    async def count(self) -> int:
        async with db.acquire() as conn:
            return int(await conn.fetchval("SELECT COUNT(*) FROM engagements"))


def _row_to_engagement(row) -> Engagement:
    return Engagement(
        id=row["id"],
        target_url=row["target_url"],
        target_host=row["target_host"],
        scope_hosts=scope_from_json(row["scope_hosts_json"]),
        status=EngagementStatus(row["status"]),
        verification_token=row["verification_token"],
        verification_method=(
            VerificationMethod(row["verification_method"])
            if row["verification_method"]
            else None
        ),
        title=row["title"] or "",
        notes=row["notes"] or "",
        created_at=row["created_at"],
        verified_at=row["verified_at"],
        closed_at=row["closed_at"],
        attested_at=row["attested_at"],
        budget_requests=row["budget_requests"],
        budget_seconds=row["budget_seconds"],
        require_exploit_approval=(
            row["require_exploit_approval"] if "require_exploit_approval" in row else False
        ),
        allow_active_exploit=(
            row["allow_active_exploit"] if "allow_active_exploit" in row else False
        ),
        allow_sql_os_cmd=(
            row["allow_sql_os_cmd"] if "allow_sql_os_cmd" in row else False
        ),
        exploit_capabilities=(
            json.loads(row["exploit_capabilities_json"] or "[]")
            if "exploit_capabilities_json" in row else []),
        user_agent_mode=(row["user_agent_mode"] or "") if "user_agent_mode" in row else "",
        user_agent=(row["user_agent"] or "") if "user_agent" in row else "",
        allow_data_proof=(
            row["allow_data_proof"] if "allow_data_proof" in row else False
        ),
        secondary_auth=_load_auth(row, "secondary_auth_json"),
        primary_auth=_load_auth(row, "primary_auth_json"),
    )


def _load_auth(row, column: str) -> list:
    raw = row[column] if column in row else None
    if not raw:
        return []
    try:
        v = json.loads(raw)
        return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []
    except json.JSONDecodeError:
        return []
