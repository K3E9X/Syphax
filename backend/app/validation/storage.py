"""Postgres storage for validated findings and kill-chains."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Dict, List, Optional

from app import db
from app.validation.models import ValidatedFinding

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS validated_findings (
    id             TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL,
    source_job_id  TEXT,
    tool           TEXT,
    vuln_class     TEXT,
    severity       TEXT,
    title          TEXT,
    target         TEXT,
    status         TEXT NOT NULL,
    confidence     DOUBLE PRECISION NOT NULL,
    method         TEXT,
    poc            TEXT,
    evidence       TEXT,
    chain_id       TEXT,
    metadata_json  TEXT,
    created_at     DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vf_engagement ON validated_findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_vf_status     ON validated_findings(status);

CREATE TABLE IF NOT EXISTS chains (
    id             TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT,
    summary        TEXT,
    steps_json     TEXT,
    created_at     DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chains_engagement ON chains(engagement_id);
"""

db.register_schema(SCHEMA_SQL)


def new_vf_id() -> str:
    return f"vf_{int(time.time() * 1000)}_{secrets.token_hex(2)}"


def stable_vf_id(engagement_id: str, tool: str, title: str, target: str) -> str:
    """The id a finding keeps across re-validations.

    replace_for_engagement is a DELETE + INSERT, and with a time-and-random id
    every re-validation renamed every row. Anything holding a reference was
    orphaned - staged_pocs.finding_id above all. A PoC staged on the first run
    pointed at an id that no longer existed, so when it ran clean the proof was
    written against a row that was not there: exit 0, nothing confirmed, no
    event, nothing in the log. The operator saw a PoC marked "executed" and a
    finding still sitting at "likely".
    (And _argv_for, resolving the same dead id, derived no target and ran the
    PoC with no arguments, which is the usage-error exit 2 that
    app/sandbox/invocation.py exists to prevent.)

    Derived from the same identity the dedup loop uses - tool, title, target -
    scoped to the engagement so two engagements against the same host do not
    collide on one primary key.
    """
    ident = "\x00".join([
        str(engagement_id or ""), str(tool or ""),
        str(title or ""), str(target or ""),
    ])
    return "vf_" + hashlib.sha1(ident.encode("utf-8", "replace")).hexdigest()[:20]


class ValidatedFindingRepository:
    async def replace_for_engagement(self, engagement_id: str, items: List[ValidatedFinding]) -> None:
        """Validation is idempotent per run: wipe then insert the fresh set."""
        async with db.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "DELETE FROM validated_findings WHERE engagement_id=$1", engagement_id
                )
                for v in items:
                    await conn.execute(
                        """
                        INSERT INTO validated_findings (
                            id, engagement_id, source_job_id, tool, vuln_class, severity,
                            title, target, status, confidence, method, poc, evidence,
                            chain_id, metadata_json, created_at
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
                        """,
                        v.id, v.engagement_id, v.source_job_id, v.tool, v.vuln_class,
                        v.severity, v.title, v.target, v.status, v.confidence, v.method,
                        v.poc, v.evidence, v.chain_id, json.dumps(v.metadata), v.created_at,
                    )

    async def list(self, engagement_id: str) -> List[ValidatedFinding]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM validated_findings WHERE engagement_id=$1 "
                "ORDER BY confidence DESC, severity",
                engagement_id,
            )
        return [_row_to_vf(r) for r in rows]

    async def get(self, vf_id: str) -> Optional[ValidatedFinding]:
        async with db.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM validated_findings WHERE id=$1", vf_id)
        return _row_to_vf(row) if row else None

    async def list_all(self) -> List[ValidatedFinding]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM validated_findings ORDER BY created_at DESC")
        return [_row_to_vf(r) for r in rows]

    async def set_chain(self, vf_id: str, chain_id: str) -> None:
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE validated_findings SET chain_id=$1 WHERE id=$2", chain_id, vf_id
            )

    async def set_metadata(self, vf_id: str, patch: Dict[str, Any]) -> None:
        """Merge keys into a finding's metadata, preserving what is there.

        Read-modify-write rather than a jsonb merge because metadata_json is a
        TEXT column; the judge is the only writer and runs one finding at a
        time, so there is no concurrent update to lose.
        """
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT metadata_json FROM validated_findings WHERE id=$1", vf_id)
            if row is None:
                return
            meta = json.loads(row["metadata_json"] or "{}")
            if not isinstance(meta, dict):
                meta = {}
            meta.update(patch)
            await conn.execute(
                "UPDATE validated_findings SET metadata_json=$1 WHERE id=$2",
                json.dumps(meta), vf_id,
            )

    async def update_verdict(self, vf_id: str, *, status: str, confidence: float,
                             method: str) -> None:
        """Adjust a finding's verdict (used by the LLM judge pass)."""
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE validated_findings SET status=$1, confidence=$2, method=$3 "
                "WHERE id=$4",
                status, confidence, method, vf_id,
            )

    async def summary(self, engagement_id: str) -> Dict[str, int]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT status, COUNT(*) AS n FROM validated_findings "
                "WHERE engagement_id=$1 GROUP BY status",
                engagement_id,
            )
        return {r["status"]: int(r["n"]) for r in rows}


class ChainRepository:
    async def replace_for_engagement(self, engagement_id: str, chains: List[Dict[str, Any]]) -> None:
        async with db.acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM chains WHERE engagement_id=$1", engagement_id)
                for c in chains:
                    await conn.execute(
                        """
                        INSERT INTO chains (id, engagement_id, title, severity, summary, steps_json, created_at)
                        VALUES ($1,$2,$3,$4,$5,$6,$7)
                        """,
                        c["id"], engagement_id, c["title"], c.get("severity"),
                        c.get("summary"), json.dumps(c.get("steps", [])), time.time(),
                    )

    async def list(self, engagement_id: str) -> List[Dict[str, Any]]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM chains WHERE engagement_id=$1 ORDER BY created_at", engagement_id
            )
        out = []
        for r in rows:
            try:
                steps = json.loads(r["steps_json"] or "[]")
            except json.JSONDecodeError:
                steps = []
            out.append({
                "id": r["id"], "title": r["title"], "severity": r["severity"],
                "summary": r["summary"], "steps": steps, "created_at": r["created_at"],
            })
        return out


def _row_to_vf(row) -> ValidatedFinding:
    try:
        meta = json.loads(row["metadata_json"] or "{}")
    except json.JSONDecodeError:
        meta = {}
    return ValidatedFinding(
        id=row["id"], engagement_id=row["engagement_id"], source_job_id=row["source_job_id"],
        tool=row["tool"], vuln_class=row["vuln_class"], severity=row["severity"],
        title=row["title"], target=row["target"], status=row["status"],
        confidence=row["confidence"], method=row["method"], poc=row["poc"] or "",
        evidence=row["evidence"] or "", chain_id=row["chain_id"], metadata=meta,
        created_at=row["created_at"],
    )
