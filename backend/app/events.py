"""Append-only engagement event stream (spec §10 live events).

The orchestrator (running in the worker) writes typed events here; the API's
WebSocket endpoint tails the table and pushes new rows to the browser. Using
Postgres as the bus (instead of Redis pub/sub) keeps the worker->API hop
trivial and survives reconnects: a client can backfill from any event id.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from app import db

logger = logging.getLogger("syphax.events")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id            BIGSERIAL PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    run_id        TEXT,
    ts            DOUBLE PRECISION NOT NULL,
    type          TEXT NOT NULL,
    level         TEXT NOT NULL DEFAULT 'info',
    message       TEXT,
    data_json     TEXT
);
ALTER TABLE events ADD COLUMN IF NOT EXISTS level TEXT NOT NULL DEFAULT 'info';
CREATE INDEX IF NOT EXISTS idx_events_engagement ON events(engagement_id, id);
"""

db.register_schema(SCHEMA_SQL)

# Event levels: the main agent console shows 'info'; the verbose console
# shows everything (info + verbose).
LEVEL_INFO = "info"
LEVEL_VERBOSE = "verbose"

# Typed event names the UI knows how to render.
PHASE_CHANGED = "phase_changed"
RUN_STARTED = "run_started"
RUN_FINISHED = "run_finished"
TASK_LAUNCHED = "task_launched"
TASK_SKIPPED = "task_skipped"
COMMAND = "command"
JOB_DONE = "job_done"
BATCH_DONE = "batch_done"
ASSET_FOUND = "asset_found"
FINGERPRINT = "fingerprint"
FINDING = "finding"
VALIDATED = "validated"
CHAIN_BUILT = "chain_built"
APPROVAL_REQUIRED = "approval_required"
APPROVAL_RESOLVED = "approval_resolved"
THOUGHT = "agent_thought"
ERROR = "error"


async def emit(
    engagement_id: str,
    type_: str,
    message: str = "",
    *,
    run_id: Optional[str] = None,
    level: str = LEVEL_INFO,
    **data: Any,
) -> None:
    """Append one event. Never raises into the caller (best-effort stream)."""
    try:
        async with db.acquire() as conn:
            await conn.execute(
                "INSERT INTO events (engagement_id, run_id, ts, type, level, message, data_json) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7)",
                engagement_id, run_id, time.time(), type_, level, message,
                json.dumps(data, default=str) if data else None,
            )
    except Exception:  # noqa: BLE001
        logger.exception("event emit failed: %s", type_)


def _row_to_event(r) -> Dict[str, Any]:
    data = {}
    if r["data_json"]:
        try:
            data = json.loads(r["data_json"])
        except json.JSONDecodeError:
            data = {}
    return {
        "id": r["id"], "engagement_id": r["engagement_id"], "run_id": r["run_id"],
        "ts": r["ts"], "type": r["type"],
        "level": r["level"] if "level" in r else "info",
        "message": r["message"], "data": data,
    }


async def list_since(
    engagement_id: str, after_id: int = 0, *, limit: int = 500
) -> List[Dict[str, Any]]:
    """Forward cursor: the next `limit` events after `after_id`, oldest first.
    This is the live-tail path - poll with the last id you saw."""
    async with db.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM events WHERE engagement_id=$1 AND id > $2 ORDER BY id LIMIT $3",
            engagement_id, after_id, limit,
        )
    return [_row_to_event(r) for r in rows]


async def list_recent(
    engagement_id: str, *, limit: int = 500, before_id: Optional[int] = None
) -> List[Dict[str, Any]]:
    """Backward cursor: the most recent `limit` events, newest first. With
    `before_id`, the events just older than it - how the UI pages back through
    a long run from its END, which the forward cursor from id 0 could never
    reach without walking the whole stream."""
    async with db.acquire() as conn:
        if before_id is not None:
            rows = await conn.fetch(
                "SELECT * FROM events WHERE engagement_id=$1 AND id < $2 "
                "ORDER BY id DESC LIMIT $3",
                engagement_id, before_id, limit,
            )
        else:
            rows = await conn.fetch(
                "SELECT * FROM events WHERE engagement_id=$1 "
                "ORDER BY id DESC LIMIT $2",
                engagement_id, limit,
            )
    return [_row_to_event(r) for r in rows]


async def count_events(engagement_id: str) -> int:
    """How many events this engagement has, so the UI can show progress and
    know whether more pages exist."""
    async with db.acquire() as conn:
        return int(await conn.fetchval(
            "SELECT COUNT(*) FROM events WHERE engagement_id=$1", engagement_id))
