"""Fresh-start reset.

With `reset_on_start` enabled the backend truncates every scan artefact at
startup, so a restart begins from a clean slate instead of carrying the
previous run's jobs, findings and captured traffic forward.

What is deliberately NOT wiped by default:

  engagements   The authorization scope. Losing it means the next scan has no
                record of what you were allowed to test, and submit()'s scope
                gate would reject everything anyway.
  audit_log     The trail of what was run against whom. On an authorized
                engagement this is the evidence that you stayed in scope; it
                should outlive a container restart.
  settings      Runtime settings saved from the UI (API keys included), which
                are re-applied on boot by settings_store.

Both exclusions have their own flag for when you really do want everything
gone. Truncation happens after init_db() so the tables are guaranteed to
exist, and TRUNCATE ... CASCADE handles the foreign keys between them.
"""
from __future__ import annotations

import logging
from typing import List

from app import db
from app.config import settings

logger = logging.getLogger("syphax.maintenance")

# Scan artefacts: everything produced by running the tool, safe to drop.
TRANSIENT_TABLES: List[str] = [
    "jobs",
    "flows",
    "events",
    "runs",
    "approvals",
    "validated_findings",
    "chains",
    "finding_triage",
    "assets",
    "fingerprints",
    "coverage",
    "llm_usage",
    "leads",
]


async def reset_transient_data() -> List[str]:
    """Truncate scan artefacts. Returns the tables actually cleared."""
    tables = list(TRANSIENT_TABLES)
    if settings.reset_engagements_on_start:
        tables.append("engagements")
    if settings.reset_audit_on_start:
        tables.append("audit_log")

    cleared: List[str] = []
    async with db.acquire() as conn:
        for table in tables:
            try:
                # CASCADE because findings/chains reference jobs and engagements.
                await conn.execute(f"TRUNCATE TABLE {table} CASCADE")
                cleared.append(table)
            except Exception as exc:  # noqa: BLE001 - table may not exist yet
                logger.debug("skipped %s: %s", table, exc)

    logger.info("fresh start: cleared %d tables (%s)", len(cleared), ", ".join(cleared))
    return cleared


async def reset_job_queue() -> int:
    """Drop queued/deferred arq jobs.

    Redis runs with appendonly on and its own named volume, so the queue
    outlives the containers. Without this, a restart resurrects jobs whose rows
    reset_transient_data() just deleted: the worker picks them up, fails to find
    the job record, and the run looks haunted. Returns the number of keys removed.
    """
    try:
        from arq.connections import RedisSettings, create_pool

        redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
        try:
            keys = []
            # arq namespaces everything it owns under these prefixes.
            for pattern in ("arq:queue*", "arq:job:*", "arq:result:*", "arq:in-progress:*"):
                keys.extend(await redis.keys(pattern))
            if keys:
                await redis.delete(*keys)
            logger.info("fresh start: dropped %d queued job keys", len(keys))
            return len(keys)
        finally:
            await redis.aclose()
    except Exception as exc:  # noqa: BLE001 - never block boot on the queue
        logger.warning("could not clear the job queue: %s", exc)
        return 0
