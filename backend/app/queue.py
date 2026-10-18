"""Shared arq/Redis pool helpers.

Kept in its own module so both the API side (app.scans.runner,
app.api.orchestrator) and the worker (app.workers) can import the pool
without creating an import cycle (workers imports the orchestrator loop,
which imports the runner, which needs the pool).
"""
from __future__ import annotations

from typing import Optional

from arq.connections import ArqRedis, RedisSettings, create_pool

from app.config import settings

_arq_pool: Optional[ArqRedis] = None

# Dedicated queue for the long-lived orchestrator loop so it never competes with
# scan subprocess jobs for worker slots. The loop occupies a slot for the whole
# run while it awaits the scan sub-jobs it launches; on a shared pool, several
# runs would starve every scan and deadlock. The orchestrator worker reads this
# queue; the scans worker reads the default queue.
ORCHESTRATOR_QUEUE = "arq:queue:orchestrator"

# Hard ceiling arq puts on one autonomous run (OrchestratorWorkerSettings.
# job_timeout). Defined here, and imported by BOTH the worker that enforces it
# and the loop that must finish under it, so the two can never drift apart. The
# previous drift - a 6h loop budget beneath a 3h worker timeout - meant arq
# cancelled every long run mid-vuln_analysis, in the CancelledError path that
# skips exploitation, so no run on a real target ever exploited, proved or
# authored anything. The loop clamps its own deadline to this minus a finalise
# reserve (see app/orchestrator/loop.py).
ORCH_JOB_TIMEOUT_SECONDS = 6 * 60 * 60


def redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(settings.redis_url)


async def get_arq_pool() -> ArqRedis:
    """Return the shared arq pool, creating it on first use."""
    global _arq_pool
    if _arq_pool is None:
        _arq_pool = await create_pool(redis_settings())
    return _arq_pool


async def close_arq_pool() -> None:
    global _arq_pool
    if _arq_pool is not None:
        await _arq_pool.close()
        _arq_pool = None
