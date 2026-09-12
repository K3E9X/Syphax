"""Network mode shared across containers.

NetworkPrivacyManager keeps its state in a module global, which is correct for
one process and wrong for this deployment: the API sets a proxy in the backend
container, while the scans are submitted from the worker and orchestrator
containers, each holding their own freshly-constructed manager. A proxy chosen
in the UI therefore reached nothing but the backend, and with REQUIRE_VPN on,
orchestrator-submitted scans were rejected as "no VPN or proxy configured"
while the UI showed connected.

One row in Postgres, which every container already shares. The VPN case no
longer needs this (worker/orchestrator share the backend's network namespace),
but the proxy is per-process configuration and does.
"""
from __future__ import annotations

import logging
import time
from typing import Optional, Tuple

from app import db

logger = logging.getLogger("syphax.network.shared_state")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS network_state (
    id         INTEGER PRIMARY KEY DEFAULT 1,
    mode       TEXT NOT NULL,
    proxy_url  TEXT,
    updated_at DOUBLE PRECISION NOT NULL,
    CONSTRAINT network_state_single_row CHECK (id = 1)
);
"""

db.register_schema(SCHEMA_SQL)


async def publish(mode: str, proxy_url: Optional[str]) -> None:
    """Make this container's network mode visible to the others."""
    try:
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO network_state (id, mode, proxy_url, updated_at)
                VALUES (1, $1, $2, $3)
                ON CONFLICT (id) DO UPDATE
                   SET mode = EXCLUDED.mode,
                       proxy_url = EXCLUDED.proxy_url,
                       updated_at = EXCLUDED.updated_at
                """,
                mode, proxy_url or None, time.time(),
            )
    except Exception:  # noqa: BLE001 - never fail a connect on bookkeeping
        logger.exception("could not publish network state")


async def read() -> Tuple[Optional[str], Optional[str]]:
    """(mode, proxy_url) as last published by any container, or (None, None)."""
    try:
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT mode, proxy_url FROM network_state WHERE id = 1")
    except Exception:  # noqa: BLE001 - a missing table must not block a scan
        return (None, None)
    if row is None:
        return (None, None)
    return (row["mode"], row["proxy_url"])
