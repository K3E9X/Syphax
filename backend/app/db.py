"""Postgres connection helpers.

Two code paths share the same DATABASE_URL:

  - async `get_pool()` / `acquire()` for FastAPI endpoints and the arq worker
    (asyncpg pool).
  - sync `sync_connect()` for the mitmproxy addon, which runs in its own
    non-asyncio process and writes a flow per response.

Schema bootstrap is centralised here: every domain module exposes a
`SCHEMA_SQL` string and registers it via `register_schema()` so that
`init_db()` can run them in order at startup.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, AsyncIterator, List, Optional

if TYPE_CHECKING:  # annotations only; asyncpg is imported lazily in get_pool()
    import asyncpg

from app.config import settings

# asyncpg is NOT imported at module top. The mitmproxy addon loads this module
# for the sync psycopg path only (sync_connect / register_schema) in an image
# that deliberately ships without asyncpg; a top-level import there crash-looped
# the proxy with ModuleNotFoundError. The async pool imports it on first use.

_pool: Optional[asyncpg.Pool] = None
_schemas: List[str] = []


def register_schema(sql: str) -> None:
    """Register a CREATE TABLE ... block to run at startup. Idempotent."""
    if sql not in _schemas:
        _schemas.append(sql)


async def get_pool() -> "asyncpg.Pool":
    global _pool
    if _pool is None:
        import asyncpg
        _pool = await asyncpg.create_pool(
            dsn=settings.database_url,
            min_size=1,
            max_size=10,
            command_timeout=60,
        )
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


@asynccontextmanager
async def acquire() -> AsyncIterator[asyncpg.Connection]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        yield conn


async def init_db() -> None:
    """Run every registered schema. Safe to call repeatedly."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        for sql in _schemas:
            await conn.execute(sql)


# ----- sync path for processes that are not asyncio-native -----

def sync_connect():
    """Return a sync psycopg3 connection. Caller is responsible for closing."""
    import psycopg
    return psycopg.connect(settings.database_url, autocommit=False)
