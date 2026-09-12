"""Postgres data access for captured HTTP flows.

Two paths into the database on purpose:

  - async `FlowRepository` for FastAPI endpoints (asyncpg pool).
  - sync `insert_flow_sync` for the mitmproxy addon (psycopg, sync) since
    mitmdump runs in its own non-asyncio process.

Both share the same DATABASE_URL via app.config.
"""
from __future__ import annotations

import json
import logging
import threading
import queue
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app import db


logger = logging.getLogger("syphax.proxy.storage")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS flows (
    id                     TEXT PRIMARY KEY,
    "timestamp"            DOUBLE PRECISION NOT NULL,
    duration_ms            INTEGER,
    method                 TEXT NOT NULL,
    scheme                 TEXT,
    host                   TEXT NOT NULL,
    port                   INTEGER,
    path                   TEXT NOT NULL,
    url                    TEXT NOT NULL,
    request_headers_json   TEXT,
    request_body           BYTEA,
    request_content_type   TEXT,
    request_size           INTEGER,
    status_code            INTEGER,
    response_headers_json  TEXT,
    response_body          BYTEA,
    response_content_type  TEXT,
    response_size          INTEGER,
    tag                    TEXT
);

CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows("timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_flows_host      ON flows(host);
CREATE INDEX IF NOT EXISTS idx_flows_status    ON flows(status_code);
"""

db.register_schema(SCHEMA_SQL)


# -----------------------------------------------------------------------------
# Sync path (mitmproxy addon)
# -----------------------------------------------------------------------------

# --------------------------------------------------------------------------- #
# Write path for the mitmproxy addon.
#
# The addon's hooks run on the proxy's own event loop, so anything slow there
# stalls every proxied request. Opening and closing a Postgres connection per
# flow meant a full TCP + auth handshake in that hot path, and a crawl of a few
# thousand requests could exhaust max_connections. Hand the row to a single
# writer thread instead and return immediately.

_QUEUE: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue(maxsize=2000)
_writer: Optional[threading.Thread] = None
_writer_lock = threading.Lock()


def _ensure_writer() -> None:
    global _writer
    with _writer_lock:
        if _writer is None or not _writer.is_alive():
            _writer = threading.Thread(target=_drain, name="flow-writer", daemon=True)
            _writer.start()


def _drain() -> None:
    """One connection for the life of the thread, reopened if the server drops
    it. A row that cannot be written is logged and abandoned - losing a capture
    is bad, wedging the proxy is worse."""
    conn = None
    while True:
        row = _QUEUE.get()
        if row is None:                       # shutdown sentinel
            break
        for attempt in (1, 2):                # one retry on a dead connection
            try:
                if conn is None or getattr(conn, "closed", False):
                    conn = db.sync_connect()
                _write_row(conn, row)
                break
            except Exception as exc:  # noqa: BLE001
                try:
                    if conn is not None:
                        conn.close()
                except Exception:  # noqa: BLE001
                    pass
                conn = None
                if attempt == 2:
                    logger.warning("dropping captured flow %s: %s",
                                   row.get("id"), exc)


def insert_flow_sync(row: Dict[str, Any]) -> None:
    """Queue a captured flow for the writer thread. Never blocks the proxy."""
    _ensure_writer()
    try:
        _QUEUE.put_nowait(row)
    except queue.Full:
        # Under a flood, a dropped capture beats a stalled proxy.
        logger.warning("flow queue full; dropping capture for %s", row.get("url"))




def _write_row(conn, row: Dict[str, Any]) -> None:
    """Insert/update one flow on an already-open connection."""
    if True:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO flows (
                    id, "timestamp", duration_ms, method, scheme, host, port, path, url,
                    request_headers_json, request_body, request_content_type, request_size,
                    status_code,
                    response_headers_json, response_body, response_content_type, response_size,
                    tag
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s,
                    %s, %s, %s, %s,
                    %s
                )
                ON CONFLICT (id) DO UPDATE SET
                    "timestamp"            = EXCLUDED."timestamp",
                    duration_ms            = EXCLUDED.duration_ms,
                    method                 = EXCLUDED.method,
                    scheme                 = EXCLUDED.scheme,
                    host                   = EXCLUDED.host,
                    port                   = EXCLUDED.port,
                    path                   = EXCLUDED.path,
                    url                    = EXCLUDED.url,
                    request_headers_json   = EXCLUDED.request_headers_json,
                    request_body           = EXCLUDED.request_body,
                    request_content_type   = EXCLUDED.request_content_type,
                    request_size           = EXCLUDED.request_size,
                    status_code            = EXCLUDED.status_code,
                    response_headers_json  = EXCLUDED.response_headers_json,
                    response_body          = EXCLUDED.response_body,
                    response_content_type  = EXCLUDED.response_content_type,
                    response_size          = EXCLUDED.response_size,
                    tag                    = EXCLUDED.tag
                """,
                (
                    row["id"],
                    row["timestamp"],
                    row.get("duration_ms"),
                    row["method"],
                    row.get("scheme"),
                    row["host"],
                    row.get("port"),
                    row["path"],
                    row["url"],
                    row.get("request_headers_json"),
                    row.get("request_body"),
                    row.get("request_content_type"),
                    row.get("request_size"),
                    row.get("status_code"),
                    row.get("response_headers_json"),
                    row.get("response_body"),
                    row.get("response_content_type"),
                    row.get("response_size"),
                    row.get("tag"),
                ),
            )
        conn.commit()


def init_schema_sync() -> None:
    """Sync schema bootstrap, callable from the mitmproxy addon before any
    insert when the API process has not yet started."""
    conn = db.sync_connect()
    try:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Async path (FastAPI endpoints)
# -----------------------------------------------------------------------------

MAX_BODY_PREVIEW = 256 * 1024  # bytes returned by /flows/{id}


@dataclass
class FlowSummary:
    id: str
    timestamp: float
    method: str
    host: str
    path: str
    url: str
    status_code: Optional[int]
    response_size: Optional[int]
    duration_ms: Optional[int]
    request_content_type: Optional[str]
    response_content_type: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


class FlowRepository:
    """Read/write captured HTTP flows. Owns no connection; borrows from the pool."""

    async def list_flows(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
        host: Optional[str] = None,
        method: Optional[str] = None,
        status_min: Optional[int] = None,
        status_max: Optional[int] = None,
        search: Optional[str] = None,
    ) -> List[FlowSummary]:
        where: List[str] = []
        params: List[Any] = []
        i = 1

        def ph() -> str:
            nonlocal i
            cur = i
            i += 1
            return f"${cur}"

        if host:
            where.append(f"host = {ph()}")
            params.append(host)
        if method:
            where.append(f"method = {ph()}")
            params.append(method.upper())
        if status_min is not None:
            where.append(f"status_code >= {ph()}")
            params.append(status_min)
        if status_max is not None:
            where.append(f"status_code <= {ph()}")
            params.append(status_max)
        if search:
            where.append(f"url ILIKE {ph()}")
            params.append(f"%{search}%")

        where_sql = f" WHERE {' AND '.join(where)}" if where else ""
        limit_ph = ph()
        offset_ph = ph()
        params.extend([limit, offset])

        sql = (
            'SELECT id, "timestamp", method, host, path, url, status_code, '
            "response_size, duration_ms, request_content_type, response_content_type "
            f'FROM flows{where_sql} ORDER BY "timestamp" DESC LIMIT {limit_ph} OFFSET {offset_ph}'
        )

        async with db.acquire() as conn:
            rows = await conn.fetch(sql, *params)

        return [FlowSummary(**dict(row)) for row in rows]

    async def count_flows(self) -> int:
        async with db.acquire() as conn:
            return int(await conn.fetchval("SELECT COUNT(*) FROM flows"))

    async def list_hosts(self) -> List[Dict[str, Any]]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT host, COUNT(*) AS count FROM flows GROUP BY host ORDER BY count DESC"
            )
        return [{"host": row["host"], "count": int(row["count"])} for row in rows]

    async def get_flow(self, flow_id: str) -> Optional[Dict[str, Any]]:
        async with db.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM flows WHERE id = $1", flow_id)
        if row is None:
            return None

        data = dict(row)

        # Parse JSON headers
        data["request_headers"] = _safe_json(data.pop("request_headers_json"))
        data["response_headers"] = _safe_json(data.pop("response_headers_json"))

        # asyncpg returns BYTEA as bytes already (memoryview in some versions);
        # normalize to bytes so the preview helper can slice it.
        req_body = data.pop("request_body")
        resp_body = data.pop("response_body")
        if isinstance(req_body, memoryview):
            req_body = bytes(req_body)
        if isinstance(resp_body, memoryview):
            resp_body = bytes(resp_body)

        data["request_body_preview"] = _body_preview(req_body, data.get("request_content_type"))
        data["response_body_preview"] = _body_preview(resp_body, data.get("response_content_type"))

        return data

    async def delete_all(self) -> int:
        async with db.acquire() as conn:
            result = await conn.execute("DELETE FROM flows")
        # result is "DELETE <count>"
        try:
            return int(result.split()[-1])
        except (IndexError, ValueError):
            return 0


def _safe_json(raw: Optional[str]) -> List[List[str]]:
    if not raw:
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return []


def _body_preview(body: Optional[bytes], content_type: Optional[str]) -> Dict[str, Any]:
    """Return a safe, size-capped view of a body for the UI."""
    if body is None:
        return {"present": False, "size": 0}

    size = len(body)
    truncated = size > MAX_BODY_PREVIEW
    view = body[:MAX_BODY_PREVIEW]

    is_text = False
    if content_type:
        lower = content_type.lower()
        is_text = (
            lower.startswith("text/")
            or "json" in lower
            or "xml" in lower
            or "javascript" in lower
            or "html" in lower
            or "form-urlencoded" in lower
        )

    if is_text:
        try:
            return {
                "present": True,
                "size": size,
                "truncated": truncated,
                "encoding": "text",
                "text": view.decode("utf-8", errors="replace"),
            }
        except Exception:
            pass

    hex_cap = 8 * 1024
    return {
        "present": True,
        "size": size,
        "truncated": truncated,
        "encoding": "hex",
        "hex": view[:hex_cap].hex(),
        "hex_truncated": size > hex_cap,
    }
