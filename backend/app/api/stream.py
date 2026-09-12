"""WebSocket live event stream for an engagement (spec §10).

Tails the append-only `events` table and pushes new rows to the browser.
Polling Postgres (every ~1s) instead of Redis pub/sub keeps the worker->API
hop trivial and lets a client backfill from any event id on reconnect.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app import events as events_log

router = APIRouter(tags=["stream"])

logger = logging.getLogger("syphax.stream")

POLL_INTERVAL = 1.0


@router.websocket("/ws/engagements/{engagement_id}/stream")
async def engagement_stream(websocket: WebSocket, engagement_id: str) -> None:
    # The HTTP middleware does not cover the WebSocket handshake, and a browser
    # cannot set headers on one - so the key travels as ?key= here. Refuse
    # before accept() so an unauthorised client never gets a socket.
    from app.api_auth import key_ok
    from app.config import settings as _settings
    if _settings.api_key and not key_ok(websocket.query_params.get("key", ""),
                                        _settings.api_key):
        await websocket.close(code=1008)   # policy violation
        return
    await websocket.accept()
    # Allow the client to resume from a known id: ?after=<id>
    try:
        after_id = int(websocket.query_params.get("after", "0"))
    except (TypeError, ValueError):
        after_id = 0

    try:
        while True:
            events = await events_log.list_since(engagement_id, after_id, limit=200)
            for ev in events:
                await websocket.send_json(ev)
                after_id = ev["id"]
            await asyncio.sleep(POLL_INTERVAL)
    except WebSocketDisconnect:
        return
    except Exception:  # noqa: BLE001
        logger.exception("stream error for engagement %s", engagement_id)
        try:
            await websocket.close()
        except Exception:  # noqa: BLE001
            pass
