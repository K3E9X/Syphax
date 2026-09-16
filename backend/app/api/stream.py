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


async def authorize_socket(websocket: WebSocket) -> bool:
    """The gate, for a WebSocket. Same policy as the HTTP middleware."""
    from app.auth import policy, storage, tokens
    from app.config import settings as _settings

    user = None
    token = websocket.cookies.get(tokens.COOKIE_NAME, "")
    if token:
        try:
            user = await storage.resolve_session(token)
        except Exception:  # noqa: BLE001 - database down is not authorisation
            user = None
    try:
        has_users = await storage.has_users()
    except Exception:  # noqa: BLE001
        return False

    decision = policy.decide(
        path=websocket.url.path,
        has_users=has_users,
        session_user=user,
        provided_key=policy.extract_key(websocket.headers,
                                        websocket.query_params.get("key", "")),
        expected_key=_settings.api_key,
    )
    return decision.allow


@router.websocket("/ws/engagements/{engagement_id}/stream")
async def engagement_stream(websocket: WebSocket, engagement_id: str) -> None:
    # The HTTP middleware does not cover the WebSocket handshake, so the same
    # decision is made here, before accept(), so an unauthorised client never
    # gets a socket. A browser cannot set headers on a handshake but it DOES
    # send same-origin cookies, so the session works unmodified; the ?key=
    # fallback stays for scripts.
    if not await authorize_socket(websocket):
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
