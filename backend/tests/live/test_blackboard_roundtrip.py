"""Blackboard post/dedup/read against real Postgres.

Skips without a real DATABASE_URL, like the rest of tests/live. The pure-logic
half is in tests/test_blackboard.py.
"""
from __future__ import annotations

import asyncio
import os
import uuid

import pytest


def _db_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    return "" if (not url or "test:test@" in url) else url


pytestmark = pytest.mark.skipif(not _db_url(), reason="needs a real DATABASE_URL")


async def _run():
    import app.events  # noqa: F401 - register schema
    import app.orchestrator.blackboard  # noqa: F401 - register schema
    from app import db
    from app.orchestrator.blackboard import (CREDENTIAL, SECRET,
                                             UNAUTH_ENDPOINT, Blackboard)

    await db.init_db()
    eng = f"bb-{uuid.uuid4().hex[:8]}"
    board = Blackboard(eng)

    first = await board.post(CREDENTIAL, "admin@https://t/login",
                             data={"username": "admin"}, source="auth-brute",
                             confidence=0.9)
    again = await board.post(CREDENTIAL, "admin@https://t/login",
                             source="auth-brute", confidence=0.95)
    await board.post(UNAUTH_ENDPOINT, "https://t/api/v1/users",
                     source="api_inventory", confidence=0.8)
    await board.post(SECRET, "AKIA_LEAKED_KEY", source="js-recon",
                     confidence=0.7)
    await board.post("injectable", "", source="x")   # empty value ignored

    leads = await board.leads()
    identities = await board.identities()
    cred = next(l for l in leads if l.kind == CREDENTIAL)
    await board.mark_consumed(cred.id, "auth-agent")
    cred_after = next(l for l in await board.leads() if l.id == cred.id)

    await db.close_pool()
    return {"first": first, "again": again, "n": len(leads),
            "idents": sorted({l.kind for l in identities}),
            "cred_conf": cred.confidence, "consumed": cred_after.consumed_by}


def test_post_dedups_and_reads_back():
    r = asyncio.run(_run())
    assert r["first"] is True          # a new lead
    assert r["again"] is False         # same (kind, value) is not new
    assert r["n"] == 3                 # empty value was ignored
    assert r["idents"] == ["credential", "secret"]
    assert r["cred_conf"] == 0.95      # re-post lifted confidence
    assert r["consumed"] == ["auth-agent"]
