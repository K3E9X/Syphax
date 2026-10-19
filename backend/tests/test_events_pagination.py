"""The events endpoint must page both ways and bound its limit.

It capped at 500, forward from id 0 only, so the UI saw the first ~2.5 min of a
run and could never reach the end of a long one. Now: a bounded limit, a
descending/tail direction with a backward cursor, and a total so the UI knows
how much exists.
"""
from __future__ import annotations

import asyncio

from app.api import orchestrator as api


def _wire(monkeypatch, *, recent=None, since=None, total=0):
    calls = {}
    async def _list_since(eng, after_id, *, limit=500):
        calls["since"] = {"after_id": after_id, "limit": limit}
        return since or []
    async def _list_recent(eng, *, limit=500, before_id=None):
        calls["recent"] = {"before_id": before_id, "limit": limit}
        return recent or []
    async def _count(eng):
        return total
    monkeypatch.setattr(api.events_log, "list_since", _list_since)
    monkeypatch.setattr(api.events_log, "list_recent", _list_recent)
    monkeypatch.setattr(api.events_log, "count_events", _count)
    return calls


def test_default_is_the_forward_tail(monkeypatch):
    calls = _wire(monkeypatch, since=[{"id": 1}], total=7)
    out = asyncio.run(api.events_backfill("e1", after_id=3))
    assert "since" in calls and "recent" not in calls
    assert calls["since"]["after_id"] == 3
    assert out["total"] == 7
    assert out["order"] == "asc"


def test_desc_uses_the_backward_cursor(monkeypatch):
    calls = _wire(monkeypatch, recent=[{"id": 9}], total=9)
    out = asyncio.run(api.events_backfill("e1", order="desc", before_id=100))
    assert "recent" in calls and "since" not in calls
    assert calls["recent"]["before_id"] == 100
    assert out["items"] == [{"id": 9}]


def test_the_limit_is_clamped(monkeypatch):
    calls = _wire(monkeypatch)
    asyncio.run(api.events_backfill("e1", limit=100000))
    assert calls["since"]["limit"] == 2000
    calls = _wire(monkeypatch)
    asyncio.run(api.events_backfill("e1", limit=0))
    assert calls["since"]["limit"] == 500        # 0 means "unspecified" -> default


def test_the_total_count_is_returned(monkeypatch):
    _wire(monkeypatch, since=[{"id": 1}, {"id": 2}], total=4210)
    out = asyncio.run(api.events_backfill("e1"))
    assert out["total"] == 4210
    assert out["count"] == 2


def test_list_recent_pages_back_from_the_end():
    """SQL check: with before_id it filters id < before_id DESC; without, it is
    the plain tail."""
    import inspect

    from app import events
    src = inspect.getsource(events.list_recent)
    assert "ORDER BY id DESC" in src
    assert "id < $2" in src
