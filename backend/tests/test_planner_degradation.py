"""When the planner LLM cannot answer, say so.

The fallback itself is right: a planner that fails must not stop a run, so the
batch keeps its deterministic catalog order. What was wrong is that it happened
in silence - `if not client.configured: return batch` with no log at all, and a
logger.warning that only reached the container's stderr.

The operator saw a normal-looking run. The only trace was a zero in the token
panel, which is how this was actually found.
"""
import asyncio

import pytest

from app.orchestrator.planner import Planner, Task


class FakeState:
    engagement_id = "eng-1"

    async def assets(self):
        return []

    async def technologies(self):
        return []


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def emitted(monkeypatch):
    """Capture what reaches the live console."""
    seen = []

    async def fake_emit(engagement_id, etype, message, **kw):
        seen.append({"engagement_id": engagement_id, "type": etype,
                     "message": message, **kw})

    import app.orchestrator.planner as planner_mod
    monkeypatch.setattr(planner_mod.events, "emit", fake_emit)
    return seen


def test_an_unconfigured_planner_is_announced(emitted):
    p = Planner(FakeState())
    run(p._report_degraded("no API key or model configured for the planner role"))
    assert len(emitted) == 1
    msg = emitted[0]["message"]
    assert "Planner LLM not used" in msg
    assert "no API key" in msg


def test_the_message_says_the_run_still_works(emitted):
    """Otherwise the operator reads it as a failure and stops a run that is
    doing exactly what it should."""
    p = Planner(FakeState())
    run(p._report_degraded("provider unavailable: 401"))
    assert "the run continues" in emitted[0]["message"]


def test_it_reaches_the_main_console_not_the_verbose_one(emitted):
    from app import events
    p = Planner(FakeState())
    run(p._report_degraded("x"))
    assert emitted[0]["level"] == events.LEVEL_INFO


def test_it_is_said_once_per_run_not_once_per_iteration(emitted):
    """The loop re-plans every cycle; repeating this would bury the console."""
    p = Planner(FakeState())
    for _ in range(10):
        run(p._report_degraded("no API key"))
    assert len(emitted) == 1


def test_each_run_gets_its_own_notice(emitted):
    """A fresh Planner is built per run, so a later run still reports."""
    run(Planner(FakeState())._report_degraded("a"))
    run(Planner(FakeState())._report_degraded("b"))
    assert len(emitted) == 2


def test_the_reason_is_carried_through(emitted):
    p = Planner(FakeState())
    run(p._report_degraded("provider unavailable: 429 rate limited"))
    assert "429 rate limited" in emitted[0]["message"]


def test_telling_the_operator_cannot_break_planning(monkeypatch):
    """The notice is a courtesy; a broken event bus must not abort a run."""
    async def boom(*a, **kw):
        raise RuntimeError("events table gone")

    import app.orchestrator.planner as planner_mod
    monkeypatch.setattr(planner_mod.events, "emit", boom)
    p = Planner(FakeState())
    run(p._report_degraded("x"))          # must not raise
    assert p._degradation_reported is True


def test_a_fresh_planner_has_not_reported_yet():
    assert Planner(FakeState())._degradation_reported is False
