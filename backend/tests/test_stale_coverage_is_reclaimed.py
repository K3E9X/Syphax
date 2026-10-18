"""A re-run must retry injection points whose job was killed last time.

'running' and 'pending' are in COVERED_STATUSES so the planner does not
relaunch an in-flight task mid-run. But a nuclei job killed at the 1800s
timeout leaves its coverage row at 'running' forever, so the next run skipped
that (item, asset) - every timed-out injection point silently un-tested on the
retry. reset_stale_coverage clears those orphans at run start, when nothing is
in flight, and leaves terminal coverage alone.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager


from app.orchestrator import state as state_mod
from app.orchestrator.state import (COVERED_STATUSES, EngagementState,
                                    status_is_covered)


class _Conn:
    def __init__(self):
        self.sql = ""
        self.params = ()

    async def execute(self, sql, *params):
        self.sql = " ".join(sql.split())
        self.params = params
        return "DELETE 33"


def _patch_db(monkeypatch, conn):
    @asynccontextmanager
    async def _acquire():
        yield conn
    monkeypatch.setattr(state_mod.db, "acquire", _acquire)


def test_only_running_and_pending_are_deleted(monkeypatch):
    conn = _Conn()
    _patch_db(monkeypatch, conn)
    n = asyncio.run(EngagementState("eng1").reset_stale_coverage())
    assert n == 33
    assert "DELETE FROM coverage" in conn.sql
    assert "status IN ('running','pending')" in conn.sql
    # terminal statuses must NOT be touched
    for terminal in ("done", "skipped", "error"):
        assert f"'{terminal}'" not in conn.sql
    assert conn.params == ("eng1",)


def test_a_malformed_tag_does_not_raise(monkeypatch):
    class _BadConn(_Conn):
        async def execute(self, sql, *params):
            return "DELETE"          # no count
    _patch_db(monkeypatch, _BadConn())
    assert asyncio.run(EngagementState("eng1").reset_stale_coverage()) == 0


def test_an_in_flight_task_still_reads_as_covered():
    """The reclaim is a run-start sweep, not a change to the rule: WHILE a run
    is going, a 'running' task must still count as covered, or the planner
    relaunches it in a loop."""
    assert "running" in COVERED_STATUSES
    assert "pending" in COVERED_STATUSES
    assert status_is_covered("running")
    assert status_is_covered("pending")


def test_the_loop_reclaims_before_it_launches_anything():
    """It must run after state is built and before the first batch, or it
    could wipe a row this run just created."""
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    assert "reset_stale_coverage()" in src
    assert src.index("executor = Executor(state)") < src.index("reset_stale_coverage()")
    assert src.index("reset_stale_coverage()") < src.index("max_jobs = engagement")


def test_the_reclaim_never_fails_the_run():
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    block = src[src.index("reset_stale_coverage()"):
                src.index("reset_stale_coverage()") + 600]
    assert "except Exception" in block
    assert "logger.exception" in block
