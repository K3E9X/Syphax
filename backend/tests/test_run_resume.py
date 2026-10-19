"""Reclaiming an interrupted run.

If the worker dies mid-run the row stays at 'running' forever, and start_run's
"one active run" guard then refuses every new run on that engagement with a 409
that never clears. Staleness is what tells a dead worker apart from a loop
legitimately waiting on a slow batch - so it has to allow for the longest
legitimate wait (ITERATION_WAIT_CAP, 45 min) without allowing forever.
"""
import time

from app.orchestrator.runs import STALE_AFTER_SECONDS, Run, is_stale


def test_finished_runs_are_never_stale():
    for status in ("completed", "failed", "stopped"):
        assert not is_stale(status, heartbeat_at=None)
        assert not is_stale(status, heartbeat_at=0.0)


def test_a_beating_run_is_not_stale():
    now = time.time()
    assert not is_stale("running", heartbeat_at=now, now=now)
    # still inside the window: a long batch wait is legitimate
    assert not is_stale("running", heartbeat_at=now - STALE_AFTER_SECONDS + 60, now=now)


def test_a_silent_run_goes_stale():
    now = time.time()
    assert is_stale("running", heartbeat_at=now - STALE_AFTER_SECONDS - 1, now=now)
    assert is_stale("queued", heartbeat_at=now - STALE_AFTER_SECONDS - 1, now=now)


def test_a_run_that_never_beat_is_stale():
    # Predates the column, or died before its first iteration. Either way it
    # must not hold the engagement hostage.
    assert is_stale("running", heartbeat_at=None)


def test_stale_window_exceeds_the_max_heartbeat_gap():
    """The stale window must be larger than the longest a HEALTHY run goes
    between heartbeats, or the reaper would reap a live run.

    It used to have to exceed ITERATION_WAIT_CAP (45min), because a batch could
    sit in _wait_for_jobs that long without a heartbeat. Now the wait loop
    heartbeats on every poll (POLL_INTERVAL), so the max gap is a few seconds
    and STALE only has to clear that - which is why it could drop from 135min
    to 10min and let the reaper close a crashed run within minutes instead of
    hours. The guarantee that makes this safe is the heartbeat in the wait
    loop, asserted here directly."""
    import inspect

    from app.orchestrator import loop
    assert STALE_AFTER_SECONDS > loop.POLL_INTERVAL * 20
    assert "runs.heartbeat(run_id)" in inspect.getsource(loop._wait_for_jobs)


def test_run_payload_exposes_staleness_to_the_ui():
    run = Run(id="r1", engagement_id="e1", status="running", heartbeat_at=None)
    assert run.to_public()["stale"] is True
    run.heartbeat_at = time.time()
    assert run.to_public()["stale"] is False
