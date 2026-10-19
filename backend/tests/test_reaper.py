"""A periodic reaper must close zombie runs and abort their orphaned scan jobs.

reclaim_stale only ran from start_run, so a run whose loop died (worker crash;
arq max_tries=1 = no requeue) stayed 'running' until the next run on that
engagement - and its nuclei/sqlmap kept being fed to the scans worker for up to
45min each with no loop to ingest them. The reaper closes both on a schedule.
"""
from __future__ import annotations

import asyncio
import inspect

from app import workers
from app.scans.models import Job, JobStatus


def _job(jid, eng):
    return Job(id=jid, tool="nuclei", target="http://t/", args=[],
               status=JobStatus.RUNNING, created_at=0.0, engagement_id=eng)


def test_the_reaper_closes_stale_runs_and_aborts_only_orphan_jobs(monkeypatch):
    aborted = []

    class _Runs:
        async def reclaim_all_stale(self):
            return 2
        async def active_engagement_ids(self):
            return {"live"}        # only this engagement has a running run

    class _Jobs:
        async def unfinished_scan_jobs(self):
            return [_job("a", "dead"), _job("b", "dead"), _job("c", "live")]

    class _Runner:
        async def cancel(self, jid):
            aborted.append(jid)
            return True

    monkeypatch.setattr("app.orchestrator.runs.RunRepository", lambda: _Runs())
    monkeypatch.setattr("app.scans.storage.JobRepository", lambda: _Jobs())
    monkeypatch.setattr("app.scans.runner.get_runner", lambda: _Runner())

    out = asyncio.run(workers.reaper({}))
    assert out == {"runs_reclaimed": 2, "jobs_aborted": 2}
    # the live engagement's job is NEVER aborted
    assert set(aborted) == {"a", "b"}
    assert "c" not in aborted


def test_a_job_with_no_engagement_is_left_alone(monkeypatch):
    """A manual scan (no run behind it) must not be reaped."""
    aborted = []

    class _Runs:
        async def reclaim_all_stale(self):
            return 0
        async def active_engagement_ids(self):
            return set()

    class _Jobs:
        async def unfinished_scan_jobs(self):
            return [_job("manual", None)]

    class _Runner:
        async def cancel(self, jid):
            aborted.append(jid)
            return True

    monkeypatch.setattr("app.orchestrator.runs.RunRepository", lambda: _Runs())
    monkeypatch.setattr("app.scans.storage.JobRepository", lambda: _Jobs())
    monkeypatch.setattr("app.scans.runner.get_runner", lambda: _Runner())
    out = asyncio.run(workers.reaper({}))
    assert aborted == []
    assert out["jobs_aborted"] == 0


def test_the_reaper_never_raises(monkeypatch):
    class _Boom:
        async def reclaim_all_stale(self):
            raise RuntimeError("db down")
        async def active_engagement_ids(self):
            raise RuntimeError("db down")
    monkeypatch.setattr("app.orchestrator.runs.RunRepository", lambda: _Boom())
    # must return, not raise
    out = asyncio.run(workers.reaper({}))
    assert out == {"runs_reclaimed": 0, "jobs_aborted": 0}


def test_a_fresh_run_is_not_reaped_before_its_first_heartbeat():
    """reclaim_all_stale keys off COALESCE(heartbeat_at, created_at), so a
    just-created run (no heartbeat yet, recent created_at) is safe."""
    from app.orchestrator.runs import RunRepository
    src = inspect.getsource(RunRepository.reclaim_all_stale)
    assert "COALESCE(heartbeat_at, created_at)" in src
    assert "heartbeat_at IS NULL" not in src


def test_stale_window_was_shortened_now_that_heartbeat_is_real():
    from app.orchestrator.runs import STALE_AFTER_SECONDS
    assert STALE_AFTER_SECONDS <= 15 * 60


def test_the_reaper_is_registered_as_a_cron_on_the_orchestrator():
    from app.workers import OrchestratorWorkerSettings
    crons = getattr(OrchestratorWorkerSettings, "cron_jobs", [])
    assert crons, "no cron registered - a zombie run is never reaped"
