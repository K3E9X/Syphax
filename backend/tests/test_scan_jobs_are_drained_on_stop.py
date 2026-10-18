"""A run that ends must stop the scan jobs it left in flight.

arq keeps handing an enqueued scan job to the scans worker even after the run
that enqueued it is gone, so nuclei/sqlmap kept running for up to 1800s each
long after a cancelled run - 16 jobs were still queued/running at the live
cancel, burning the 2-core VM for hours. _drain_scan_jobs aborts them: arq's
job id is our job id, so ScanRunner.cancel targets each directly.
"""
from __future__ import annotations

import asyncio
import inspect


from app.orchestrator import loop
from app.scans.models import Job, JobStatus


def _job(jid, status):
    return Job(id=jid, tool="nuclei", target="http://t/", args=[],
               status=status, created_at=0.0, engagement_id="eng1")


class _Repo:
    def __init__(self, jobs):
        self._jobs = jobs
    async def list_by_engagement(self, engagement_id, *, limit=1000):
        return self._jobs


class _Runner:
    def __init__(self):
        self.cancelled = []
    async def cancel(self, job_id):
        self.cancelled.append(job_id)
        return True


class _Eng:
    id = "eng1"


class _Run:
    id = "run1"


def _wire(monkeypatch, jobs, runner):
    monkeypatch.setattr(loop, "JobRepository", lambda: _Repo(jobs))
    import app.scans.runner as runner_mod
    monkeypatch.setattr(runner_mod, "get_runner", lambda: runner)
    async def _noop_emit(*a, **k):
        return None
    monkeypatch.setattr(loop.events, "emit", _noop_emit)


def test_only_queued_and_running_jobs_are_aborted(monkeypatch):
    jobs = [
        _job("a", JobStatus.QUEUED),
        _job("b", JobStatus.RUNNING),
        _job("c", JobStatus.SUCCEEDED),
        _job("d", JobStatus.FAILED),
        _job("e", JobStatus.CANCELLED),
    ]
    runner = _Runner()
    _wire(monkeypatch, jobs, runner)
    n = asyncio.run(loop._drain_scan_jobs(_Eng(), _Run()))
    assert n == 2
    assert set(runner.cancelled) == {"a", "b"}


def test_nothing_to_drain_is_zero_and_calls_no_abort(monkeypatch):
    jobs = [_job("c", JobStatus.SUCCEEDED)]
    runner = _Runner()
    _wire(monkeypatch, jobs, runner)
    assert asyncio.run(loop._drain_scan_jobs(_Eng(), _Run())) == 0
    assert runner.cancelled == []


def test_a_failed_abort_does_not_raise_and_is_not_counted(monkeypatch):
    class _FlakyRunner:
        async def cancel(self, job_id):
            if job_id == "a":
                raise RuntimeError("arq unreachable")
            return True
    _wire(monkeypatch, [_job("a", JobStatus.RUNNING),
                        _job("b", JobStatus.QUEUED)], _FlakyRunner())
    # one raises, one succeeds -> returns 1, never raises
    assert asyncio.run(loop._drain_scan_jobs(_Eng(), _Run())) == 1


def test_a_listing_failure_drains_nothing_rather_than_crashing(monkeypatch):
    class _BadRepo:
        async def list_by_engagement(self, *a, **k):
            raise RuntimeError("db down")
    monkeypatch.setattr(loop, "JobRepository", lambda: _BadRepo())
    assert asyncio.run(loop._drain_scan_jobs(_Eng(), _Run())) == 0


# ---- it is wired into both the graceful end and the cancel handler ----

def test_the_loop_drains_before_finalising_and_in_the_cancel_handler():
    src = inspect.getsource(loop.run_engagement_loop)
    assert src.count("await _drain_scan_jobs(engagement, run)") == 2
    # graceful path: drain before _finalize_engagement
    assert (src.index("await _drain_scan_jobs(engagement, run)")
            < src.index("_finalize_engagement(engagement"))
    # cancel path: drain before the salvage
    assert (src.rindex("await _drain_scan_jobs(engagement, run)")
            < src.index("_salvage_on_cancel(engagement"))


def test_the_abort_targets_the_job_id_which_is_the_arq_id():
    """The whole mechanism rests on arq's job id being our job id."""
    runner_src = inspect.getsource(__import__("app.scans.runner",
                                              fromlist=["x"]))
    assert "_job_id=job.id" in runner_src
    assert "abort_job" in runner_src


def test_drains_concurrently_not_serially():
    """Dozens of orphans must not cost dozens of 5s round-trips."""
    src = inspect.getsource(loop._drain_scan_jobs)
    assert "asyncio.gather" in src
