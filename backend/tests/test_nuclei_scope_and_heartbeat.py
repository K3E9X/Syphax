"""The vuln phase must not drown in full-template nuclei runs, and a live run
must look alive to the reaper.

Live runs showed 27 nuclei jobs hitting the 1800s timeout for 0 findings: with
no -tags nuclei ran ~4000 templates per asset, and VULN-NUCLEI ran per
endpoint, so the vuln budget went entirely to jobs that never finished and the
exploit phase never reached sqlmap/dalfox. And heartbeat_at never moved, so a
reaper could not tell a live long run from a dead one.
"""
from __future__ import annotations

import inspect


def test_vuln_nuclei_is_scoped_to_high_signal_tags():
    from app.methodology.catalog import CATALOG
    item = next(i for i in CATALOG if i.id == "VULN-NUCLEI")
    assert "-tags" in item.default_options, "VULN-NUCLEI runs the full set"
    tags = item.default_options[item.default_options.index("-tags") + 1]
    # a bounded set, not everything
    assert "," in tags
    for family in ("cve", "misconfiguration", "default-login"):
        assert family in tags


def test_vuln_nuclei_runs_per_host_not_per_endpoint():
    """A template scan tests the host; re-running it per discovered URL is what
    multiplied it into dozens of timing-out jobs. The per-parameter fuzzing is
    EXP-DAST's job."""
    from app.methodology.catalog import CATALOG
    item = next(i for i in CATALOG if i.id == "VULN-NUCLEI")
    assert item.applies_when == {"is_base": True}
    # EXP-DAST stays per-endpoint
    dast = next(i for i in CATALOG if i.id == "EXP-DAST")
    assert dast.applies_when == {"is_endpoint": True}
    assert "-dast" in dast.default_options


def test_the_nuclei_job_timeout_is_shorter():
    """A job stuck past 15 min is not making progress; kill it so its coverage
    is reclaimed and retried rather than burning the whole 30 min."""
    from app.scans.wrappers.nuclei import NucleiWrapper
    assert NucleiWrapper.timeout_seconds <= 15 * 60


def test_the_wait_loop_heartbeats_every_poll():
    """A batch can sit in the wait for minutes; without a heartbeat there a
    live run looks as stale as a dead one and the reaper cannot tell them
    apart."""
    from app.orchestrator import loop
    src = inspect.getsource(loop._wait_for_jobs)
    assert "runs.heartbeat(run_id)" in src
    # and it must not let a heartbeat miss break the wait
    assert "except Exception" in src


def test_the_iteration_refreshes_the_heartbeat():
    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    assert "run.heartbeat_at = time.time()" in src
    # inside the iteration body (after the first, which is the pre-loop seed)
    assert src.count("run.heartbeat_at = time.time()") >= 2
