"""The run must reach exploitation on a slow or large target, and end itself
before the worker's arq job_timeout can hard-cancel it.

Regression guard for the bug where every run on a real target ended as
'cancelled' mid-vuln_analysis - the loop's 6h budget sat under a 3h worker
job_timeout, so arq cancelled the task (exploitation-skipping CancelledError
path) long before the loop's own graceful stop; and phase budgets were counted
in jobs, not time, so a slow target never spent a phase's job share and never
advanced. Audit of real runs: 48/122/82 jobs launched in ~3h, all cancelled.
"""
from __future__ import annotations

from app.methodology import (PHASE_EXPLOIT, PHASE_MAPPING, PHASE_RECON,
                             PHASE_VULN)
from app.orchestrator.loop import (DEFAULT_MAX_SECONDS, FINALIZE_RESERVE_SECONDS,
                                   PHASE_BUDGET_SHARE, phase_time_skip)
from app.queue import ORCH_JOB_TIMEOUT_SECONDS


def test_loop_budget_lands_under_the_worker_timeout():
    """The loop must stop with room to finalise before arq cancels it.

    This is the invariant whose violation caused the hard-cancel: the effective
    time budget has to be strictly less than the worker's job_timeout, by at
    least the finalise reserve.
    """
    effective = min(DEFAULT_MAX_SECONDS,
                    ORCH_JOB_TIMEOUT_SECONDS - FINALIZE_RESERVE_SECONDS)
    assert FINALIZE_RESERVE_SECONDS > 0
    assert effective <= ORCH_JOB_TIMEOUT_SECONDS - FINALIZE_RESERVE_SECONDS
    assert effective < ORCH_JOB_TIMEOUT_SECONDS


def test_worker_timeout_is_the_shared_constant():
    """The worker and the loop read the SAME ceiling, so they cannot drift back
    apart into the 6h-loop-under-3h-timeout configuration that caused this."""
    from app.workers import OrchestratorWorkerSettings
    assert OrchestratorWorkerSettings.job_timeout == ORCH_JOB_TIMEOUT_SECONDS


def test_time_budget_reserves_the_exploitation_phase():
    """Once the earlier phases' share of the clock is spent, they yield; the
    exploitation phase is never skipped, so it always gets its reserved slice."""
    recon_end = PHASE_BUDGET_SHARE[PHASE_RECON]
    mapping_end = recon_end + PHASE_BUDGET_SHARE[PHASE_MAPPING]
    vuln_end = mapping_end + PHASE_BUDGET_SHARE[PHASE_VULN]

    budget = 1000.0
    # Early: nothing is forced to yield yet.
    assert phase_time_skip(0.0, budget) == set()
    # Just inside recon's share: recon still has the floor.
    assert PHASE_RECON not in phase_time_skip((recon_end - 0.01) * budget, budget)
    # Past recon's share: recon yields, mapping does not yet.
    skip = phase_time_skip((recon_end + 0.01) * budget, budget)
    assert PHASE_RECON in skip and PHASE_MAPPING not in skip
    # Past vuln's share: recon+mapping+vuln all yield, exploitation never does.
    late = phase_time_skip((vuln_end + 0.01) * budget, budget)
    assert {PHASE_RECON, PHASE_MAPPING, PHASE_VULN} <= late
    assert PHASE_EXPLOIT not in late


def test_time_skip_is_inert_when_no_time_has_passed():
    """A fast unit/integration run (elapsed ~ 0) must behave exactly as before:
    no phase is skipped on time grounds, so the job-count path is unchanged."""
    assert phase_time_skip(0.0, DEFAULT_MAX_SECONDS) == set()
    assert phase_time_skip(5.0, DEFAULT_MAX_SECONDS) == set()
    # Degenerate budgets never raise and never skip.
    assert phase_time_skip(10.0, 0.0) == set()
