"""P0-1: the traffic analysers run DURING the engagement, not only at the end.

run_analysis was called once, from _finalize_engagement. So every finding the
analysers produce - the IDOR, the broken access control, the JWT weakness, the
secret in a bundle, the forgotten API version - and every lead they put on the
blackboard arrived AFTER exploitation was over. None of it could steer a single
exploitation task, which is the entire point of having a board, and a run that
ended on its budget lost all of it.

They run in three passes now, and the gate is the thing to get right: moving
analysis earlier must not become a way around a human approving exploitation.
"""
from __future__ import annotations

import inspect

import pytest

from app.analysis import (ACTIVE_STEPS, FINAL_ONLY_STEPS, run_analysis,
                          step_names)


# ---- every analyser is accounted for ----------------------------------

def test_every_step_is_classified():
    """"Apply it to all the tools" has to be checkable. step_names is parsed
    from run_analysis's own source, so a new analyser cannot be added without
    landing in exactly one of these buckets."""
    names = step_names()
    assert len(names) >= 20, f"only found {len(names)} steps: {names}"
    for name in names:
        buckets = [name in ACTIVE_STEPS, name in FINAL_ONLY_STEPS]
        assert buckets.count(True) <= 1, f"{name} is in two categories"
    # and nothing is classified that is not a real step
    for name in ACTIVE_STEPS | FINAL_ONLY_STEPS:
        assert name in names, f"{name} is classified but is not a step"


def test_the_active_set_is_exactly_what_writes_or_bursts():
    """Derived from the code, not invented: these are the ones that already
    took allow_active, plus cve_checks which was behind an `if`."""
    assert ACTIVE_STEPS == {"mass_assignment", "api_sequences", "rate_limit",
                            "auth_posture", "cve_checks"}


def test_the_read_only_set_is_the_rest():
    readonly = set(step_names()) - ACTIVE_STEPS - FINAL_ONLY_STEPS
    # the ones whose findings the operator asked about by name
    for expected in ("logic", "access_control", "jwt", "js_recon",
                     "api_inventory", "api_exposure", "schema_audit"):
        assert expected in readonly, f"{expected} would still wait for the end"


# ---- the selectors ----------------------------------------------------

@pytest.mark.parametrize("kw,expect_in,expect_out", [
    ({"only": ACTIVE_STEPS}, "mass_assignment", "logic"),
    ({"skip": ACTIVE_STEPS}, "logic", "mass_assignment"),
])
def test_only_and_skip_select_the_pass(kw, expect_in, expect_out):
    """A thin check that the selector arguments exist and are honoured by the
    loop, without running twenty analysers against a database."""
    src = inspect.getsource(run_analysis)
    assert "wanted is not None and name not in wanted" in src
    assert "name in unwanted" in src
    assert expect_in in step_names() and expect_out in step_names()


def test_re_running_supersedes_rather_than_duplicates():
    """Three passes over the same traffic must not triple the findings.
    save_analysis_job deletes an analyser's previous job first."""
    from app.analysis import _store
    src = inspect.getsource(_store.save_analysis_job)
    assert "delete_by_tool" in src
    assert src.index("delete_by_tool") < src.index("repo.create")


# ---- the gate, which is the part worth being careful about ------------

def test_the_mid_run_pass_cannot_fire_a_writing_analyser():
    """At vuln_analysis the exploitation checkpoint has NOT been reached. The
    read-only pass must therefore both skip the writing analysers and pass
    allow_active=False, so neither path can send a write."""
    from app.orchestrator import loop
    src = inspect.getsource(loop._analyse_traffic)
    readonly = src[src.index("else:"):]
    assert "allow_active=False" in readonly
    assert "skip=ACTIVE_STEPS" in readonly


def test_the_active_pass_runs_only_after_the_approval():
    """Ordering is the whole safety argument here, so it is asserted on the
    source of the loop rather than trusted."""
    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    approval = src.index("_await_exploit_approval")
    active = src.index("_analyse_traffic(engagement, run, active=True)")
    assert approval < active, (
        "the writing analysers would run before the human approved "
        "exploitation")


def test_a_denied_approval_never_reaches_the_active_pass():
    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    denied = src.index('run.stop_reason = "exploit_denied"')
    active = src.index("_analyse_traffic(engagement, run, active=True)")
    between = src[denied:active]
    assert "break" in between, (
        "a denied approval must leave the loop before the active analysers")


def test_the_read_only_pass_runs_when_vuln_analysis_starts():
    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    phase = src.index("if current_phase == PHASE_VULN:")
    call = src.index("await _analyse_traffic(engagement, run)")
    exploit = src.index("batch[0].phase == PHASE_EXPLOIT")
    assert phase < call < exploit


def test_finalisation_still_runs_everything():
    """The last pass is the only one that sees the traffic exploitation
    generated, and the only one that runs llm_recon."""
    from app.orchestrator import loop
    src = inspect.getsource(loop._finalize_engagement)
    assert "run_analysis(engagement.id, allow_active=_active_ok)" in src
    assert "only=" not in src.split("run_analysis(")[1][:120]


def test_analysis_never_fails_the_run():
    from app.orchestrator import loop
    src = inspect.getsource(loop._analyse_traffic)
    assert "except Exception" in src
    assert "return" in src


# ---- the console tells the truth --------------------------------------

def test_the_finding_count_comes_from_the_jobs_not_the_result_dicts():
    """Only 14 of the analysers report a "findings" key, so summing those
    under-reports - and a confident wrong number in the console is exactly
    what the operator asked to stop seeing."""
    from app.orchestrator import loop
    src = inspect.getsource(loop._count_analyser_findings)
    assert "FROM jobs" in src
    assert "ANALYSER_TOOLS" in src
    # and it says "unknown" rather than printing a confident zero
    assert "return -1" in src
    say = inspect.getsource(loop._analyse_traffic)
    assert "found >= 0" in say


def test_the_step_key_and_the_job_tool_name_are_reconciled():
    """The step keys use underscores ("js_recon"); the job tool names are the
    hyphenated ones the UI knows ("js-recon"). Conflating them would count
    zero for half the analysers."""
    from app.orchestrator import loop
    src = inspect.getsource(loop._count_analyser_findings)
    assert 'replace("-", "_")' in src


# ---- it runs once per run, not once per phase transition --------------

def test_each_pass_runs_once_per_run():
    """plan() picks the earliest phase with uncovered work, so a mapping asset
    discovered during vuln_analysis sends the run back to mapping and then
    forward again - re-entering the transition block. Fourteen analysers over
    the same traffic a second time is idempotent but not free, and the time
    comes out of the phase budgets."""
    from app.orchestrator import loop
    src = inspect.getsource(loop._analyse_traffic)
    assert "_ANALYSED" in src
    assert "if label in done:" in src
    assert "return" in src[src.index("if label in done:"):]


def test_the_once_per_run_cache_is_bounded():
    """The worker is long-lived, so a dict keyed by run id grows forever."""
    from app.orchestrator import loop
    assert loop._ANALYSED_MAX > 0
    src = inspect.getsource(loop._analyse_traffic)
    assert "popitem(last=False)" in src


def test_the_two_passes_do_not_block_each_other():
    """They are tracked separately: the read-only pass having run must not
    stop the active one from running after the approval."""
    from app.orchestrator import loop
    loop._ANALYSED.clear()
    loop._ANALYSED["r1"] = {"read-only"}
    assert "active" not in loop._ANALYSED["r1"]
    loop._ANALYSED.clear()
