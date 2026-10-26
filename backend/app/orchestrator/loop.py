"""The autonomous engagement loop (spec §4, §13.4 acceptance).

plan -> execute -> wait -> ingest, repeated until coverage saturates, the
budget is hit, or a stop is requested. Runs inside the arq worker as a
long-lived task; the scan jobs it launches run concurrently on the same
worker (max_jobs > 1), so the loop can submit a batch and wait for it.

This is deterministic and fully functional without any LLM; the planner's
optional LLM pass only re-orders the batch.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from app.audit import audit
from app import events
from app.engagements import EngagementRepository, EngagementStatus
from app.orchestrator.approvals import ApprovalRepository, requires_exploit_approval
from app.orchestrator.executor import Executor
from app.orchestrator.identity import (adopt_identity,
                                       drop_dead_identity)
from app.orchestrator.planner import Planner
from app.orchestrator.strategist import Strategist
from app.orchestrator.runs import Run, RunRepository
from app.orchestrator.state import EngagementState
from app.methodology import (PHASE_EXPLOIT, PHASE_MAPPING, PHASE_ORDER,
                             PHASE_RECON, PHASE_VULN)
from app.queue import ORCH_JOB_TIMEOUT_SECONDS
from app.scans.models import JobStatus
from app.scans.storage import JobRepository
from app.validation import build_chains, validate_engagement

logger = logging.getLogger("syphax.orchestrator.loop")

# Safety defaults when the engagement sets no budget.
# Sized for what the tool is for: discover the endpoints and APIs behind a URL
# and TEST them. The old 200 jobs / 2 hours was enough to map a small site and
# nothing else - a run on a real target ended with `time budget reached` during
# mapping, having proven nothing. Both are per-engagement overridable
# (budget_requests / budget_seconds) for a deliberately small run.
DEFAULT_MAX_JOBS = 600

# Each phase's share of the job budget.
#
# Without a cap, "the earliest phase with any uncovered work" wins forever, and
# mapping can always manufacture more work than the budget allows: its tools
# create endpoint assets and its items applied to every endpoint asset, so 40
# discovered endpoints were 200 mapping tasks - the entire default budget -
# before a single vuln_analysis task existed. Every run on a real site ended
# inside mapping, which is why the only findings were recon-grade and "info",
# and why no exploitation, no PoC and no authored payload ever happened.
#
# A phase that does not use its share leaves the slack to the phases after it:
# the overall budget is still the only hard stop, so nothing is wasted by
# reserving. These add to 1.0 for readability, not because they must.
PHASE_BUDGET_SHARE = {
    PHASE_RECON: 0.15,
    PHASE_MAPPING: 0.30,
    PHASE_VULN: 0.25,
    PHASE_EXPLOIT: 0.30,
}
# Never cap a phase below this many jobs, however small the budget - unless the
# budget itself is smaller than that times the number of phases, in which case
# the floor scales down rather than letting the early phases take everything.
MIN_PHASE_JOBS = 4


def phase_allowance(max_jobs: int, phase: str) -> int:
    """How many jobs `phase` may launch in a run with this budget.

    Exported and used by the loop rather than inlined, so the simulation in
    tests/test_the_run_reaches_exploitation.py can import the real arithmetic
    instead of restating it - a test that restates the rule cannot catch the
    rule being wrong.
    """
    share = PHASE_BUDGET_SHARE.get(phase)
    if share is None:
        return max_jobs
    floor = max(1, min(MIN_PHASE_JOBS, max_jobs // max(1, len(PHASE_BUDGET_SHARE))))
    return max(floor, int(max_jobs * share))


def phase_time_skip(elapsed: float, time_budget: float) -> set:
    """Phases whose share of the TIME budget has already elapsed.

    The job-count sibling of this (`phase_allowance` + `skip_phases`) stops any
    single phase from eating the whole *job* budget. But the budget that runs
    out first on a real target is TIME, not jobs: a large surface or slow tools
    spend hours in mapping/vuln_analysis launching only a few dozen jobs, so the
    job-count shares are never reached - the run just hits the worker's
    job_timeout mid-vuln and the exploitation phase never runs at all.

    So time is capped the same way jobs are. Once the run is past a phase's
    cumulative share of the wall-clock (recon .15, then +mapping .30, then
    +vuln .25), that phase yields to the ones after it. The last phase
    (exploitation) is never skipped - it has nowhere to yield to, and reserving
    the final 1 - sum(earlier shares) of the clock for it is the whole point.
    """
    if time_budget <= 0:
        return set()
    frac = elapsed / time_budget
    skip: set = set()
    cumulative = 0.0
    for phase in PHASE_ORDER:
        share = PHASE_BUDGET_SHARE.get(phase)
        if share is None:
            continue
        cumulative += share
        if phase != PHASE_EXPLOIT and frac >= cumulative:
            skip.add(phase)
    return skip


DEFAULT_MAX_SECONDS = 6 * 60 * 60          # 6 hours
# The loop's own deadline must land BEFORE the worker's arq job_timeout, with
# room left to finalise. If it does not, arq cancels the task at job_timeout and
# the run falls into the CancelledError path - read-only salvage, exploitation
# deliberately skipped - instead of the graceful `time_budget` stop that runs
# the exploitation and validation phases on whatever was found. A 6h loop budget
# sitting under a 3h job_timeout is exactly why every run on a real target ended
# 'cancelled' mid-vuln_analysis with nothing exploited, no PoC and no payload.
FINALIZE_RESERVE_SECONDS = 20 * 60
MIN_TIME_BUDGET = 60
# 150 x BATCH_SIZE is 1200 planning slots, comfortably above the job budget, so
# the iteration count is never the thing that stops a run.
MAX_ITERATIONS = 150
BATCH_SIZE = 8
POLL_INTERVAL = 3.0                        # seconds between job-status polls
ITERATION_WAIT_CAP = 45 * 60               # max wait for one batch to finish

_TERMINAL = {JobStatus.SUCCEEDED.value, JobStatus.FAILED.value, JobStatus.CANCELLED.value}

# Human-readable explanation of why a run ended, surfaced in the live feed and
# the UI so the operator never has to guess (addresses "the handoff is fuzzy").
_REASON_LABELS = {
    "coverage_saturated": "all applicable tests have run",
    "time_budget": "time budget reached",
    "job_budget": "job budget reached",
    "llm_budget": "LLM spend cap reached",
    "no_tools": "no launchable tasks (required tools unavailable)",
    "max_iterations": "iteration cap reached",
    "stopped": "stopped by operator",
    "exploit_denied": "exploitation not approved",
    "cancelled": "run cancelled",
    "error": "stopped after repeated errors",
}


async def run_engagement_loop(run_id: str) -> dict:
    runs = RunRepository()
    engagements = EngagementRepository()
    jobs_repo = JobRepository()

    run = await runs.get(run_id)
    if run is None:
        return {"run_id": run_id, "status": "missing"}

    engagement = await engagements.get(run.engagement_id)
    if engagement is None:
        await _fail(runs, run, "engagement not found")
        return run.to_public()
    if engagement.status != EngagementStatus.AUTHORIZED:
        await _fail(runs, run, f"engagement is {engagement.status.value}, not authorized")
        return run.to_public()

    # Bill every LLM call made during this run to the engagement.
    from app.llm.usage import current_engagement
    current_engagement.set(engagement.id)

    state = EngagementState(engagement.id)
    planner = Planner(state)
    executor = Executor(state)
    # Reads the blackboard and tells the planner what this run has already
    # established. Empty advice until something posts a lead, and empty advice
    # changes nothing - so the run behaves exactly as before on a target where
    # nothing is found.
    strategist = Strategist(state)

    # Reclaim (item, asset) pairs a previous run left pinned at 'running'/
    # 'pending' - those are in COVERED_STATUSES, so without this a re-run skips
    # every injection point whose job was killed at the timeout. Safe here:
    # this run has launched nothing yet, so any such row is an orphan.
    try:
        reclaimed = await state.reset_stale_coverage()
        if reclaimed:
            await events.emit(
                engagement.id, events.PHASE_CHANGED,
                f"Reclaimed {reclaimed} unfinished task(s) from a previous run "
                "so they are retried this time.",
                run_id=run.id, level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001 - coverage reclaim must never fail a run
        logger.exception("[%s] stale-coverage reclaim failed", run.id)

    max_jobs = engagement.budget_requests or DEFAULT_MAX_JOBS
    # Clamp the loop budget below the worker's job_timeout (minus a finalise
    # reserve) so the run stops itself gracefully - and reaches exploitation +
    # validation - before arq can hard-cancel it. See FINALIZE_RESERVE_SECONDS.
    time_budget = min(engagement.budget_seconds or DEFAULT_MAX_SECONDS,
                      max(MIN_TIME_BUDGET,
                          ORCH_JOB_TIMEOUT_SECONDS - FINALIZE_RESERVE_SECONDS))
    deadline = time.time() + time_budget

    # Before anything is planned: which tools can actually find something,
    # and whether the crawl's traffic is being captured for the analysers.
    try:
        # How thorough this run was told to be. Said out loud because the
        # answer changes how much of the surface is tested, and a run that
        # tested a sliver used to look exactly like one that tested it all.
        from app.limits import describe as describe_depth
        await events.emit(engagement.id, events.THOUGHT, describe_depth(),
                          run_id=run.id, level=events.LEVEL_INFO)
        await _report_capture(engagement, run)
        await _report_tool_readiness(engagement, run)
    except Exception:  # noqa: BLE001 - a preflight must never fail a run
        logger.exception("[%s] tool preflight failed", run.id)

    # What the target publishes about itself, before anything is planned.
    #
    # robots.txt and sitemap.xml are the owner's own list of paths - including
    # the ones they asked not to have indexed - and the OpenAPI schema is the
    # API's own contract. Both were ignored: nothing read robots.txt, and
    # VULN-API-CONTRACT (schemathesis, which property-tests every documented
    # operation) applies only to an asset whose URL says "openapi" or
    # "swagger", which nothing ever created. Seeded here so every later phase
    # plans against them.
    try:
        from app.analysis.surface_seed import seed_published_surface
        await seed_published_surface(engagement.id)
    except Exception:  # noqa: BLE001 - seeding must never fail a run
        logger.exception("[%s] could not seed the published surface", run.id)

    approvals = ApprovalRepository()
    need_approval = requires_exploit_approval(engagement)

    run.status = "running"
    run.started_at = time.time()
    run.heartbeat_at = time.time()
    await runs.update(run)
    await audit("engagement.run_started", engagement_id=engagement.id, run_id=run.id)
    await events.emit(engagement.id, events.RUN_STARTED, "Autonomous run started",
                      run_id=run.id, target=engagement.target_url)

    # Seed the surface: the verified host + the base URL.
    await state.add_asset("host", engagement.target_host, source="engagement")
    await state.add_asset("endpoint", engagement.target_url, source="engagement")
    # Resolve the target to its IP(s) (dig) and bring them into scope + the
    # surface. The IP a hostname points at is the same server, so its services
    # (other ports/vhosts) are in scope too - otherwise every IP-keyed asset was
    # skipped as "out of scope" and the run never looked at the host by address.
    try:
        await _seed_resolved_ips(state, engagement)
    except Exception:  # noqa: BLE001 - resolution is best-effort, never fatal
        logger.exception("[%s] could not resolve target IPs", run.id)
    # Seed from real captured traffic (proxy): the actual parameterized
    # endpoints the operator exercised - far richer than crawling alone.
    seeded = await _seed_from_proxy(state, engagement)
    if seeded:
        await events.emit(engagement.id, events.ASSET_FOUND,
                          f"Seeded {seeded} endpoint(s) from captured proxy traffic",
                          run_id=run.id, level=events.LEVEL_VERBOSE)

    current_phase: Optional[str] = None
    no_launch_streak = 0
    error_streak = 0
    # Which phases actually got planned. A run that ends on its job or time
    # budget during mapping never reaches exploitation, so nothing can be
    # proven - and that was reported nowhere, which reads as "the scanner found
    # nothing".
    phases_seen: set = set()
    # Jobs launched per phase, so no phase can eat the whole budget.
    jobs_by_phase: Dict[str, int] = {}
    capped_reported: set = set()
    try:
        for iteration in range(MAX_ITERATIONS):
            # A sign of life, so a worker that dies can be told apart from a
            # loop legitimately waiting on a slow batch.
            await runs.beat(run.id)
            if await runs.stop_requested(run.id):
                run.status = "stopped"
                run.stop_reason = "stopped"
                await runs.update(run)
                break
            if time.time() > deadline:
                logger.info("[%s] time budget reached", run.id)
                run.stop_reason = "time_budget"
                break
            if run.jobs_launched >= max_jobs:
                logger.info("[%s] job budget reached (%d)", run.id, max_jobs)
                run.stop_reason = "job_budget"
                break
            # The operator can cap LLM spend per engagement in Settings. That
            # input existed from the start and nothing ever read it, so the cap
            # silently did nothing; a runaway planner loop could bill freely.
            over_budget = await _llm_budget_exceeded(engagement.id)
            if over_budget:
                logger.info("[%s] LLM budget reached ($%.2f)", run.id, over_budget)
                run.stop_reason = "llm_budget"
                await events.emit(
                    engagement.id, events.RUN_FINISHED,
                    f"LLM budget reached: ${over_budget:.2f} spent on this "
                    "engagement. Raise or clear the cap in Settings.",
                    run_id=run.id,
                )
                break

            # One iteration of plan -> launch -> wait -> ingest. A transient
            # error in any single iteration (malformed finding, DB hiccup,
            # planner quirk) must NOT abort the whole run: log it, and only
            # give up after several consecutive failures.
            try:
                job_exhausted = {
                    phase for phase in PHASE_BUDGET_SHARE
                    if jobs_by_phase.get(phase, 0) >= phase_allowance(max_jobs, phase)
                }
                # The time-budget sibling: a phase that has spent its share of
                # the wall-clock yields too, so a slow or large target still
                # reaches exploitation instead of dying in mapping/vuln on the
                # job_timeout. elapsed = how far into the time budget we are.
                elapsed = time_budget - (deadline - time.time())
                time_exhausted = phase_time_skip(elapsed, time_budget)
                exhausted = job_exhausted | time_exhausted
                for phase in exhausted - capped_reported:
                    capped_reported.add(phase)
                    if phase in job_exhausted:
                        msg = (
                            f"Phase '{phase}' reached its share of the job budget "
                            f"({jobs_by_phase.get(phase, 0)} of {max_jobs} tasks); "
                            "moving on so the later phases run.")
                    else:
                        msg = (
                            f"Phase '{phase}' reached its share of the time budget; "
                            "moving on so the later phases run.")
                    await events.emit(
                        engagement.id, events.PHASE_CHANGED, msg,
                        run_id=run.id, phase=phase, level=events.LEVEL_INFO)

                # If the run has earned a session, start using it. Done
                # before planning so the tasks this iteration launches are the
                # authenticated ones - see orchestrator/identity for why this
                # is the switch that makes a black-box run a grey-box one.
                try:
                    # A session is not permanent: it expires, and a scanner
                    # carrying it can reach a logout. Drop a dead one first,
                    # so a fresh login can replace it and the run stops
                    # reporting anonymous results as authenticated ones.
                    await drop_dead_identity(engagement.id)
                    await adopt_identity(engagement.id)
                except Exception:  # noqa: BLE001 - never fail a run over this
                    logger.debug("[%s] identity adoption skipped", run.id)

                # What the board knows, before deciding what to run next.
                advice = await strategist.advise()
                batch = await planner.plan(max_tasks=BATCH_SIZE,
                                           skip_phases=exhausted,
                                           advice=advice)
                # Trim to what this phase has left, not just to BATCH_SIZE.
                # Checking the cap once per iteration lets a full batch
                # overshoot it, and on a small budget one overshoot is the
                # whole reservation: with a 12-task budget, recon took 8 and
                # mapping the other 4, so exploitation got nothing at all.
                if batch:
                    phase = batch[0].phase
                    left = (phase_allowance(max_jobs, phase)
                            - jobs_by_phase.get(phase, 0))
                    if left > 0:
                        batch = batch[:left]
                if not batch:
                    logger.info("[%s] coverage saturated after %d iterations", run.id, iteration)
                    run.stop_reason = "coverage_saturated"
                    break

                run.iterations = iteration + 1
                run.phase = batch[0].phase
                run.heartbeat_at = time.time()
                await runs.update(run)
                if batch[0].phase != current_phase:
                    current_phase = batch[0].phase
                    phases_seen.add(current_phase)
                    await events.emit(engagement.id, events.PHASE_CHANGED,
                                      f"Phase: {current_phase}", run_id=run.id, phase=current_phase)

                    # Recon and mapping are done by the time vuln analysis
                    # starts, so this is the moment the picture is complete
                    # enough to be worth joining - and still early enough for
                    # the leads to change what gets scanned.
                    if current_phase == PHASE_VULN:
                        await _materialise_js(engagement, run)
                        # Parameters BEFORE the injection tests are planned.
                        # See _discover_params: every injection item in the
                        # catalog applies only to an endpoint that has them.
                        await _discover_params(engagement, run)
                        # The API schema, for the same reason: it is built from
                        # the traffic recon and mapping just captured, and the
                        # contract tests that read it are planned next.
                        await _synthesise_api_schema(engagement, run)
                        # The forgotten versions, before the catalog is applied
                        # to the surface: finding /api/v1 and not scanning it
                        # would be worse than not finding it.
                        await _hunt_shadow_apis(engagement, run)
                        # P0-1: the traffic analysers, HERE rather than only
                        # at the end. Read-only ones only - the writing ones
                        # wait for the exploitation checkpoint below.
                        await _analyse_traffic(engagement, run)
                        await _run_correlation(engagement, run, executor, runs)

                # Human checkpoint before exploitation (spec §11 approval).
                if need_approval and batch[0].phase == PHASE_EXPLOIT:
                    approved = await _await_exploit_approval(
                        approvals, runs, engagement.id, run.id, batch
                    )
                    if not approved:
                        # Stop requested or denied: end the active testing loop.
                        run.status = "stopped"
                        run.stop_reason = "exploit_denied"
                        await runs.update(run)
                        break
                    # Approved. The analysers that WRITE to the target or
                    # burst it can run now, and their leads reach the board
                    # before the exploitation batches that follow this one.
                    await _analyse_traffic(engagement, run, active=True)

                # Launch the batch (respecting the remaining job budget).
                launched_ids: List[str] = []
                for task in batch:
                    if run.jobs_launched >= max_jobs:
                        break
                    job = await executor.launch(task)
                    if job is not None:
                        launched_ids.append(job.id)
                        run.jobs_launched += 1
                        jobs_by_phase[task.phase] = jobs_by_phase.get(task.phase, 0) + 1
                        await events.emit(
                            engagement.id, events.TASK_LAUNCHED,
                            f"{task.tool} -> {task.asset_value}",
                            run_id=run.id, tool=task.tool, target=task.asset_value,
                            catalog_item=task.catalog_item_id,
                        )
                await runs.update(run)
                error_streak = 0

                if not launched_ids:
                    # Everything in the batch was skipped (tool missing). launch()
                    # already marked them covered, so the next plan() advances; but
                    # guard against a pathological all-tools-missing run spinning
                    # (and burning a planner LLM call) every iteration.
                    no_launch_streak += 1
                    if no_launch_streak >= 3:
                        logger.info("[%s] no launchable tasks for %d iterations; stopping",
                                    run.id, no_launch_streak)
                        run.stop_reason = "no_tools"
                        await events.emit(engagement.id, events.PHASE_CHANGED,
                                          "No launchable tasks (required tools unavailable)",
                                          run_id=run.id, level=events.LEVEL_VERBOSE)
                        break
                    continue
                no_launch_streak = 0

                # Wait for this batch to finish, then ingest.
                finished = await _wait_for_jobs(jobs_repo, launched_ids, runs, run.id)
                new_findings = 0
                for job in finished:
                    try:
                        await executor.ingest(job)
                    except Exception:  # noqa: BLE001 - one bad job never aborts the run
                        logger.exception("[%s] ingest failed for job %s", run.id, job.id)
                        continue
                    new_findings += len(job.findings)
                await events.emit(
                    engagement.id, events.BATCH_DONE,
                    f"Batch done: {len(finished)} jobs, {new_findings} findings",
                    run_id=run.id, jobs=len(finished), findings=new_findings,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - resilient per-iteration
                error_streak += 1
                logger.exception("[%s] iteration %d error (streak %d): %s",
                                 run.id, iteration, error_streak, exc)
                run.error = f"{type(exc).__name__}: {exc}"
                if error_streak >= 3:
                    run.stop_reason = "error"
                    break
                continue

        else:
            logger.info("[%s] hit MAX_ITERATIONS", run.id)
            run.stop_reason = run.stop_reason or "max_iterations"

        # Stop any scan jobs still in flight before finalising. The loop that
        # would ingest them is ending, so they will not contribute to this run;
        # leaving them running burns the VM for up to their own 1800s timeout
        # each and pins their coverage. See _drain_scan_jobs.
        await _drain_scan_jobs(engagement, run)

        # Validation phase: confirm findings with safe PoC, then build chains.
        # Always run it (even on stop) so partial results are still validated.
        await _finalize_engagement(engagement, run, runs, state,
                                   phases_seen=phases_seen)

        if run.status != "stopped":
            run.status = "completed"
    except asyncio.CancelledError:
        run.status = "stopped"
        run.stop_reason = run.stop_reason or "cancelled"
        # Validate what the run already collected, before letting the
        # cancellation through.
        #
        # The graceful stop paths above break out of the loop and fall into
        # _finalize_engagement, whose own comment says "Always run it (even on
        # stop) so partial results are still validated". This path did not: it
        # persisted the row and re-raised. So an operator who pressed Stop -
        # which is exactly what they do when they can see the run is wasting
        # its budget - threw away every finding the run had made. One run
        # reached iteration 28 with 206 jobs behind it and showed zero
        # findings, because the Findings page reads validated_findings and
        # nothing had validated them.
        #
        # Every active step inside _finalize_engagement already self-suppresses
        # on stop_reason "cancelled", so this is the read-only half: the
        # traffic analysers and the validator.
        # Abort the scan jobs this run enqueued but never finished FIRST: a
        # hard-cancel at the worker's job_timeout leaves them running in arq,
        # where the scans worker keeps feeding nuclei/sqlmap the whole VM for
        # hours after the run is gone. Draining before the salvage also frees
        # the CPU so the read-only salvage analysers can actually run.
        await _drain_scan_jobs(engagement, run)
        await _salvage_on_cancel(engagement, run, runs, state, phases_seen)
        await _finalize(runs, run)
        await audit("engagement.run_cancelled", engagement_id=engagement.id, run_id=run.id)
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("[%s] orchestrator loop crashed", run.id)
        run.stop_reason = "error"
        await _fail(runs, run, f"{type(exc).__name__}: {exc}")
        return run.to_public()

    run.stop_reason = run.stop_reason or "coverage_saturated"
    await _finalize(runs, run)
    await audit(
        "engagement.run_finished",
        engagement_id=engagement.id,
        run_id=run.id,
        status=run.status,
        stop_reason=run.stop_reason,
        jobs=run.jobs_launched,
        coverage=await state.coverage_summary(),
    )
    reason_label = _REASON_LABELS.get(run.stop_reason, run.stop_reason or "")
    await events.emit(engagement.id, events.RUN_FINISHED,
                      f"Run {run.status} - {reason_label} "
                      f"({run.jobs_launched} jobs, {run.iterations} iterations)",
                      run_id=run.id, status=run.status, stop_reason=run.stop_reason,
                      jobs=run.jobs_launched)
    return run.to_public()


async def _report_verification_limits(engagement, run,
                                      campaign: Optional[Dict[str, Any]] = None,
                                      phases_seen: Optional[set] = None) -> None:
    """Name what kept findings unverified, in the live console.

    Everything here was already decided and already discarded: run_cve_checks
    returned {"skipped": 1, "reason": "allow_active_exploit is off"} into a
    dict nobody rendered, and the file-reading tools scanned an empty directory
    and reported nothing - which looks exactly like finding nothing.

    `campaign` is what run_campaign returned. The panel knew nothing about the
    exploitation phase, so the reasons it could name were never the reasons
    that bit: an unreachable sandbox, a PoC held back by inspection, a finding
    with no route at all.
    """
    campaign = campaign or {}
    try:
        from app.scans.artifacts import js_dir, listdir
        from app.validation import ValidatedFindingRepository
        from app.validation.limits import (limits_for, summary_line,
                                           unverified_classes_of)

        findings = await ValidatedFindingRepository().list(engagement.id)
        limits = limits_for(
            allow_active_exploit=bool(engagement.allow_active_exploit),
            unverified_classes=unverified_classes_of(findings),
            captured_js_files=len(listdir(js_dir(engagement.target_url), limit=1)),
            stop_reason=run.stop_reason or "",
            tools_unavailable=[],  # superseded by tools_not_ready, below
            tools_not_ready=_tool_readiness(),
            sandbox_error=await _sandbox_error(),
            llm_configured=await _planner_configured(),
            auto_run_poc=await _auto_run_enabled(),
            inspection_refusals=_count_inspection_refusals(campaign),
            routeless_findings=int(campaign.get("skipped") or 0),
            routeless_reasons=campaign.get("skipped_reasons") or {},
            # None when the caller did not say, so the panel never claims
            # either way on a path that does not track it.
            reached_exploitation=(PHASE_EXPLOIT in phases_seen
                                  if phases_seen is not None else None),
            last_phase=_last_phase(phases_seen),
        )
        if not limits:
            return
        logger.info("[%s] %s", run.id, summary_line(limits))
        for limit in limits:
            await events.emit(engagement.id, events.THOUGHT, limit.sentence,
                              level=events.LEVEL_INFO, run_id=run.id,
                              limit=limit.key)
    except Exception:  # noqa: BLE001 - explaining must never fail the run
        logger.debug("could not report the verification limits", exc_info=True)


_PHASE_ORDER = ["recon", "mapping", PHASE_VULN, PHASE_EXPLOIT]


def _last_phase(phases_seen: Optional[set]) -> str:
    """The furthest phase the run actually planned, for the limits panel."""
    if not phases_seen:
        return ""
    ordered = [p for p in _PHASE_ORDER if p in phases_seen]
    return ordered[-1] if ordered else sorted(phases_seen)[-1]


async def _report_capture(engagement, run) -> None:
    """Say whether this run will have traffic to analyse.

    IDOR, BFLA, broken access control, JWT and secrets-in-bundles all read the
    captured flows. Nothing routed tool traffic through the capture proxy, so
    on an automated run that table was empty and all of them ran against
    nothing - called, with no input. The difference between a run that can find
    those classes and one that cannot is worth one line at the start.
    """
    try:
        from app.network.privacy import get_network_manager
        from app.proxy.capture import capture_proxy_url
        from app.scans.identity import CAPTURE_WORTH_IT

        anonymity = await get_network_manager().proxy_for_tools_shared()
        if anonymity:
            await events.emit(
                engagement.id, events.PHASE_CHANGED,
                "Crawl traffic will NOT be captured: an anonymity proxy is "
                "configured and a tool takes one proxy flag. Leaking the real "
                "IP is the worse trade. The IDOR, access-control, JWT and "
                "secret-in-JavaScript checks will have nothing to read unless "
                "you browse the target through the proxy yourself.",
                run_id=run.id, level=events.LEVEL_INFO)
            return
        url = capture_proxy_url()
        if url:
            await events.emit(
                engagement.id, events.PHASE_CHANGED,
                f"Crawl traffic is being captured ({', '.join(sorted(CAPTURE_WORTH_IT))} "
                f"-> {url}), so the IDOR, access-control, JWT and "
                f"secret-in-JavaScript checks have something to read.",
                run_id=run.id, level=events.LEVEL_INFO)
        else:
            await events.emit(
                engagement.id, events.PHASE_CHANGED,
                "Crawl traffic will NOT be captured: the capture proxy is not "
                "reachable. The traffic-driven checks (IDOR, access control, "
                "JWT, secrets in JavaScript) will find nothing - they read "
                "captured flows, and there will be none.",
                run_id=run.id, level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001 - reporting must never fail a run
        logger.exception("[%s] could not report the capture state", run.id)


def _tool_readiness() -> list:
    """Which tools cannot do their job. Never raises."""
    try:
        from app.scans.wrappers import not_ready
        return not_ready()
    except Exception:  # noqa: BLE001 - a broken preflight must not fail a run
        logger.exception("could not read tool readiness")
        return []


async def _report_tool_readiness(engagement, run) -> None:
    """Say, at the START of the run, which tools cannot find anything.

    A tool whose data is missing is worse than an absent one: the binary runs,
    exits 0 and reports nothing, so the target looks clean. nuclei is the case
    that matters - five catalog items and six -dast injection families run it,
    and the image downloads its templates with `|| true`, so a throttled build
    leaves a working binary with no templates at all. Said up front, because by
    the end of the run the operator has already drawn their conclusion.
    """
    entries = _tool_readiness()
    broken = [e for e in entries if e.get("installed") and not e.get("ready")]

    # Try to repair the one that is both the most damaging and the most
    # repairable. The image runs `nuclei -update-templates -silent || true` at
    # build time, so a throttled or offline build ships a working binary with
    # no templates - and telling the operator to rebuild is a poor answer when
    # the fix is one command the worker can run itself.
    if any(e.get("tool") == "nuclei" for e in broken):
        if await _repair_nuclei_templates(engagement, run):
            entries = _tool_readiness()
            broken = [e for e in entries
                      if e.get("installed") and not e.get("ready")]

    absent = [e for e in entries if not e.get("installed")]
    for entry in broken:
        await events.emit(
            engagement.id, events.PHASE_CHANGED,
            f"{entry['tool']} is installed but cannot find anything: "
            f"{entry['reason']}",
            run_id=run.id, level=events.LEVEL_INFO, tool=entry["tool"])
    if absent:
        await events.emit(
            engagement.id, events.PHASE_CHANGED,
            f"{len(absent)} tool(s) are not in this image and will be skipped: "
            + ", ".join(sorted(e["tool"] for e in absent)[:12]),
            run_id=run.id, level=events.LEVEL_VERBOSE)


async def _repair_nuclei_templates(engagement, run) -> bool:
    """Download the nuclei templates now. True if it worked.

    Bounded and best-effort: this is a repair, not a dependency. If it fails,
    the caller reports nuclei as unusable, which is the honest answer.
    """
    await events.emit(
        engagement.id, events.PHASE_CHANGED,
        "nuclei has no templates - downloading them now. Without them it scans "
        "for nothing and every target comes back clean.",
        run_id=run.id, level=events.LEVEL_INFO)
    try:
        # NO `-disable-update-check`: it switches off the update subsystem that
        # -update-templates runs through, so the download fetches nothing. The
        # same mistake in the Dockerfile emptied a template set of 14036.
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-update-templates", "-silent",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        _out, err = await asyncio.wait_for(proc.communicate(), timeout=600)
    except asyncio.TimeoutError:
        await events.emit(engagement.id, events.PHASE_CHANGED,
                          "nuclei template download timed out after 10 minutes.",
                          run_id=run.id, level=events.LEVEL_INFO)
        return False
    except Exception as exc:  # noqa: BLE001 - a repair must never fail a run
        logger.exception("[%s] nuclei template download failed", run.id)
        await events.emit(
            engagement.id, events.PHASE_CHANGED,
            f"nuclei template download failed: {exc.__class__.__name__}.",
            run_id=run.id, level=events.LEVEL_INFO)
        return False

    from app.scans.wrappers import get_wrapper
    ok = get_wrapper("nuclei").readiness().ready
    await events.emit(
        engagement.id, events.PHASE_CHANGED,
        "nuclei templates installed." if ok else
        f"nuclei templates still missing after the download "
        f"({(err or b'').decode('utf-8', 'replace')[:200].strip() or 'no error output'}).",
        run_id=run.id, level=events.LEVEL_INFO)
    return ok


async def _sandbox_error() -> str:
    """Why the sandbox cannot run a PoC, or "" if it can.

    run_poc raises SandboxUnavailable with the exact cause - unreachable, egress
    never locked, an image that pins its allowlist at boot, no HTTP client - and
    the campaign turned every one of those into "the exploit did not work", once
    per PoC.
    """
    from app.sandbox import runner_client
    try:
        status = await runner_client.health()
    except Exception as exc:  # noqa: BLE001 - an absent runner is a normal state
        return (f"the sandbox runner is not reachable at "
                f"{runner_client.RUNNER_URL} ({exc.__class__.__name__}). "
                f"Nothing can be executed without it.")
    if not status.get("egress_locked"):
        return ("the sandbox runner started without an egress policy, so it "
                "refuses to run untrusted code.")
    if str(status.get("egress_mode") or "boot") != "per-request":
        return ("the sandbox runner image predates per-request egress: it pins "
                "its allowlist once at boot from SANDBOX_ALLOWED_HOSTS, which "
                "is empty, so it denies every packet a PoC sends. Rebuild it "
                "with: docker compose up -d --build sandbox-runner")
    missing = [n for n, ok in (status.get("clients") or {}).items() if not ok]
    if "python_requests" in missing:
        return ("the sandbox runner has no HTTP client for python, so a PoC "
                "cannot reach the target. Rebuild the sandbox-runner image.")
    return ""


async def _planner_configured() -> bool:
    """Is there a key for the role that writes exploits?"""
    try:
        from app.llm import ROLE_PLANNER, get_router
        return bool(get_router().get(ROLE_PLANNER).configured)
    except Exception:  # noqa: BLE001 - assume configured rather than cry wolf
        return True


async def _auto_run_enabled() -> bool:
    try:
        from app.exploit.settings_live import auto_run_poc
        return bool(await auto_run_poc())
    except Exception:  # noqa: BLE001
        return True


def _count_inspection_refusals(campaign: Dict[str, Any]) -> int:
    """How many staged PoCs the operator-safety gate held back."""
    total = 0
    for plan in campaign.get("plans") or []:
        for attempt in plan.get("attempts") or []:
            reason = str(((attempt.get("auto_run") or {}).get("reason") or "")).lower()
            if "critical signal" in reason or "vetting refused" in reason:
                total += 1
    return total


async def _llm_budget_exceeded(engagement_id: str):
    """Spend so far if it has crossed the per-engagement cap, else None.

    No cap configured means no ceiling. Any failure reading the setting or the
    spend returns None: a budget guardrail that cannot be evaluated must not
    stop a run the operator asked for.
    """
    try:
        from app import settings_store
        from app.llm import usage as llm_usage
        cfg = (await settings_store.get_public()).get("budget") or {}
        limit = cfg.get("per_engagement_usd")
        if not llm_usage.budget_verdict(limit, 0)["limit_usd"]:
            return None   # no cap configured: no ceiling, and no query needed
        spent = await llm_usage.spend(engagement_id)
        verdict = llm_usage.budget_verdict(limit, spent)
        return verdict["spend_usd"] if verdict["over"] else None
    except Exception:  # noqa: BLE001
        logger.debug("could not evaluate the LLM budget", exc_info=True)
        return None


async def _discover_params(engagement, run) -> None:
    """Find injection points before the phase that needs them is planned.

    Seven catalog items - sqlmap, commix, and the nuclei -dast runs for SSRF,
    SSTI, LFI, XXE, open redirect and CRLF - carry
    `applies_when={"requires_params": True}`, which is true only of an endpoint
    ASSET whose URL already carries a query string. So an endpoint with no
    visible parameter is tested as if it had no input at all.

    analyze_params exists to close that, and its own docstring says so:
    "discovered parameters are seeded back as parameterised endpoint assets, so
    the param-gated exploitation items (sqlmap / dalfox / nuclei -dast) test
    them". It ran in `run_analysis`, i.e. during FINALISATION - after every
    scan phase had already been planned and run. The assets it seeded could
    therefore only ever help a second run on the same engagement, and a first
    run on a target full of injection flaws planned no injection test at all
    and reported nothing above "info".

    It still runs in run_analysis as well, where it sees the traffic the scan
    itself captured. This call is the one that can change what gets scanned.
    """
    try:
        from app.analysis.param_discovery import analyze_params
        result = await analyze_params(engagement.id)
        seeded = int(result.get("seeded", 0) or 0)
        if seeded:
            await events.emit(
                engagement.id, events.PHASE_CHANGED,
                f"Seeded {seeded} parameterised endpoint(s) before vuln analysis",
                level=events.LEVEL_VERBOSE, run_id=run.id,
            )
    except Exception:  # noqa: BLE001 - never block the phase transition
        logger.exception("[%s] parameter discovery failed", run.id)


# Passes of _analyse_traffic already done, per run id. The phase can go BACK:
# plan() picks the earliest phase with uncovered work, so a mapping asset
# discovered during vuln_analysis returns the run to mapping and then forward
# again - which would re-enter the transition block and re-run fourteen
# analysers over the same traffic. Idempotent, but not free, and the time it
# costs comes out of the phase budgets.
# Bounded: the worker is long-lived, so an unbounded dict keyed by run id is
# a slow leak. Only the recent runs can still be mid-flight.
_ANALYSED: "OrderedDict[str, set]" = OrderedDict()
_ANALYSED_MAX = 64


async def _analyse_traffic(engagement, run, *, active: bool = False) -> None:
    """Run the traffic analysers DURING the engagement (P0-1).

    They used to run once, from _finalize_engagement. So every finding they
    produce - the IDOR, the broken access control, the JWT weakness, the
    secret in a bundle, the forgotten API - and every lead they put on the
    blackboard arrived AFTER exploitation was over. None of it could steer a
    single exploitation task, which is the whole point of having a board, and
    a run that ended on its budget lost all of it entirely.

    Two passes, because the gate is real. `active=False` is the read-only set,
    run when vuln_analysis starts: it sends nothing the methodology has not
    already sent, so it needs no approval. `active=True` is the set that
    WRITES to the target or bursts it, and it is called only after the
    exploitation checkpoint has been approved - moving analysis earlier must
    not become a way around a human saying yes.

    Still best-effort, and still idempotent: save_analysis_job replaces an
    analyser's previous job, so the finalisation pass supersedes both of these
    once it has seen the traffic exploitation generated.
    """
    key = str(run.id)
    if key not in _ANALYSED:
        _ANALYSED[key] = set()
        while len(_ANALYSED) > _ANALYSED_MAX:
            _ANALYSED.popitem(last=False)
    done = _ANALYSED[key]
    label = "active" if active else "read-only"
    if label in done:
        return
    done.add(label)

    try:
        from app.analysis import (ACTIVE_STEPS, FINAL_ONLY_STEPS,
                                  run_analysis)
        if active:
            result = await run_analysis(engagement.id, allow_active=True,
                                        only=ACTIVE_STEPS)
        else:
            result = await run_analysis(engagement.id, allow_active=False,
                                        skip=ACTIVE_STEPS | FINAL_ONLY_STEPS)
    except Exception:  # noqa: BLE001 - analysis must never fail the run
        logger.exception("[%s] mid-run traffic analysis failed", run.id)
        return

    ran = len(result or {})
    # Counted from the jobs the pass just wrote, not from the result dicts:
    # only 14 of the analysers report a "findings" key, so summing those
    # under-reports and the console would understate what was found.
    # save_analysis_job replaces an analyser's job, so this is exactly what
    # this pass produced.
    found = await _count_analyser_findings(engagement.id, result or {})
    try:
        await events.emit(
            engagement.id, events.THOUGHT,
            f"Traffic analysis ({label}): {ran} analyser(s) over the captured "
            f"traffic"
            + (f", {found} finding(s)" if found >= 0 else "")
            + ". Running it now rather than at the end is what lets these "
              "steer the tests that follow.",
            run_id=run.id, level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001
        logger.debug("could not announce the traffic analysis")


async def _count_analyser_findings(engagement_id: str,
                                   result: Dict[str, Any]) -> int:
    """How many findings the analysers that just ran actually stored.

    Returns -1 when it cannot be counted, so the caller can say "unknown"
    rather than print a confident zero.
    """
    try:
        from app import db
        from app.analysis import ANALYSER_TOOLS
        # The step keys use underscores ("js_recon"); the job tool names are
        # the hyphenated ones the UI knows ("js-recon"). Match either.
        ran = {name for name in result}
        tools = [t for t in ANALYSER_TOOLS
                 if t in ran or t.replace("-", "_") in ran]
        if not tools:
            return 0
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COALESCE(SUM(jsonb_array_length(findings_json::jsonb)), 0) "
                "AS n FROM jobs WHERE engagement_id = $1 AND tool = ANY($2)",
                engagement_id, tools)
        return int((row or {}).get("n") or 0)
    except Exception:  # noqa: BLE001 - a count is not worth a failure
        logger.debug("[%s] could not count analyser findings", engagement_id)
        return -1


async def _hunt_shadow_apis(engagement, run) -> None:
    """Find the API versions the application stopped calling, before scanning.

    OWASP API9 is the only item on the API Top 10 that is not a bug in a line
    of code: /api/v2 is current and reviewed, /api/v1 is still answering two
    years after anyone thought about it, and the gap between them is three
    years of security work the old version never received.

    This runs here rather than only in run_analysis because it SEEDS: every
    forgotten version that answers becomes an endpoint asset, so the vuln
    phase applies the same catalog to it that the current version gets.
    Reporting v1 and never scanning it would leave the report claiming the
    surface was covered while the one unmaintained version was skipped.
    """
    try:
        from app.analysis.api_inventory import analyze_api_inventory
        result = await analyze_api_inventory(engagement.id)
        live = int(result.get("live", 0) or 0)
        seeded = int(result.get("seeded", 0) or 0)
        if live:
            await events.emit(
                engagement.id, events.PHASE_CHANGED,
                f"Found {live} forgotten API endpoint(s) the application no "
                f"longer calls; {seeded} added to the scan surface",
                level=events.LEVEL_INFO, run_id=run.id,
            )
    except Exception:  # noqa: BLE001 - never block the phase transition
        logger.exception("[%s] shadow API hunt failed", run.id)


async def _synthesise_api_schema(engagement, run) -> None:
    """Build an OpenAPI schema from the captured traffic, before vuln analysis.

    The contract tests (schemathesis) are the only thing in the catalog that
    reasons about an API as a set of OPERATIONS rather than a set of URLs, and
    they applied only to an asset whose URL names a published schema. Most
    targets publish none, so on most targets they never ran.

    This builds one from what the crawl was actually seen to speak to, which is
    both what the application really exposes and, by definition, the half no
    documentation covers. VULN-API-OBSERVED then tests it with `--url` pointing
    back at the live target, and refuses itself when nothing was built.
    """
    try:
        from app.analysis.openapi_synth import synthesise
        result = await synthesise(engagement.id, run_id=run.id)
        count = int(result.get("operations", 0) or 0)
        if count:
            await events.emit(
                engagement.id, events.PHASE_CHANGED,
                f"Synthesised an API schema with {count} operation(s) from "
                f"captured traffic",
                level=events.LEVEL_VERBOSE, run_id=run.id,
            )
    except Exception:  # noqa: BLE001 - never block the phase transition
        logger.exception("[%s] could not synthesise an API schema", run.id)


async def _materialise_js(engagement, run) -> None:
    """Write the captured JavaScript to disk before the vuln phase runs.

    retire.js and jsluice read files, not URLs, and the analyzer that has the
    bundles in hand (js_recon) only runs during finalisation - after every scan
    phase is over. Without this the two tools would be scheduled against an
    empty directory and would report nothing, every time.
    """
    try:
        from app.analysis.js_cache import materialise_js
        result = await materialise_js(engagement.id)
        written = int(result.get("written", 0) or 0)
        if written:
            await events.emit(
                engagement.id, events.PHASE_CHANGED,
                f"Cached {written} JavaScript file(s) for client-side analysis",
                level=events.LEVEL_VERBOSE, run_id=run.id,
            )
    except Exception:  # noqa: BLE001 - never block the phase transition
        logger.exception("[%s] could not cache captured JavaScript", run.id)


async def _run_correlation(engagement, run: Run, executor: Executor,
                           runs: RunRepository) -> int:
    """Join the recon signals and launch what the join suggests.

    Runs once, when vuln analysis starts: recon and mapping have produced the
    assets, fingerprints and captured traffic, and there is still a whole scan
    left for the leads to influence.

    Leads go through executor.launch() like any other task, so the engagement
    authorization and scope gate in Runner.submit() applies unchanged - the
    model can propose, it cannot widen the target set.
    """
    try:
        from app.analysis.correlation import correlate
        from app.orchestrator.planner import Task
        from app.proxy.storage import FlowRepository
        from app.validation import ValidatedFindingRepository

        state = executor.state
        assets = await state.assets()
        if not assets:
            return 0

        technologies = await state.technologies()
        findings = await ValidatedFindingRepository().list(engagement.id)
        try:
            flows = await FlowRepository().list_flows(limit=200)
        except Exception:  # noqa: BLE001 - proxy may be empty or unavailable
            flows = []

        result = await correlate(
            assets=assets,
            technologies=technologies,
            findings=findings,
            flows=flows,
            coverage_summary=await state.coverage_summary(),
        )
    except Exception as exc:  # noqa: BLE001 - correlation must never break a run
        logger.warning("[%s] correlation skipped: %s", run.id, exc)
        return 0

    leads = result.get("leads") or []
    if result.get("summary"):
        await events.emit(engagement.id, events.PHASE_CHANGED,
                          f"Correlation: {result['summary']}",
                          run_id=run.id, level=events.LEVEL_VERBOSE)
    if not leads:
        return 0

    launched = 0
    for lead in leads:
        options: List[str] = []
        if lead["tool"] == "nuclei" and lead.get("tags"):
            options = ["-tags", ",".join(lead["tags"])]

        task = Task(
            catalog_item_id=f"CORRELATED-{lead['tool'].upper()}",
            asset_value=lead["asset"],
            tool=lead["tool"],
            options=options,
            phase=PHASE_VULN,
        )
        try:
            job = await executor.launch(task)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] correlated lead failed to launch", run.id)
            continue
        if job is None:
            continue

        launched += 1
        run.jobs_launched += 1
        await events.emit(
            engagement.id, events.TASK_LAUNCHED,
            f"correlated: {lead['tool']} -> {lead['asset']} ({lead['rationale']})",
            run_id=run.id, tool=lead["tool"], target=lead["asset"],
            catalog_item=task.catalog_item_id,
        )

    if launched:
        await runs.update(run)
    logger.info("[%s] correlation launched %d/%d lead(s)", run.id, launched, len(leads))
    return launched


# How long a cancelled run may spend validating what it already has. The
# operator pressed Stop and is watching; a bounded wait with a line in the
# console is the trade, and losing the whole run's work is not.
CANCEL_SALVAGE_SECONDS = 120


async def _drain_scan_jobs(engagement, run: Run) -> int:
    """Abort this engagement's scan jobs still queued or running in arq.

    When a run ends - cancelled at the worker's job_timeout, or stopped at a
    budget - the scan jobs it enqueued do NOT stop with it: arq keeps handing
    them to the scans worker, which runs nuclei/sqlmap for up to their own
    1800s timeout each, long after the run is over. On the live run, 16 jobs
    were still queued/running at the cancel, burning the 2-core VM for hours;
    nothing ingests their findings (the loop that would is gone) and - before
    the coverage reclaim - they pinned their injection points as 'covered' for
    the next run.

    arq's job id IS our job id (enqueue_job(..., _job_id=job.id)), so the
    runner's cancel targets each directly: the scans worker catches the
    CancelledError, SIGTERMs the subprocess and marks the job cancelled. Aborts
    run concurrently so dozens of orphans do not cost dozens of 5s round-trips.
    Never raises - draining is cleanup, it must not turn a stop into a crash.
    """
    from app.scans.runner import get_runner

    try:
        jobs = await JobRepository().list_by_engagement(engagement.id, limit=2000)
    except Exception:  # noqa: BLE001
        logger.exception("[%s] could not list jobs to drain", run.id)
        return 0
    pending = [j for j in jobs
               if j.status in (JobStatus.QUEUED, JobStatus.RUNNING)]
    if not pending:
        return 0

    runner = get_runner()
    results = await asyncio.gather(
        *[runner.cancel(j.id) for j in pending], return_exceptions=True)
    aborted = sum(1 for r in results if r is True)
    logger.info("[%s] drained %d/%d unfinished scan job(s)",
                run.id, aborted, len(pending))
    try:
        await events.emit(
            engagement.id, events.PHASE_CHANGED,
            f"Stopped {aborted} unfinished scan job(s) left over from this run "
            "so they do not keep running after it ends.",
            run_id=run.id, level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001 - reporting must not fail the drain
        logger.debug("could not report the scan-job drain")
    return aborted


async def _salvage_on_cancel(engagement, run: Run, runs: RunRepository,
                             state: EngagementState,
                             phases_seen: Optional[set] = None) -> None:
    """Validate a cancelled run's findings within a bounded window.

    Never raises anything but CancelledError: a second cancel means the
    operator wants it to stop now, and that is answered immediately.
    """
    try:
        await events.emit(
            engagement.id, events.THOUGHT,
            f"Run cancelled after {run.jobs_launched} job(s). Validating what "
            f"it already found before stopping - up to "
            f"{CANCEL_SALVAGE_SECONDS}s. Active exploitation is skipped: you "
            f"stopped the run.",
            level=events.LEVEL_INFO, run_id=run.id)
    except Exception:  # noqa: BLE001
        logger.debug("[%s] could not announce the salvage", run.id)

    try:
        await asyncio.wait_for(
            _finalize_engagement(engagement, run, runs, state,
                                 phases_seen=phases_seen),
            timeout=CANCEL_SALVAGE_SECONDS)
    except asyncio.CancelledError:
        raise                       # cancelled again: stop now
    except asyncio.TimeoutError:
        logger.warning("[%s] salvage validation timed out", run.id)
        try:
            await events.emit(
                engagement.id, events.THOUGHT,
                f"Validation of the cancelled run did not finish within "
                f"{CANCEL_SALVAGE_SECONDS}s. The findings it did validate are "
                f"on the Findings page; re-run validation from the engagement "
                f"to finish the rest.",
                level=events.LEVEL_INFO, run_id=run.id)
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001 - salvage must never mask the cancel
        logger.exception("[%s] salvage validation failed", run.id)


async def _finalize_engagement(engagement, run: Run, runs: RunRepository,
                               state: EngagementState,
                               phases_seen: Optional[set] = None) -> None:
    """Everything after the plan/execute loop: analysis, active exploitation,
    validation, the LLM judge, adaptive probes and kill-chains.

    Lifted out of run_engagement_loop, which had grown to 355 lines as each of
    these phases was added - long enough that the recon deadlock hid in it.
    Each step stays best-effort: none of them may fail the run.
    """
    run.phase = "validation"
    await runs.update(run)
    await events.emit(engagement.id, events.PHASE_CHANGED, "Phase: validation",
                      run_id=run.id, phase="validation")
    try:
        # Traffic-driven analysis (logic/IDOR/CSRF/BFLA, JS secrets+endpoints,
        # JWT, access-control, CORS, params, GraphQL) over captured traffic.
        from app.analysis import run_analysis
        _active_ok = run.stop_reason not in {"exploit_denied", "stopped", "cancelled"}
        await run_analysis(engagement.id, allow_active=_active_ok)
        # Threat-intel enrichment (read-only third-party APIs: Shodan / Censys /
        # VirusTotal). Internet-visible ports, service versions and reputation -
        # adds surface even on a WAF'd target, and never touches it. Skipped
        # entirely when no provider key is configured.
        try:
            from app.intel import run_intel
            await run_intel(engagement.id)
        except Exception:  # noqa: BLE001 - enrichment never fails a run
            logger.exception("[%s] intel enrichment error", run.id)
        # Proof-of-impact: prove confirmed injections (RCE/SQLi) with a
        # benign read-only command. Double opt-in: requires
        # allow_active_exploit (the exploitation phase already passed its
        # approval checkpoint, which is the other gate).
        # ...but never run active exploitation if the operator denied the
        # exploitation checkpoint or stopped/cancelled the run.
        _suppressed = {"exploit_denied", "stopped", "cancelled"}

        # Say it is the exploitation phase while it IS the exploitation phase.
        # This block runs the known-CVE pass, the auth spray and the proof of
        # impact, and it used to do all of that while the UI read "validation"
        # - so an operator watching the live view saw the most consequential
        # part of the run under the wrong banner.
        run.phase = PHASE_EXPLOIT
        await runs.update(run)
        await events.emit(engagement.id, events.PHASE_CHANGED,
                          f"Phase: {PHASE_EXPLOIT}", run_id=run.id,
                          phase=PHASE_EXPLOIT)

        if engagement.allow_active_exploit and run.stop_reason not in _suppressed:
            try:
                from app.exploit import (prove_impact, run_auth_spray,
                                         run_known_exploits)
                # Known-CVE exploitation: run the public PoC templates for the
                # fingerprinted stack (OOB-confirmed) before proof-of-impact.
                await run_known_exploits(engagement.id)
                await run_auth_spray(engagement.id)
                await prove_impact(engagement.id)
            except Exception:  # noqa: BLE001 - never fail the run on proof
                logger.exception("[%s] active-exploit phase error", run.id)

        # Which public PoCs exist for every CVE found - Exploit-DB via the
        # local searchsploit database, real GitHub PoC repositories, and the
        # advisory links.
        #
        # Deliberately OUTSIDE the allow_active_exploit gate above. It is
        # read-only: it queries a local database and a search API, and never
        # touches the target. Gating it would withhold exactly the information
        # an operator needs in order to decide whether to allow exploitation at
        # all - and an engagement that stops short of exploiting still wants
        # "a working public exploit exists for this" in its report.
        #
        # It runs AFTER the block above rather than before it, because the
        # known-CVE pass finds CVEs of its own and the aggregation was missing
        # every one of them.
        try:
            from app.analysis import analyze_public_exploits
            await analyze_public_exploits(engagement.id)
        except Exception:  # noqa: BLE001 - enrichment never fails a run
            logger.exception("[%s] public-exploit aggregation error", run.id)

        run.phase = "validation"
        await runs.update(run)
        await events.emit(engagement.id, events.PHASE_CHANGED, "Phase: validation",
                          run_id=run.id, phase="validation")

        stats = await validate_engagement(engagement.id)

        # The campaign: walk every VALIDATED finding, follow every route to
        # proving it, and stop at the first that works.
        #
        # It must run AFTER validate_engagement, which is what creates the
        # validated findings it reads. It used to run nine lines earlier, found
        # an empty table on a first run, and returned through a silent early
        # exit - no plan, no PoC, no event. Every finding then stayed "likely"
        # with nothing in the console to say why.
        #
        # Outside the active-exploit gate on purpose: fetching a repository and
        # asking a model both happen without touching the target. Executing a
        # staged PoC is where the gate bites, and execute_poc re-checks it.
        campaign_result: Dict[str, Any] = {}
        try:
            from app.exploit import run_campaign
            campaign_result = await run_campaign(engagement.id) or {}
        except Exception:  # noqa: BLE001 - one dead route is not the run
            logger.exception("[%s] exploitation campaign error", run.id)

        # Leaked cloud creds -> prove blast radius with read-only identity and
        # permission probes. It reads VALIDATED findings to find the key, so it
        # belongs here and not in the exploitation block above, where it ran
        # before validation had written a single row and therefore never found
        # one. Active, so it still self-gates on allow_active_exploit.
        if engagement.allow_active_exploit and run.stop_reason not in _suppressed:
            try:
                from app.intel.cloud_creds import probe_leaked_cloud_creds
                await probe_leaked_cloud_creds(engagement.id)
            except Exception:  # noqa: BLE001 - never fail the run on a probe
                logger.exception("[%s] cloud-credential probe error", run.id)

        # Intelligence #3: LLM judge pass to kill false positives / confirm
        # with grounded evidence (best-effort; no-op without an LLM).
        try:
            from app.validation.llm_judge import judge_engagement
            await judge_engagement(engagement.id)
        except Exception:  # noqa: BLE001 - judging never fails the run
            logger.exception("[%s] llm-judge error", run.id)

        # Shadow judge: opt-in, runs a second opinion alongside the real one and
        # records where they disagree. It CANNOT move a verdict - it only calls
        # set_metadata - so it runs after the real judge has finished and is
        # pure evaluation. Off unless SHADOW_JUDGE_BACKEND is set. Kept entirely
        # inside its own try: a model under evaluation must not be able to fail
        # the run it is being evaluated against.
        from app.config import settings as _settings
        _shadow_backend = (_settings.shadow_judge_backend or "").strip()
        if _shadow_backend:
            try:
                from app.validation.second_opinion import resolve
                from app.validation.shadow import run_shadow_judge
                fn, label = resolve(_shadow_backend)
                if fn is None:
                    logger.info("[%s] shadow judge not run: %s", run.id, label)
                else:
                    await run_shadow_judge(engagement.id, second_opinion=fn,
                                           backend=label)
            except Exception:  # noqa: BLE001 - the shadow never fails the run
                logger.exception("[%s] shadow-judge error", run.id)
        # Intelligence #5: settle what is still 'likely' by firing an
        # adaptive, oracle-backed probe at the target. Active, so it obeys
        # the same gate + denial suppression as the exploitation block.
        if engagement.allow_active_exploit and run.stop_reason not in _suppressed:
            try:
                from app.exploit.payload_gen import run_payload_validation
                await run_payload_validation(engagement.id)
            except Exception:  # noqa: BLE001 - probing never fails the run
                logger.exception("[%s] payload-probe error", run.id)
        # Fold this engagement's final verdicts into the cross-engagement
        # memory, so the next run on a similar stack starts informed. Verdicts
        # are final by here: the judge and the probes have both run.
        try:
            from app import memory
            await memory.record_engagement(engagement.id)
        except Exception:  # noqa: BLE001 - memory must never fail a run
            logger.exception("[%s] memory update failed", run.id)

        chains = await build_chains(engagement.id)

        # Chained exploitation: now that the chains are drawn and each finding
        # has been exploited on its own, author one PoC per multi-step chain
        # that runs the steps in order - feeding each step what the last one
        # produced. Like run_campaign it only authors and stages (no target is
        # touched until a human approves and runs it), so it runs regardless of
        # allow_active_exploit; the run endpoint is where the gate bites.
        try:
            from app.exploit.chain_exploit import run_chain_campaign
            await run_chain_campaign(engagement.id)
        except Exception:  # noqa: BLE001 - one dead chain is not the run
            logger.exception("[%s] chain-exploit campaign error", run.id)

        # Re-read the counts. `stats` was captured before run_campaign, the
        # cloud-credential probe, the judge and the payload prober - and all
        # four of them move verdicts. Emitting that dict here meant the one
        # line the operator actually reads said "0 confirmed" even on a run
        # that had just confirmed several, while the dashboard (which queries
        # live) disagreed with it.
        try:
            from app.validation import ValidatedFindingRepository as _VFRepo
            final_stats = await _VFRepo().summary(engagement.id)
        except Exception:  # noqa: BLE001 - a failed count must not fail the run
            logger.exception("[%s] could not re-read the validation summary", run.id)
            final_stats = dict(stats)

        await audit(
            "engagement.validated",
            engagement_id=engagement.id, run_id=run.id,
            stats=final_stats,
            # Kept, and labelled, because the difference between the two is
            # exactly what the exploitation phase achieved.
            stats_before_exploitation=stats,
        )
        await events.emit(engagement.id, events.VALIDATED,
                          f"Validated: {final_stats.get('confirmed',0)} confirmed, "
                          f"{final_stats.get('false_positive',0)} false positive",
                          run_id=run.id, stats=final_stats)

        # "0 confirmed" reads as "the scanner is broken". Usually it means an
        # oracle existed but a switch kept it from running, or the input it
        # needs was never captured. Say which, or the operator has to guess.
        await _report_verification_limits(engagement, run, campaign_result,
                                          phases_seen=phases_seen)
        if chains:
            await events.emit(engagement.id, events.CHAIN_BUILT,
                              f"{len(chains)} kill-chain(s) identified",
                              run_id=run.id, count=len(chains))
    except Exception:  # noqa: BLE001 - validation must not fail the run
        logger.exception("[%s] validation phase error", run.id)

    # Purge the captured traffic now that every analyser has read it. The
    # bodies are transient working data - a crawl of a real site is gigabytes
    # of them, which is what filled a small VM's disk mid-run - and the
    # findings already hold the evidence that mattered. Off by default so a
    # roomy box keeps the Proxy page populated after a run; on a small one,
    # set PURGE_FLOWS_AFTER_RUN=true.
    await _purge_captured_traffic(engagement, run)


async def _purge_captured_traffic(engagement, run: Run) -> None:
    import os
    if os.getenv("PURGE_FLOWS_AFTER_RUN", "false").strip().lower() not in (
            "1", "true", "yes", "on"):
        return
    try:
        from app.proxy import FlowRepository
        freed = await FlowRepository().purge()
        await events.emit(
            engagement.id, events.THOUGHT,
            f"Purged {freed} captured flow(s) after analysis to reclaim disk; "
            f"the findings keep their evidence. Set PURGE_FLOWS_AFTER_RUN=false "
            f"to keep the raw traffic.",
            level=events.LEVEL_VERBOSE, run_id=run.id)
    except Exception:  # noqa: BLE001 - a failed purge must never fail the run
        logger.exception("[%s] could not purge captured traffic", run.id)


async def _seed_resolved_ips(state: "EngagementState", engagement) -> None:
    """Resolve the target host to its IP(s); add them to scope and the surface.

    The IP a hostname points at is the same server. Without this, the ports and
    service findings keyed to that IP (nmap reports the address, not the name)
    were all rejected as out-of-scope and the host was never tested by address.
    Scope is widened only to the target's own resolved addresses - nothing else.
    """
    import socket

    host = (engagement.target_host or "").strip().lower()
    if not host:
        return

    # DNS resolution (skipped when the target is already an IP). A DNS failure
    # is not fatal: we can still widen scope to the registrable domain below.
    ips: list = []
    if not _looks_like_ip(host):
        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
            ips = sorted({i[4][0] for i in infos if i and i[4]})
        except Exception:  # noqa: BLE001
            ips = []

    new_scope = list(engagement.scope_hosts)
    added = []
    for ip in ips:
        await state.add_asset("host", ip, source="dns")
        if ip not in new_scope:
            new_scope.append(ip)
            added.append(ip)

    if added:
        engagement.scope_hosts = new_scope
        try:
            await EngagementRepository().update(engagement)
            await audit("engagement.scope_resolved_ip", engagement_id=engagement.id,
                        host=host, added=added)
            await events.emit(
                engagement.id, events.ASSET_FOUND,
                f"Resolved {host} -> {', '.join(added)} (added to scope)",
                level=events.LEVEL_INFO)
        except Exception:  # noqa: BLE001
            logger.exception("could not persist resolved scope")


def _looks_like_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _seed_from_proxy(state: "EngagementState", engagement) -> int:
    """Add in-scope captured proxy requests as endpoint assets. Endpoints with
    query parameters unlock the param-gated tests (sqlmap/dalfox/nuclei-dast)
    against the real surface the operator exercised."""
    from urllib.parse import urlparse
    from app.proxy import FlowRepository

    try:
        flows = await FlowRepository().list_flows(limit=1000)
    except Exception:  # noqa: BLE001
        return 0

    seen = set()
    count = 0
    for f in flows:
        host = (urlparse(f.url).hostname or "").lower()
        if not engagement.host_in_scope(host):
            continue
        # Normalize (drop fragment); de-dupe identical URLs.
        if f.url in seen:
            continue
        seen.add(f.url)
        await state.add_asset("endpoint", f.url, source="proxy")
        count += 1
        if count >= 500:
            break
    return count


async def _await_exploit_approval(
    approvals: "ApprovalRepository",
    runs: RunRepository,
    engagement_id: str,
    run_id: str,
    batch,
) -> bool:
    """Create an approval request for the exploitation batch and block until a
    human approves/denies it (or the run is stopped). Returns True to proceed."""
    existing = await approvals.pending_for_run(run_id)
    if existing is None:
        tools = sorted({t.tool for t in batch})
        targets = sorted({t.asset_value for t in batch})[:10]
        appr = await approvals.create(
            engagement_id, run_id,
            summary=f"Approve exploitation phase: {', '.join(tools)} on {len(targets)} target(s)",
            tools=tools, targets=targets,
        )
        await events.emit(engagement_id, events.APPROVAL_REQUIRED,
                          "Exploitation requires approval", run_id=run_id,
                          approval_id=appr.id, tools=tools, targets=targets)
    # Poll until resolved or stopped.
    while True:
        if await runs.stop_requested(run_id):
            return False
        decision = await approvals.decision_for_run(run_id)
        if decision == "approved":
            await events.emit(engagement_id, events.APPROVAL_RESOLVED,
                              "Exploitation approved", run_id=run_id, decision="approved")
            return True
        if decision == "denied":
            await events.emit(engagement_id, events.APPROVAL_RESOLVED,
                              "Exploitation denied", run_id=run_id, decision="denied")
            return False
        await asyncio.sleep(POLL_INTERVAL)


async def _wait_for_jobs(
    jobs_repo: JobRepository,
    job_ids: List[str],
    runs: RunRepository,
    run_id: str,
) -> list:
    """Poll until all jobs reach a terminal state, the per-batch cap elapses,
    or a stop is requested. Returns the finished Job objects."""
    deadline = time.time() + ITERATION_WAIT_CAP
    pending = set(job_ids)
    finished = []

    while pending and time.time() < deadline:
        if await runs.stop_requested(run_id):
            break
        # Touch the heartbeat on every poll, not once per run. A batch can sit
        # here for minutes; without this a live run looks as stale as a dead
        # one, so the reaper (which keys off heartbeat age) cannot tell them
        # apart and would reap a healthy long run.
        try:
            await runs.heartbeat(run_id)
        except Exception:  # noqa: BLE001 - a heartbeat miss must not stop a wait
            pass
        await asyncio.sleep(POLL_INTERVAL)
        for jid in list(pending):
            job = await jobs_repo.get(jid)
            if job is None:
                pending.discard(jid)
                continue
            if job.status.value in _TERMINAL:
                finished.append(job)
                pending.discard(jid)

    # Pull whatever reached a terminal state but we missed; do NOT include jobs
    # still QUEUED/RUNNING (ingesting those would mark them 'error' = covered,
    # so their real test never runs and never retries). Their coverage stays
    # 'running' from launch; a later run can pick them up.
    for jid in pending:
        job = await jobs_repo.get(jid)
        if job is not None and job.status.value in _TERMINAL:
            finished.append(job)
    return finished


async def _finalize(runs: RunRepository, run: Run) -> None:
    run.finished_at = time.time()
    await runs.update(run)


async def _fail(runs: RunRepository, run: Run, error: str) -> None:
    run.status = "failed"
    run.error = error
    run.finished_at = time.time()
    await runs.update(run)
