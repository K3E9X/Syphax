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
from typing import List, Optional

from app.audit import audit
from app import events
from app.engagements import EngagementRepository, EngagementStatus
from app.orchestrator.approvals import ApprovalRepository, requires_exploit_approval
from app.orchestrator.executor import Executor
from app.orchestrator.planner import Planner
from app.orchestrator.runs import Run, RunRepository
from app.orchestrator.state import EngagementState
from app.methodology import PHASE_EXPLOIT, PHASE_VULN
from app.scans.models import JobStatus
from app.scans.storage import JobRepository
from app.validation import build_chains, validate_engagement

logger = logging.getLogger("syphax.orchestrator.loop")

# Safety defaults when the engagement sets no budget.
DEFAULT_MAX_JOBS = 200
DEFAULT_MAX_SECONDS = 2 * 60 * 60          # 2 hours
MAX_ITERATIONS = 50
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

    max_jobs = engagement.budget_requests or DEFAULT_MAX_JOBS
    deadline = time.time() + (engagement.budget_seconds or DEFAULT_MAX_SECONDS)

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
                batch = await planner.plan(max_tasks=BATCH_SIZE)
                if not batch:
                    logger.info("[%s] coverage saturated after %d iterations", run.id, iteration)
                    run.stop_reason = "coverage_saturated"
                    break

                run.iterations = iteration + 1
                run.phase = batch[0].phase
                await runs.update(run)
                if batch[0].phase != current_phase:
                    current_phase = batch[0].phase
                    await events.emit(engagement.id, events.PHASE_CHANGED,
                                      f"Phase: {current_phase}", run_id=run.id, phase=current_phase)

                    # Recon and mapping are done by the time vuln analysis
                    # starts, so this is the moment the picture is complete
                    # enough to be worth joining - and still early enough for
                    # the leads to change what gets scanned.
                    if current_phase == PHASE_VULN:
                        await _materialise_js(engagement, run)
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

                # Launch the batch (respecting the remaining job budget).
                launched_ids: List[str] = []
                for task in batch:
                    if run.jobs_launched >= max_jobs:
                        break
                    job = await executor.launch(task)
                    if job is not None:
                        launched_ids.append(job.id)
                        run.jobs_launched += 1
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

        # Validation phase: confirm findings with safe PoC, then build chains.
        # Always run it (even on stop) so partial results are still validated.
        await _finalize_engagement(engagement, run, runs, state)

        if run.status != "stopped":
            run.status = "completed"
    except asyncio.CancelledError:
        run.status = "stopped"
        run.stop_reason = run.stop_reason or "cancelled"
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
        from app.scans.storage import JobRepository as _Jobs
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


async def _finalize_engagement(engagement, run: Run, runs: RunRepository,
                               state: EngagementState) -> None:
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
        # Proof-of-impact: prove confirmed injections (RCE/SQLi) with a
        # benign read-only command. Double opt-in: requires
        # allow_active_exploit (the exploitation phase already passed its
        # approval checkpoint, which is the other gate).
        # ...but never run active exploitation if the operator denied the
        # exploitation checkpoint or stopped/cancelled the run.
        _suppressed = {"exploit_denied", "stopped", "cancelled"}
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
        stats = await validate_engagement(engagement.id)
        # Intelligence #3: LLM judge pass to kill false positives / confirm
        # with grounded evidence (best-effort; no-op without an LLM).
        try:
            from app.validation.llm_judge import judge_engagement
            await judge_engagement(engagement.id)
        except Exception:  # noqa: BLE001 - judging never fails the run
            logger.exception("[%s] llm-judge error", run.id)
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
        await audit(
            "engagement.validated",
            engagement_id=engagement.id, run_id=run.id, stats=stats,
        )
        await events.emit(engagement.id, events.VALIDATED,
                          f"Validated: {stats.get('confirmed',0)} confirmed, "
                          f"{stats.get('false_positive',0)} false positive",
                          run_id=run.id, stats=stats)
        if chains:
            await events.emit(engagement.id, events.CHAIN_BUILT,
                              f"{len(chains)} kill-chain(s) identified",
                              run_id=run.id, count=len(chains))
    except Exception:  # noqa: BLE001 - validation must not fail the run
        logger.exception("[%s] validation phase error", run.id)


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
