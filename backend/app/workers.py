"""arq worker: picks scan jobs off Redis and executes the wrapper subprocess.

Runs as a separate container (see the 'worker' service in docker-compose). The
FastAPI process only enqueues; this process is the only one that actually
spawns nuclei/sqlmap/ffuf/etc.

Cancellation: the API calls arq.connections.ArqRedis.abort_job(job_id). arq
sends an asyncio.CancelledError into the task; we catch it and SIGTERM the
subprocess in finally so the binary releases its resources cleanly.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from arq import cron

from app import db
from app.queue import close_arq_pool, get_arq_pool  # noqa: F401
from app.queue import ORCH_JOB_TIMEOUT_SECONDS, ORCHESTRATOR_QUEUE
from app.queue import redis_settings as _redis_settings
import app.audit  # noqa: F401  - register schema
import app.engagements.storage  # noqa: F401  - register schema
import app.events  # noqa: F401  - register schema
import app.llm.usage  # noqa: F401  - register schema
import app.memory  # noqa: F401  - register schema
import app.network.shared_state  # noqa: F401  - register schema
import app.orchestrator.state  # noqa: F401  - register schema
import app.orchestrator.runs  # noqa: F401  - register schema
import app.orchestrator.approvals  # noqa: F401  - register schema
import app.proxy.storage  # noqa: F401  - register schema
import app.scans.storage  # noqa: F401  - register schema
import app.validation.storage  # noqa: F401  - register schema

from app.orchestrator.loop import run_engagement_loop
from app.scans.models import Finding, JobStatus
from app.scans.storage import JobRepository
from app.scans.wrappers import get_wrapper
from app.scans.wrappers.base import cap_findings

logger = logging.getLogger("syphax.worker")

# Same caps as the in-process Runner had.
MAX_STREAM_BYTES = 1 * 1024 * 1024  # 1 MiB


# -----------------------------------------------------------------------------
# Task implementation
# -----------------------------------------------------------------------------

async def _missing_capability(wrapper, job) -> str:
    """"" when this engagement may run this tool, else what is missing.

    Fails CLOSED: a tool that declares a requirement and whose engagement
    cannot be read is refused, because the safe reading of "we do not know
    what was authorised" is "not this".
    """
    required = [str(c) for c in getattr(wrapper, "requires_capability", ()) or ()]
    if not required:
        return ""
    if not job.engagement_id:
        return (f"{job.tool} needs the {', '.join(required)} capability, and "
                f"this job is not attached to an engagement that could "
                f"declare it")
    try:
        from app.engagements import EngagementRepository
        from app.exploit.capabilities import BY_ID, granted
        eng = await EngagementRepository().get(job.engagement_id)
        if eng is None:
            return f"{job.tool} needs {', '.join(required)}; the engagement is gone"
        have = granted(eng)
        missing = [c for c in required if c not in have]
        if not missing:
            return ""
        labels = [BY_ID[c].label if c in BY_ID else c for c in missing]
        return (f"{job.tool} changes systems rather than reading them, so it "
                f"needs {', '.join(labels)} declared on this engagement. Turn "
                f"it on in the engagement's capabilities if the written "
                f"authorisation covers it - the report prints what was "
                f"declared.")
    except Exception:  # noqa: BLE001 - unreadable authorisation is a refusal
        logger.exception("[%s] could not read the engagement's capabilities", job.id)
        return (f"{job.tool} needs {', '.join(required)} and the engagement's "
                f"capabilities could not be read, so it was not run")


def parse_and_cap(wrapper, job, stdout: bytes, stderr: bytes,
                  exit_code: int) -> List[Finding]:
    """Parse one job's output and bound what it may contribute.

    The ONLY place a wrapper is parsed. The cap is universal only because
    this is: a discovery tool reports one item per thing it finds, and on a
    real target that is thousands. gau turned an archive into 2175 findings
    and 2162 assets, and since the planner builds a task per (catalog item x
    asset) the run then spent its entire TIME budget on them. katana, ffuf,
    httpx, subfinder, dnsx and kiterunner have the same shape. Nothing
    critical or high is ever dropped - see cap_findings.

    `exit_code` is -1 for a cancelled job, whose output is a truncated
    stream; every wrapper parses a line at a time and tolerates that.
    """
    result = wrapper.parse(stdout, stderr, exit_code, job.target)
    before = len(result.findings)
    findings = cap_findings(result.findings, tool=job.tool,
                            category=getattr(wrapper, "category", ""))
    if len(findings) != before:
        logger.info("[%s] %s produced %d findings; capped to %d",
                    job.id, job.tool, before, len(findings))
    return findings


async def run_scan(ctx: Dict[str, Any], job_id: str) -> Dict[str, Any]:
    """arq task. Load the job from Postgres, run the wrapper, persist results.

    Returns a tiny status dict (arq stores it as the job result).
    """
    repo = JobRepository()
    job = await repo.get(job_id)
    if job is None:
        logger.error("run_scan: job %s not found in DB", job_id)
        return {"job_id": job_id, "status": "missing"}

    wrapper = get_wrapper(job.tool)

    # Is this engagement allowed to run this tool at all? A handful of tools
    # do not read a target, they change it - and that is a decision for the
    # operator holding the authorisation, declared per engagement, not for
    # the wrapper's author. Checked here, before the process exists, so
    # launching the job directly cannot step around it.
    blocked_cap = await _missing_capability(wrapper, job)
    if blocked_cap:
        job.status = JobStatus.SUCCEEDED
        job.started_at = job.started_at or time.time()
        job.finished_at = time.time()
        job.findings = []
        job.error = f"not run: {blocked_cap}"
        await repo.update(job)
        logger.info("[%s] %s refused: %s", job.id, job.tool, blocked_cap)
        if job.engagement_id:
            from app import events
            await events.emit(
                job.engagement_id, events.THOUGHT,
                f"{job.tool} was not run on {job.target}: {blocked_cap}",
                level=events.LEVEL_INFO, tool=job.tool, job_id=job.id)
        return {"job_id": job_id, "status": job.status.value, "skipped": True}

    # Does this job have anything to work on? Some wrappers pass FILES as
    # arguments, and when the artefact directory is empty the command line has
    # no file in it: `trufflehog filesystem` with no path is a usage error, and
    # `jsluice urls` with no file silently reads stdin and reports nothing.
    # Both looked like a finding about the target. Refusing here puts the real
    # reason on the record instead.
    try:
        blocked = wrapper.precondition(job.target, job.args or [])
    except Exception:  # noqa: BLE001 - a broken check must not block the job
        logger.exception("[%s] precondition failed for %s", job.id, job.tool)
        blocked = ""
    if blocked:
        job.status = JobStatus.SUCCEEDED
        job.started_at = job.started_at or time.time()
        job.finished_at = time.time()
        job.findings = []
        job.error = f"not run: {blocked}"
        await repo.update(job)
        logger.info("[%s] %s skipped: %s", job.id, job.tool, blocked)
        if job.engagement_id:
            from app import events
            await events.emit(
                job.engagement_id, events.THOUGHT,
                f"{job.tool} was not run on {job.target}: {blocked}",
                level=events.LEVEL_INFO, tool=job.tool, job_id=job.id)
        return {"job_id": job_id, "status": job.status.value, "skipped": True}

    cmd = wrapper.build_command(job.target, job.args)

    job.status = JobStatus.RUNNING
    job.started_at = time.time()
    await repo.update(job)
    logger.info("[%s] %s %s", job.id, job.tool, cmd)

    # Verbose: surface the exact command line to the live view.
    if job.engagement_id:
        from app import events
        await events.emit(
            job.engagement_id, events.COMMAND,
            " ".join(cmd),
            level=events.LEVEL_VERBOSE, tool=job.tool, job_id=job.id,
        )

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    proc: Optional[asyncio.subprocess.Process] = None

    # Some tools read their targets from standard input rather than a flag.
    # Without this the subprocess inherited no usable stdin, so a wrapper had
    # no way to express it - dnsx failed on every job for want of one line.
    stdin_text = None
    try:
        stdin_text = wrapper.stdin_for(job.target, job.args or [])
    except Exception:  # noqa: BLE001 - a wrapper quirk is not a launch failure
        logger.exception("[%s] stdin_for failed for %s", job.id, job.tool)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        if stdin_text is not None and proc.stdin is not None:
            try:
                proc.stdin.write(stdin_text.encode())
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass          # the tool exited before reading; its error says why
            finally:
                proc.stdin.close()

        try:
            await asyncio.wait_for(
                _pump_streams(proc, stdout_buf, stderr_buf),
                timeout=wrapper.timeout_seconds,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            job.status = JobStatus.FAILED
            job.error = f"timeout after {wrapper.timeout_seconds}s"
            job.exit_code = -1
            job.finished_at = time.time()
            job.stdout = bytes(stdout_buf)
            job.stderr = bytes(stderr_buf)
            await repo.update(job)
            return {"job_id": job_id, "status": job.status.value}

        exit_code = await proc.wait()

    except asyncio.CancelledError:
        # arq.abort_job() lands here. SIGTERM the subprocess then re-raise so
        # arq marks the task as aborted.
        if proc is not None and proc.returncode is None:
            try:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            except ProcessLookupError:
                pass
        job.status = JobStatus.CANCELLED
        job.finished_at = time.time()
        job.stdout = bytes(stdout_buf)
        job.stderr = bytes(stderr_buf)
        # Keep what it had already found. A nuclei or sqlmap run killed in
        # flight has usually written its hits to stdout before the abort, and
        # discarding them meant an operator who stopped a run lost findings
        # that were already on disk. Every wrapper parses a line at a time and
        # tolerates a truncated last line, so a partial stream is safe to
        # read; if it is not, the job is still recorded as cancelled with its
        # raw output intact.
        try:
            job.findings = parse_and_cap(wrapper, job, bytes(stdout_buf),
                                         bytes(stderr_buf), -1)
        except Exception:  # noqa: BLE001 - never mask the cancellation
            logger.debug("[%s] could not parse the cancelled job's output",
                         job.id)
        await repo.update(job)
        raise

    except FileNotFoundError as exc:
        job.status = JobStatus.FAILED
        job.error = f"binary not found: {exc.filename}"
        job.finished_at = time.time()
        await repo.update(job)
        return {"job_id": job_id, "status": job.status.value}

    except Exception as exc:  # noqa: BLE001
        logger.exception("[%s] worker crashed", job.id)
        job.status = JobStatus.FAILED
        job.error = f"{type(exc).__name__}: {exc}"
        job.finished_at = time.time()
        job.stdout = bytes(stdout_buf)
        job.stderr = bytes(stderr_buf)
        await repo.update(job)
        return {"job_id": job_id, "status": job.status.value}

    # Normal completion.
    try:
        findings: List[Finding] = parse_and_cap(
            wrapper, job, bytes(stdout_buf), bytes(stderr_buf), exit_code)
    except Exception as exc:  # noqa: BLE001
        logger.exception("[%s] parse failed", job.id)
        findings = []
        job.error = f"parse error: {type(exc).__name__}: {exc}"

    job.stdout = bytes(stdout_buf)
    job.stderr = bytes(stderr_buf)
    job.exit_code = exit_code
    job.finished_at = time.time()
    job.findings = findings
    job.status = JobStatus.SUCCEEDED
    await repo.update(job)

    logger.info(
        "[%s] done in %.1fs exit=%s findings=%d",
        job.id,
        (job.finished_at - job.started_at) if job.started_at else 0.0,
        exit_code,
        len(findings),
    )
    return {"job_id": job_id, "status": job.status.value, "findings": len(findings)}


async def run_engagement(ctx: Dict[str, Any], run_id: str) -> Dict[str, Any]:
    """arq task: drive the autonomous plan->execute->ingest loop for a run.

    Long-lived. The scan sub-jobs it launches run concurrently on this same
    worker (max_jobs > 1), so the loop can submit a batch and await it.
    """
    return await run_engagement_loop(run_id)


async def _pump_streams(
    proc: asyncio.subprocess.Process,
    stdout_buf: bytearray,
    stderr_buf: bytearray,
) -> None:
    assert proc.stdout is not None and proc.stderr is not None

    async def pump(reader: asyncio.StreamReader, buf: bytearray) -> None:
        while True:
            chunk = await reader.read(16 * 1024)
            if not chunk:
                return
            buf.extend(chunk)
            if len(buf) > MAX_STREAM_BYTES:
                # Drop oldest data; keep recent tail.
                del buf[: len(buf) - MAX_STREAM_BYTES]

    await asyncio.gather(pump(proc.stdout, stdout_buf), pump(proc.stderr, stderr_buf))


# -----------------------------------------------------------------------------
# arq lifecycle hooks
# -----------------------------------------------------------------------------

async def startup(ctx: Dict[str, Any]) -> None:
    await db.init_db()
    # Hydrate the LLM router from the settings saved in the DB (the model-router
    # and provider keys entered in the UI). The API process does this in its
    # lifespan; the worker and orchestrator are separate processes with their
    # own router, so without this the orchestrator's planner/validator see no
    # key and every run silently degrades to catalog-only ("no API key or model
    # configured for the planner role").
    from app import settings_store
    try:
        await settings_store.apply_saved_on_startup()
    except Exception:  # noqa: BLE001 - a missing/invalid saved config must not stop the worker
        logger.exception("worker startup: could not hydrate the model router from settings")
    logger.info("worker startup: Postgres pool ready; model router hydrated")


async def shutdown(ctx: Dict[str, Any]) -> None:
    await db.close_pool()


def _scan_concurrency() -> int:
    """How many tool subprocesses may run at once. Env-driven, because it is
    the main lever between a fast run and a VM that falls over.

    The default was 8, which on a 2GB instance ran eight heavy scanners
    (nuclei, nmap, sqlmap, ffuf...) in parallel, exhausted the RAM, and took
    the whole host down to the point of needing a reboot. 4 is a saner
    default; a small box sets SYPHAX_SCAN_CONCURRENCY=2, a big one raises it.
    """
    import os
    try:
        value = int(os.getenv("SYPHAX_SCAN_CONCURRENCY", "4"))
    except (TypeError, ValueError):
        value = 4
    return max(1, min(value, 32))


class WorkerSettings:
    """Scans worker. Used by: arq app.workers.WorkerSettings

    Reads the DEFAULT queue and runs ONLY scan jobs, so the full pool is
    available to tool subprocesses. The orchestrator loop runs on a separate
    worker/queue (OrchestratorWorkerSettings) and never steals a slot here."""
    functions = [run_scan]
    redis_settings = _redis_settings()
    on_startup = startup
    on_shutdown = shutdown
    # Parallel tool subprocesses. See _scan_concurrency: this is what stands
    # between a run and an out-of-memory VM, so it is tunable per instance.
    max_jobs = _scan_concurrency()
    # arq retries failed jobs by default; we never want that for pentest
    # commands (a flaky network would re-run sqlmap five times). Disable.
    max_tries = 1
    job_timeout = 3 * 60 * 60
    # Required for ArqRedis.abort_job() to actually cancel a running task
    # (the Stop button on scans). Without this, abort requests are ignored.
    allow_abort_jobs = True


async def reaper(ctx: Dict[str, Any]) -> Dict[str, int]:
    """Periodic sweep: close zombie runs and abort the scan jobs they orphaned.

    Two failure modes it catches, neither covered by the run's own cleanup:
      * a run whose loop died (orchestrator worker crash/restart - arq
        max_tries=1, so no requeue) stays 'running' forever until the next run
        on that engagement. reclaim_all_stale closes it by stale heartbeat.
      * the scan jobs that run left in flight keep being fed to the scans worker
        (nuclei/sqlmap for up to 45min each) with no loop to ingest them.
        They are aborted here: any job still queued/running whose engagement has
        no active run is an orphan.

    Runs on the orchestrator worker, every few minutes. Never raises - a cron
    that throws just stops running.
    """
    from app.orchestrator.runs import RunRepository
    from app.scans.runner import get_runner
    from app.scans.storage import JobRepository

    runs_reclaimed = 0
    try:
        runs_reclaimed = await RunRepository().reclaim_all_stale()
        if runs_reclaimed:
            logger.info("reaper: reclaimed %d stale run(s)", runs_reclaimed)
    except Exception:  # noqa: BLE001
        logger.exception("reaper: reclaim_all_stale failed")

    jobs_aborted = 0
    try:
        active = await RunRepository().active_engagement_ids()
        unfinished = await JobRepository().unfinished_scan_jobs()
        orphans = [j for j in unfinished
                   if j.engagement_id and j.engagement_id not in active]
        if orphans:
            runner = get_runner()
            results = await asyncio.gather(
                *[runner.cancel(j.id) for j in orphans], return_exceptions=True)
            jobs_aborted = sum(1 for r in results if r is True)
            logger.info("reaper: aborted %d orphan scan job(s) of %d unfinished",
                        jobs_aborted, len(unfinished))
    except Exception:  # noqa: BLE001
        logger.exception("reaper: orphan-job sweep failed")

    return {"runs_reclaimed": runs_reclaimed, "jobs_aborted": jobs_aborted}


class OrchestratorWorkerSettings:
    """Orchestrator worker. Used by: arq app.workers.OrchestratorWorkerSettings

    Reads the dedicated ORCHESTRATOR_QUEUE and runs ONLY the long-lived
    plan->execute->ingest loops. Separated from scans so a loop awaiting its
    sub-jobs can never starve the scan pool (the old shared-pool deadlock)."""
    functions = [run_engagement]
    queue_name = ORCHESTRATOR_QUEUE
    redis_settings = _redis_settings()
    on_startup = startup
    on_shutdown = shutdown
    # Concurrent engagement runs. Each loop is mostly awaiting, so this can be
    # modest; scans execute on the other worker regardless.
    max_jobs = 6
    max_tries = 1
    # Shared with the loop so its deadline always lands under this. The loop
    # stops itself (and runs exploitation) before arq reaches this ceiling; this
    # is only the hard backstop for a genuinely wedged run.
    job_timeout = ORCH_JOB_TIMEOUT_SECONDS
    allow_abort_jobs = True
    # Every 3 minutes: close runs whose loop died and abort the scan jobs they
    # orphaned. The one periodic task the stack never had, so a crashed run
    # stayed 'running' and its nuclei/sqlmap kept burning the VM for hours.
    cron_jobs = [cron(reaper, minute=set(range(0, 60, 3)), run_at_startup=True)]
