"""Executor agent (spec §4.1).

Turns a planner Task into a real wrapper job (via the queue), and ingests a
finished job's findings back into the engagement state so later planning sees
the expanded surface:

  * httpx / whatweb  -> fingerprints (drive tech-gated catalog items)
  * katana / gau / ffuf -> new endpoint assets (drive param-gated items)

The executor never shells out itself; it goes through the same Runner /
arq queue as manual scans, so the authorization model and sandboxing are
identical.
"""
from __future__ import annotations

import logging
from typing import List, Optional
import re
from urllib.parse import urlparse

from app import events
from app.scans import Job, get_runner
from app.orchestrator.planner import Task
from app.orchestrator.state import EngagementState

# Tool output can be megabytes; the advisor only needs the end, where the
# error actually is.
_TAIL_BYTES = 2000


def _tail(blob: bytes) -> str:
    if not blob:
        return ""
    return blob[-_TAIL_BYTES:].decode("utf-8", errors="replace")

logger = logging.getLogger("syphax.orchestrator.executor")


# Retries are submitted from ingest, which is outside the loop's per-batch
# budget check, so they need their own ceiling. Without one a run with many
# empty jobs could roughly double its request count against the target.
MAX_RETRIES_PER_RUN = 10


class Executor:
    def __init__(self, state: EngagementState) -> None:
        self.state = state
        self.runner = get_runner()
        self._eng = None
        self.retries_launched = 0

    async def _engagement(self):
        """The engagement (cached) - used for scope checks at ingest time."""
        if self._eng is None:
            from app.engagements.storage import EngagementRepository
            self._eng = await EngagementRepository().get(self.state.engagement_id)
        return self._eng

    async def launch(self, task: Task) -> Optional[Job]:
        """Submit a task as a job and mark coverage 'running'. Returns the job
        or None if the tool isn't available."""
        try:
            job = await self.runner.submit(
                tool=task.tool,
                target=task.asset_value,
                options=task.options,
                engagement_id=self.state.engagement_id,
                catalog_item_id=task.catalog_item_id,
            )
        except (RuntimeError, KeyError) as exc:
            logger.warning("skip task %s: %s", task.key, exc)
            await self.state.mark_coverage(task.catalog_item_id, task.asset_value, "skipped")
            await events.emit(
                self.state.engagement_id, events.TASK_SKIPPED,
                f"{task.tool} skipped on {task.asset_value}: {exc}",
                level=events.LEVEL_VERBOSE, tool=task.tool, target=task.asset_value,
            )
            return None

        await self.state.mark_coverage(
            task.catalog_item_id, task.asset_value, "running", job_id=job.id
        )
        return job

    async def ingest(self, job: Job) -> None:
        """Fold a finished job's findings into the engagement state."""
        status = "done" if job.status.value in ("succeeded",) else "error"
        if job.catalog_item_id:
            await self.state.mark_coverage(
                job.catalog_item_id, job.target, status, job_id=job.id
            )

        # Verbose: one line per finished job (exit code + finding count).
        await events.emit(
            self.state.engagement_id, events.JOB_DONE,
            f"{job.tool} {job.status.value} (exit {job.exit_code}) "
            f"- {len(job.findings)} finding(s) on {job.target}",
            level=events.LEVEL_VERBOSE,
            tool=job.tool, target=job.target, status=job.status.value,
            findings=len(job.findings),
        )

        # A job that failed or came back empty used to disappear silently:
        # coverage moved on and the run lost that test. Triage it and, when a
        # gentler retry would plausibly change the outcome, run it once.
        await self._triage_underperforming(job)

        for f in job.findings:
            await self._ingest_finding(job, f)
            # Verbose: one line per finding as it is ingested.
            await events.emit(
                self.state.engagement_id, events.FINDING,
                f"[{f.severity}] {f.title} ({job.tool})",
                level=events.LEVEL_VERBOSE,
                severity=f.severity, tool=job.tool, target=f.target,
            )

    async def _triage_underperforming(self, job: Job) -> None:
        """Diagnose a failed/empty job and retry once if that would help.

        Best-effort throughout: triage is an optimisation, and a broken advisor
        must never cost a run its results.
        """
        from app.scans.retry_advisor import (advise, retry_options,
                                             should_triage)

        try:
            if self.retries_launched >= MAX_RETRIES_PER_RUN:
                return
            if not should_triage(job.tool, job.exit_code, len(job.findings), job.args):
                return

            advice = await advise(
                job.tool,
                exit_code=job.exit_code,
                stderr_tail=_tail(job.stderr),
                stdout_tail=_tail(job.stdout),
                options=job.args,
            )
            if advice is None:
                return

            await events.emit(
                self.state.engagement_id, events.JOB_DONE,
                f"{job.tool} on {job.target}: {advice.diagnosis} - {advice.reason}",
                level=events.LEVEL_VERBOSE,
                tool=job.tool, target=job.target, diagnosis=advice.diagnosis,
            )
            if not advice.retry:
                return

            new_options = retry_options(job.args, advice)
            self.retries_launched += 1
            retried = await self.runner.submit(
                tool=job.tool,
                target=job.target,
                options=new_options,
                engagement_id=self.state.engagement_id,
                catalog_item_id=job.catalog_item_id,
            )
            await events.emit(
                self.state.engagement_id, events.TASK_LAUNCHED,
                f"retry: {job.tool} -> {job.target} ({advice.diagnosis}) {advice.options}",
                tool=job.tool, target=job.target, job_id=retried.id,
            )
        except Exception:  # noqa: BLE001 - never let triage break ingest
            logger.exception("triage failed for job %s", job.id)

    async def _ingest_finding(self, job: Job, finding) -> None:
        tool = job.tool
        meta = finding.metadata or {}

        # Fingerprints from probe/fingerprint tools.
        techs: List[str] = []
        if tool == "whatweb":
            if meta.get("plugin"):
                techs.append(str(meta["plugin"]))
        elif tool == "httpx":
            techs.extend(str(t) for t in (meta.get("tech") or []))
            if meta.get("server"):
                techs.append(str(meta["server"]))
        elif tool == "wpscan":
            techs.append("wordpress")
        elif tool == "wafw00f" and meta.get("waf"):
            # Record the WAF so later exploitation adapts (see app/scans/waf.py).
            techs.append(f"waf:{meta['waf']}")
        for tech in techs:
            await self.state.add_fingerprint(tech, source=tool)
            await events.emit(
                self.state.engagement_id, events.FINGERPRINT,
                f"{tech} (via {tool})",
                level=events.LEVEL_VERBOSE, technology=tech, tool=tool,
            )

        # New endpoint assets from crawl / archive / content-discovery tools.
        new_asset = None  # (kind, value)
        if tool in ("katana", "gau", "ffuf"):
            url = finding.target
            if _looks_like_http_url(url):
                await self.state.add_asset("endpoint", url, source=tool)
                new_asset = ("endpoint", url)
        elif tool == "subfinder":
            host = (finding.target or "").lower()
            # Only in-scope subdomains become assets. Out-of-scope hosts would
            # otherwise generate candidate tasks every iteration that the runner
            # scope-gate then rejects - wasted planning cycles and coverage rows.
            eng = await self._engagement()
            if host and (eng is None or eng.host_in_scope(host)):
                await self.state.add_asset("host", host, source="subfinder")
                new_asset = ("host", host)

        if new_asset:
            await events.emit(
                self.state.engagement_id, events.ASSET_FOUND,
                f"{new_asset[0]}: {new_asset[1]} (via {tool})",
                level=events.LEVEL_VERBOSE, kind=new_asset[0], value=new_asset[1],
            )


# Characters RFC 3986 excludes from a URL. A backslash is the one that matters
# in practice: katana parses JavaScript, and a regex literal like
# `\/index\.html` is not a path - but it has a scheme once joined to the base,
# so a scheme-only check let it through. Every later phase then tested
# `http://target/\/index\.html`, which is a 404, and the run found nothing.
_NOT_IN_A_URL = set('\\ "<>{}|^`') | {chr(c) for c in range(0x21)} | {chr(0x7f)}

# A path that is really a regex: escaped separators or metacharacters.
_REGEX_PATH = re.compile(r"\\[./]|\(\?|\[\^|\)\$|\.\*")


def _looks_like_http_url(value: str) -> bool:
    """Is this a URL we should scan, or debris a parser mistook for one?

    Scheme alone is not enough. Crawlers that read JavaScript emit regex
    literals, template placeholders and fragments of code; each carries the
    base URL's scheme and used to become a scanned asset, spending the whole
    run on paths that cannot exist.
    """
    if not value or "://" not in value:
        return False
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    if any(ch in _NOT_IN_A_URL for ch in value):
        return False
    if _REGEX_PATH.search(parsed.path or ""):
        return False
    # Unresolved templating: ${...}, {{...}}, :param placeholders from a router.
    if "${" in value or "{{" in value:
        return False
    return True
