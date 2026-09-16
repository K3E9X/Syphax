"""Job submission front-end.

Before Phase 1-E the runner spawned subprocesses in the same FastAPI process
via asyncio.create_task. Now scans are queued on Redis and executed by the
arq worker container (app.workers.run_scan). This module keeps the same
public API (`submit`, `cancel`) so existing endpoints keep working unchanged.
"""
from __future__ import annotations

import logging
import time
from typing import List, Optional
from urllib.parse import urlparse

from app.scans.models import Job, JobStatus
from app.scans.storage import JobRepository, new_job_id
from app.scans.wrappers import get_wrapper
from app.queue import get_arq_pool

logger = logging.getLogger("syphax.scans.runner")


class Runner:
    def __init__(self) -> None:
        self.repo = JobRepository()

    async def submit(
        self,
        tool: str,
        target: str,
        options: Optional[List[str]] = None,
        flow_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        catalog_item_id: Optional[str] = None,
    ) -> Job:
        wrapper = get_wrapper(tool)  # raises KeyError for unknown tools
        if not wrapper.is_available():
            raise RuntimeError(f"tool '{tool}' is not installed in this container")

        # ----- VPN kill switch (EVERY submission, same reasoning as the -----
        # authorization gate below: the orchestrator and exploit modules call
        # submit() directly, so this is the only place that catches them all).
        # A tunnel that dropped mid-engagement must not leak the real IP.
        from app.network.privacy import get_network_manager

        netmgr = get_network_manager()
        guard = await netmgr.guard_scan()
        if not guard.get("allowed"):
            try:
                from app.audit import audit
                await audit("scan.blocked_no_vpn", engagement_id=engagement_id,
                            tool=tool, target=target, reason=guard.get("reason"))
            except Exception:  # noqa: BLE001
                pass
            raise RuntimeError(f"scan blocked: {guard.get('reason')}")

        options = list(options or [])

        # Set by the gate below when there is an engagement. Initialised here
        # rather than relying on the `if` branch having run, which would be a
        # NameError on every scan submitted without one.
        eng = None

        if engagement_id:
            # ----- authorization gate (EVERY autonomous/exploit submission) -----
            # The REST endpoint checks this, but the orchestrator and the exploit
            # modules call submit() directly. Enforcing it here closes the hole:
            # the engagement must be authorized and the target host in scope.
            # Discovered subdomains (subfinder/gau) are never auto-trusted.
            from app.engagements.models import EngagementStatus
            from app.engagements.storage import EngagementRepository

            eng = await EngagementRepository().get(engagement_id)
            if eng is None:
                raise RuntimeError(f"engagement {engagement_id} not found")
            if eng.status != EngagementStatus.AUTHORIZED:
                raise RuntimeError(
                    f"engagement {engagement_id} is '{eng.status.value}', not authorized"
                )
            host = _host_of(target)
            if not eng.host_in_scope(host):
                try:
                    from app.audit import audit
                    await audit("scan.blocked_out_of_scope", engagement_id=engagement_id,
                                tool=tool, target=target, target_host=host,
                                scope=eng.scope_hosts)
                except Exception:  # noqa: BLE001
                    pass
                raise RuntimeError(
                    f"target host '{host}' is not in engagement scope {eng.scope_hosts}"
                )

            # Authenticated scanning: inject the engagement's primary-identity
            # headers as tool-specific flags so the scanner tests behind the login.
            try:
                from app.scans.auth import auth_args
                if eng.primary_auth:
                    options = auth_args(tool, eng.primary_auth) + options
            except Exception:  # noqa: BLE001 - never block a scan on auth wiring
                logger.exception("auth injection failed for %s", tool)

            # WAF-aware exploitation: if a WAF was fingerprinted, prepend
            # evasion/throttle options so active tools adapt.
            try:
                from app.orchestrator.state import EngagementState
                from app.scans.waf import is_waf_tech, waf_args

                techs = await EngagementState(engagement_id).technologies()
                if is_waf_tech(techs):
                    options = waf_args(tool) + options
                    # Intelligence #4: adapt the tamper set to the SPECIFIC WAF
                    # (LLM picks from an allowlist). Replaces the static tamper.
                    if eng.allow_active_exploit:
                        from app.scans.payload_adapt import (adaptive_tampers,
                                                             strip_tamper)
                        waf_name = next(
                            (str(t).split("waf:", 1)[1] for t in techs
                             if str(t).lower().startswith("waf:")), "")
                        adaptive = await adaptive_tampers(tool, waf_name)
                        if adaptive:
                            options = adaptive + strip_tamper(options)
            except Exception:  # noqa: BLE001 - never block a scan on WAF wiring
                logger.exception("waf adaptation failed for %s", tool)

        # Blind-XSS OOB: fire dalfox blind payloads at a configured interactsh
        # server (confirmed server-side).
        try:
            import os
            from app.scans.waf import blind_args
            oob = os.environ.get("INTERACTSH_SERVER", "").strip()
            extra = blind_args(tool, oob)
            if extra:
                options = extra + options
        except Exception:  # noqa: BLE001
            logger.exception("oob wiring failed for %s", tool)

        # Scan identity: User-Agent policy and the X-Pentest-ID attribution
        # header, plus the proxy when one is configured. Appended last so an
        # explicit caller-supplied flag still wins.
        try:
            from app.scans.identity import identity_args, proxy_args

            # The engagement's identity choice, when there is one. Loaded from
            # the row the authorization gate already fetched above, so this
            # costs nothing extra; falls back to the environment otherwise,
            # which is what a scan submitted without an engagement gets.
            options = identity_args(
                tool,
                mode=getattr(eng, "user_agent_mode", "") if eng else "",
                custom_ua=getattr(eng, "user_agent", "") if eng else "",
            ) + options
            proxy = await netmgr.proxy_for_tools_shared()
            if proxy:
                options = proxy_args(tool, proxy) + options
        except Exception:  # noqa: BLE001 - never block a scan on identity wiring
            logger.exception("identity wiring failed for %s", tool)

        job = Job(
            id=new_job_id(),
            tool=tool,
            target=target,
            args=options,
            status=JobStatus.QUEUED,
            created_at=time.time(),
            flow_id=flow_id,
            engagement_id=engagement_id,
            catalog_item_id=catalog_item_id,
        )
        await self.repo.create(job)

        pool = await get_arq_pool()
        # Reuse our own job ID as the arq job ID so cancel can target it.
        await pool.enqueue_job("run_scan", job.id, _job_id=job.id)
        logger.info("[%s] enqueued (%s on %s)", job.id, tool, target)
        return job

    async def cancel(self, job_id: str) -> bool:
        """Ask the worker to abort the job. arq sends a CancelledError to the
        task; app.workers.run_scan catches it, SIGTERMs the subprocess and
        marks the job as cancelled."""
        pool = await get_arq_pool()
        try:
            return bool(await pool.abort_job(job_id, timeout=5))
        except Exception:  # noqa: BLE001
            logger.exception("cancel failed for %s", job_id)
            return False


def _host_of(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    return target.split("/", 1)[0].split(":", 1)[0].lower()


_runner: Optional[Runner] = None


def get_runner() -> Runner:
    global _runner
    if _runner is None:
        _runner = Runner()
    return _runner
