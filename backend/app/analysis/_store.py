"""Shared persistence for the analysis modules.

Each analyzer (logic / JS recon / JWT / access-control) stores its findings as
a synthetic scan job under its own `tool` name, so they flow through the normal
validation -> report -> kill-chain pipeline AND stay cleanly partitioned in the
UI (one tool == one category of test). Re-running an analyzer replaces its
previous synthetic job (idempotent) instead of duplicating findings.
"""
from __future__ import annotations

import logging
import time
from typing import List

from app.scans.models import Finding, Job, JobStatus
from app.scans.storage import JobRepository, new_job_id

logger = logging.getLogger("syphax.analysis.store")


async def save_analysis_job(
    engagement_id: str, tool: str, findings: List[Finding], *, target: str
) -> None:
    repo = JobRepository()
    await repo.delete_by_tool(engagement_id, tool)
    now = time.time()
    job = Job(
        id=new_job_id(),
        tool=tool,
        target=target,
        args=[],
        status=JobStatus.SUCCEEDED,
        created_at=now,
        started_at=now,
        finished_at=now,
        exit_code=0,
        findings=findings,
        engagement_id=engagement_id,
    )
    await repo.create(job)

    # Every analyser stores through here, so this is where they all become
    # producers for the exploitation blackboard - one mapping instead of
    # twenty hand-wired call sites that would drift apart. A finding that
    # chains to nothing posts nothing, and a failed post never fails the
    # analyser that called us.
    try:
        from app.orchestrator.blackboard import post_from_finding
        for finding in findings:
            await post_from_finding(engagement_id, finding, source=tool)
    except Exception:  # noqa: BLE001 - the board is an enhancement
        logger.debug("[%s] could not post %s leads", engagement_id, tool)
