"""Staged third-party PoCs: fetch, review, approve, run.

The route set mirrors the state machine, and the approval step is the whole
point of having one. Nothing here runs on stage; nothing runs on approve
either. Running is a separate, explicit call, and it re-checks every gate
rather than trusting that approval implied them - an engagement can be closed,
or its scope changed, between the review and the click.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.audit import audit
from app.exploit import vetting
from app.engagements import EngagementRepository, EngagementStatus
from app.sandbox import runner_client
from app.sandbox.inspect import inspect_code
from app.sandbox.staging import (STATUS_APPROVED, STATUS_EXECUTED,
                                 STATUS_REJECTED, STATUS_STAGED, StagedPoC,
                                 StagedPoCRepository, can_transition, fetch_file,
                                 fetch_repo_files, new_poc_id, parse_repo_url)

logger = logging.getLogger("syphax.api.poc")

router = APIRouter(prefix="/api/poc", tags=["poc"])

_repo = StagedPoCRepository()
_engagements = EngagementRepository()


class StageRequest(BaseModel):
    engagement_id: str
    repo_url: str
    finding_id: Optional[str] = None


class DecisionRequest(BaseModel):
    decided_by: str = "operator"


class RunRequest(BaseModel):
    timeout: int = 60


async def _authorized_engagement(engagement_id: str):
    eng = await _engagements.get(engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    if eng.status != EngagementStatus.AUTHORIZED:
        raise HTTPException(status_code=409,
                            detail=f"engagement is '{eng.status.value}', not authorized")
    return eng


@router.post("/stage")
async def stage(req: StageRequest) -> Dict[str, Any]:
    """Fetch a repository's PoC files, inspect them, store them for review."""
    eng = await _authorized_engagement(req.engagement_id)

    parsed = parse_repo_url(req.repo_url)
    if parsed is None:
        raise HTTPException(status_code=400,
                            detail="repo_url must be a github.com repository URL")
    owner, name = parsed

    candidates = await fetch_repo_files(owner, name)
    if not candidates:
        raise HTTPException(status_code=404,
                            detail="no runnable PoC file found in that repository")

    staged: List[Dict[str, Any]] = []
    for c in candidates:
        code = await fetch_file(owner, name, c["path"])
        if not code:
            continue
        # Inspected at stage time, not at run time: the reviewer needs the
        # report in front of them while deciding, not after.
        report = inspect_code(code, scope_hosts=eng.scope_hosts, filename=c["path"])
        poc = StagedPoC(
            id=new_poc_id(),
            engagement_id=eng.id,
            finding_id=req.finding_id,
            repo=f"{owner}/{name}",
            path=c["path"],
            language=c["language"],
            code=code,
            inspection=report.to_dict(),
            status=STATUS_STAGED,
            created_at=time.time(),
        )
        await _repo.create(poc)
        staged.append(poc.to_public(include_code=False))

    if not staged:
        raise HTTPException(status_code=404, detail="could not fetch any file")

    await audit("poc.staged", engagement_id=eng.id, repo=f"{owner}/{name}",
                files=[s["path"] for s in staged])
    return {"repo": f"{owner}/{name}", "staged": staged}


@router.get("/engagements/{engagement_id}")
async def list_staged(engagement_id: str) -> Dict[str, Any]:
    items = await _repo.list(engagement_id)
    return {"items": [p.to_public(include_code=False) for p in items]}


@router.get("/{poc_id}")
async def get_staged(poc_id: str) -> Dict[str, Any]:
    """The full code plus its inspection - what the reviewer actually reads."""
    poc = await _repo.get(poc_id)
    if poc is None:
        raise HTTPException(status_code=404, detail="staged PoC not found")
    return poc.to_public(include_code=True)


@router.post("/{poc_id}/approve")
async def approve(poc_id: str, req: DecisionRequest) -> Dict[str, Any]:
    return await _decide(poc_id, STATUS_APPROVED, req.decided_by)


@router.post("/{poc_id}/reject")
async def reject(poc_id: str, req: DecisionRequest) -> Dict[str, Any]:
    return await _decide(poc_id, STATUS_REJECTED, req.decided_by)


async def _decide(poc_id: str, target: str, decided_by: str) -> Dict[str, Any]:
    poc = await _repo.get(poc_id)
    if poc is None:
        raise HTTPException(status_code=404, detail="staged PoC not found")
    if not can_transition(poc.status, target):
        raise HTTPException(status_code=409,
                            detail=f"cannot go from '{poc.status}' to '{target}'")

    await _repo.set_status(poc_id, target, decided_by=decided_by)
    await audit(f"poc.{target}", engagement_id=poc.engagement_id,
                poc_id=poc_id, repo=poc.repo, path=poc.path, decided_by=decided_by,
                inspection_verdict=(poc.inspection or {}).get("verdict"))
    return {"id": poc_id, "status": target, "decided_by": decided_by}


@router.post("/{poc_id}/run")
async def run(poc_id: str, req: RunRequest) -> Dict[str, Any]:
    """Execute an approved PoC in the isolated runner.

    Every gate is re-checked here rather than assumed from the approval: an
    engagement can be closed, or its scope narrowed, between the review and
    this call.
    """
    poc = await _repo.get(poc_id)
    if poc is None:
        raise HTTPException(status_code=404, detail="staged PoC not found")
    if poc.status != STATUS_APPROVED:
        raise HTTPException(
            status_code=409,
            detail=f"PoC is '{poc.status}': a human must approve it before it runs")

    eng = await _authorized_engagement(poc.engagement_id)
    if not eng.allow_active_exploit:
        raise HTTPException(status_code=409,
                            detail="allow_active_exploit is off for this engagement")
    if not eng.scope_hosts:
        raise HTTPException(status_code=409, detail="engagement has no scope")

    # Re-vetted here, against the scope as it stands now. The approval said "I
    # have read this code"; it did not say "and it may destroy a database".
    #
    # This is the one thing a human approval does not unlock, and the line is
    # narrow on purpose: destructive, persistent, denial-of-service or
    # out-of-scope. Everything an exploit actually needs - POST, PUT, writing a
    # file, uploading a shell, executing a command, reading data - is allowed
    # and always was. What is refused is damage the operator cannot undo and a
    # report they cannot defend, and the refusal names the line so the code can
    # be fixed and re-staged.
    verdict = vetting.vet(poc.code, scope_hosts=eng.scope_hosts)
    if not verdict.allowed:
        offending = "; ".join(
            f"line {s.line_no}: {s.detail}" if s.line_no else s.detail
            for s in verdict.blocking[:5])
        await audit("poc.refused", engagement_id=eng.id, poc_id=poc_id,
                    repo=poc.repo, path=poc.path,
                    reasons=[s.category for s in verdict.blocking])
        raise HTTPException(status_code=409, detail=f"{verdict.summary} {offending}")

    try:
        result = await runner_client.run_poc(
            poc.code, language=poc.language,
            scope_hosts=eng.scope_hosts, timeout=req.timeout)
    except runner_client.SandboxUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await _repo.set_status(poc_id, STATUS_EXECUTED, decided_by=poc.decided_by)
    await audit("poc.executed", engagement_id=eng.id, poc_id=poc_id,
                repo=poc.repo, path=poc.path, exit_code=result.exit_code,
                scope=eng.scope_hosts)
    return {"id": poc_id, "status": STATUS_EXECUTED, "result": result.to_dict()}


@router.get("/runner/health")
async def runner_health() -> Dict[str, Any]:
    """Whether the isolated runner is up and its egress policy applied."""
    try:
        return await runner_client.health()
    except Exception as exc:  # noqa: BLE001 - an absent runner is a normal state
        return {"status": "unavailable", "error": str(exc)[:200]}
