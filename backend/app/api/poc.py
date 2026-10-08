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
from app.engagements import EngagementRepository, EngagementStatus
from app.sandbox import runner_client
from app.sandbox.inspect import inspect_code
from app.sandbox.staging import (STATUS_APPROVED, STATUS_REJECTED, STATUS_STAGED, StagedPoC,
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
    # Command line for the PoC. Omitted/None = derive it from the PoC's declared
    # options and its finding's target; [] = run bare (what used to happen
    # always, which made argparse-based exploits exit 2 on a usage message).
    argv: Optional[List[str]] = None


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


@router.get("/overview")
async def overview(engagement_id: str = "") -> Dict[str, Any]:
    """Every PoC the tool fetched or wrote, and what running it proved.

    The exploitation story was spread across three screens: the live console
    said a PoC ran, the Sandbox page held the code, the finding carried the
    output. This is the one place that answers "what was tried, and did it
    work" - per PoC, with its origin, its two readings and its exit code.
    """
    pocs = (await _repo.list(engagement_id) if engagement_id
            else await _repo.list_all())
    engs = {e.id: e for e in await _engagements.list(limit=500)}

    items = []
    counts = {"total": 0, "executed": 0, "proved": 0, "waiting": 0, "refused": 0}
    for p in pocs:
        insp = p.inspection or {}
        run = insp.get("run_result") or {}
        vetting = insp.get("vetting") or {}
        exit_code = run.get("exit_code")
        proved = bool(run) and exit_code == 0
        counts["total"] += 1
        if run:
            counts["executed"] += 1
        if proved:
            counts["proved"] += 1
        if not vetting.get("allowed", True):
            counts["refused"] += 1
        elif p.status == STATUS_STAGED and insp.get("verdict") != "review":
            counts["waiting"] += 1

        eng = engs.get(p.engagement_id)
        items.append({
            "id": p.id,
            "engagement": (eng.target_host if eng else p.engagement_id),
            "engagement_id": p.engagement_id,
            "finding_id": p.finding_id,
            "origin": insp.get("origin") or "manual",
            "repo": p.repo, "path": p.path, "language": p.language,
            "status": p.status, "decided_by": p.decided_by,
            "created_at": p.created_at,
            # the two readings
            "inspection_verdict": insp.get("verdict"),
            "vetting_allowed": vetting.get("allowed"),
            "vetting_summary": vetting.get("summary"),
            # did the model rehearse it, and did that work
            "rehearsed": (insp.get("refine") or {}).get("iterations"),
            "demonstrated": (insp.get("refine") or {}).get("demonstrated"),
            # what running it actually did
            "ran": bool(run),
            "exit_code": exit_code,
            "argv": run.get("argv") or [],
            "stdout": (run.get("stdout") or "")[:4000],
            "stderr": (run.get("stderr") or "")[:2000],
            "proved": proved,
        })
    return {"counts": counts, "items": items}


@router.get("/{poc_id}")
async def get_staged(poc_id: str) -> Dict[str, Any]:
    """The full code plus its inspection - what the reviewer actually reads."""
    poc = await _repo.get(poc_id)
    if poc is None:
        raise HTTPException(status_code=404, detail="staged PoC not found")
    out = poc.to_public(include_code=True)
    # The command line this PoC would be run with, derived from its declared
    # options and its finding's target. Shown (and editable) before running, so
    # an exploit that needs "-t host -p port" is not fired bare at a usage error.
    try:
        from app.exploit.poc_run import _argv_for
        out["suggested_argv"] = await _argv_for(poc)
    except Exception:  # noqa: BLE001 - a failed guess must not hide the PoC
        out["suggested_argv"] = []
    return out


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

    # The run gate (allow_active_exploit, scope, a fresh vet against the
    # engagement as it stands now, the sandbox run and the audit) lives in one
    # shared helper so the operator's manual run and the automatic run of a
    # vetted public PoC are governed identically - the auto path can never be
    # laxer than this one. Scope is not grantable; a declared capability is.
    from app.exploit.poc_run import PoCRunRefused, execute_poc
    try:
        return await execute_poc(eng, poc, timeout=req.timeout,
                                 decided_by=poc.decided_by or "operator",
                                 argv=req.argv)
    except PoCRunRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


@router.get("/runner/health")
async def runner_health() -> Dict[str, Any]:
    """Whether the isolated runner is up and its egress policy applied."""
    try:
        return await runner_client.health()
    except Exception as exc:  # noqa: BLE001 - an absent runner is a normal state
        return {"status": "unavailable", "error": str(exc)[:200]}
