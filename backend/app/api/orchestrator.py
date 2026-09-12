"""Autonomous engagement control: start a run, stop it, read live state."""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.audit import audit
from app.engagements import EngagementRepository, EngagementStatus
from app import events as events_log
from app.orchestrator.approvals import ApprovalRepository
from app.orchestrator.runs import Run, RunRepository, new_run_id
from app.orchestrator.state import EngagementState
from app.scans.storage import JobRepository
from app.queue import get_arq_pool
from app.validation import (
    ChainRepository,
    ValidatedFindingRepository,
    build_chains,
    validate_engagement,
)

from app.reporting.mappings import CATEGORY_LABELS, CATEGORY_ORDER

router = APIRouter(prefix="/api/engagements", tags=["orchestrator"])

# Ordered category taxonomy shared with the UI so findings partition the same
# way everywhere (recon -> enumeration -> access control -> ...).
_CATEGORY_META = [{"key": k, "label": CATEGORY_LABELS[k]} for k in CATEGORY_ORDER]

_engagements = EngagementRepository()
_runs = RunRepository()
_jobs = JobRepository()
_vf = ValidatedFindingRepository()
_chains = ChainRepository()
_approvals = ApprovalRepository()


@router.post("/{engagement_id}/run")
async def start_run(engagement_id: str) -> dict:
    e = await _engagements.get(engagement_id)
    if e is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    if e.status != EngagementStatus.AUTHORIZED:
        raise HTTPException(
            status_code=403,
            detail=f"engagement is '{e.status.value}', not 'authorized'. Verify ownership first.",
        )

    # One active run at a time - but a worker that died used to leave a run at
    # 'running' forever, and this guard then refused every new run with a 409
    # that never cleared. Reclaim anything with no live loop first.
    reclaimed = await _runs.reclaim_stale(engagement_id)
    if reclaimed:
        await audit("engagement.run_reclaimed", engagement_id=engagement_id,
                    count=reclaimed)

    latest = await _runs.latest_for_engagement(engagement_id)
    if latest and latest.status in ("queued", "running"):
        raise HTTPException(status_code=409, detail=f"run {latest.id} already active")

    run = Run(
        id=new_run_id(),
        engagement_id=engagement_id,
        status="queued",
        created_at=time.time(),
    )
    await _runs.create(run)

    pool = await get_arq_pool()
    from app.queue import ORCHESTRATOR_QUEUE
    await pool.enqueue_job("run_engagement", run.id, _job_id=run.id,
                           _queue_name=ORCHESTRATOR_QUEUE)
    await audit("engagement.run_queued", engagement_id=engagement_id, run_id=run.id)
    return {"run": run.to_public()}


@router.post("/{engagement_id}/stop")
async def stop_run(engagement_id: str) -> dict:
    latest = await _runs.latest_for_engagement(engagement_id)
    if latest is None or latest.status not in ("queued", "running"):
        raise HTTPException(status_code=404, detail="no active run")
    await _runs.request_stop(latest.id)
    # Also try to abort the arq task so a long wait is interrupted promptly.
    try:
        pool = await get_arq_pool()
        await pool.abort_job(latest.id, timeout=5)
    except Exception:  # noqa: BLE001
        pass
    await audit("engagement.run_stop_requested", engagement_id=engagement_id, run_id=latest.id)
    return {"run_id": latest.id, "stop_requested": True}


@router.get("/{engagement_id}/state")
async def engagement_state(engagement_id: str) -> dict:
    e = await _engagements.get(engagement_id)
    if e is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    state = EngagementState(engagement_id)
    run = await _runs.latest_for_engagement(engagement_id)
    assets = await state.assets()
    tech = await state.technologies()
    coverage = await state.coverage_rows()
    cov_summary = await state.coverage_summary()

    # Aggregate findings from this engagement's jobs.
    jobs = await _jobs.list_by_engagement(engagement_id)
    findings = []
    for j in jobs:
        for f in j.findings:
            d = f.to_dict()
            d["job_id"] = j.id
            d["tool"] = j.tool
            findings.append(d)

    validated = await _vf.list(engagement_id)
    chains = await _chains.list(engagement_id)
    validation_summary = await _vf.summary(engagement_id)
    from app.llm import usage as llm_usage
    llm = await llm_usage.summary(engagement_id)

    from app.reporting.mappings import category_for_class

    def _vf_public(v) -> dict:
        d = v.to_public()
        d["category"] = category_for_class(v.vuln_class)
        # Surface request/response when an analyzer captured them in metadata,
        # so the live view can show the per-finding req/resp panel.
        md = v.metadata or {}
        d["req"] = md.get("req") or ""
        d["resp"] = md.get("resp") or ""
        return d

    return {
        "engagement": e.to_public(),
        "run": run.to_public() if run else None,
        "llm_usage": llm,
        "assets": [
            {"kind": a.kind, "value": a.value, "has_params": a.has_params,
             "is_https": a.is_https, "source": a.source}
            for a in assets
        ],
        "technologies": tech,
        "coverage_summary": cov_summary,
        "coverage": coverage,
        "jobs": [j.to_public() for j in jobs],
        "findings": findings,
        "findings_count": len(findings),
        "validated_findings": [_vf_public(v) for v in validated],
        "validation_summary": validation_summary,
        "chains": chains,
        "categories": _CATEGORY_META,
    }


@router.post("/{engagement_id}/validate")
async def run_validation(engagement_id: str) -> dict:
    """Validate the engagement's findings on demand (e.g. after manual scans),
    independent of a full autonomous run."""
    e = await _engagements.get(engagement_id)
    if e is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    from app.analysis import run_analysis
    await run_analysis(engagement_id)
    stats = await validate_engagement(engagement_id)
    chains = await build_chains(engagement_id)
    await audit("engagement.validated_manual", engagement_id=engagement_id, stats=stats)
    return {"stats": stats, "chains": len(chains)}


@router.post("/{engagement_id}/analyze-traffic")
async def analyze_traffic(engagement_id: str) -> dict:
    """Run all traffic-driven analyzers (logic/IDOR/CSRF/BFLA, JS secrets +
    endpoints, JWT, access-control) over proxy-captured authenticated traffic,
    then re-validate and rebuild chains so the new findings show up."""
    e = await _engagements.get(engagement_id)
    if e is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    from app.analysis import run_analysis
    result = await run_analysis(engagement_id)
    await validate_engagement(engagement_id)
    await build_chains(engagement_id)
    await audit("engagement.analyzed_traffic", engagement_id=engagement_id, result=result)
    return result


@router.get("/{engagement_id}/diff")
async def engagement_diff(engagement_id: str, against: str) -> dict:
    """Compare this engagement's findings with another engagement's.

    The retest question: what did we fix, what came back, what is new. Both
    engagements must exist; `against` is the earlier one.
    """
    for eid in (engagement_id, against):
        if await _engagements.get(eid) is None:
            raise HTTPException(status_code=404, detail=f"engagement {eid} not found")
    if engagement_id == against:
        raise HTTPException(status_code=400, detail="cannot diff an engagement against itself")

    from app.reporting.diff import diff_findings

    previous = [v.to_public() for v in await _vf.list(against)]
    current = [v.to_public() for v in await _vf.list(engagement_id)]
    result = diff_findings(previous, current).to_public()
    result["previous_engagement"] = against
    result["current_engagement"] = engagement_id
    return result


@router.get("/{engagement_id}/findings")
async def validated_findings(engagement_id: str) -> dict:
    items = await _vf.list(engagement_id)
    return {
        "summary": await _vf.summary(engagement_id),
        "count": len(items),
        "items": [v.to_public() for v in items],
    }


@router.get("/{engagement_id}/chains")
async def chains(engagement_id: str) -> dict:
    items = await _chains.list(engagement_id)
    return {"count": len(items), "items": items}


@router.get("/{engagement_id}/events")
async def events_backfill(engagement_id: str, after_id: int = 0) -> dict:
    items = await events_log.list_since(engagement_id, after_id)
    return {"count": len(items), "items": items}


@router.get("/{engagement_id}/approvals")
async def list_approvals(engagement_id: str) -> dict:
    items = await _approvals.list_for_engagement(engagement_id)
    return {"count": len(items), "items": [a.to_public() for a in items]}


class ApprovalDecision(BaseModel):
    decision: str  # "approved" | "denied"


@router.post("/{engagement_id}/approvals/{approval_id}")
async def decide_approval(engagement_id: str, approval_id: str, body: ApprovalDecision) -> dict:
    if body.decision not in ("approved", "denied"):
        raise HTTPException(status_code=400, detail="decision must be 'approved' or 'denied'")
    appr = await _approvals.get(approval_id)
    if appr is None or appr.engagement_id != engagement_id:
        raise HTTPException(status_code=404, detail="approval not found")
    ok = await _approvals.decide(approval_id, body.decision)
    if not ok:
        raise HTTPException(status_code=409, detail="approval already decided")
    await audit("engagement.approval_decided", engagement_id=engagement_id,
                approval_id=approval_id, decision=body.decision)
    return {"approval_id": approval_id, "decision": body.decision}
