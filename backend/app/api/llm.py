"""LLM copilot endpoints:

  GET  /api/llm/providers                 - the provider catalog the UI offers
  GET  /api/llm/readiness                 - do all three roles resolve to a model?
  POST /api/llm/flows/{flow_id}/suggest   - analyse one captured flow
  POST /api/llm/jobs/{job_id}/explain     - explain scan findings
  POST /api/llm/report                    - generate a markdown pentest report
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.llm import LLMError, get_analyzer, get_llm
from app.proxy import FlowRepository
from app.scans.storage import JobRepository

router = APIRouter(prefix="/api/llm", tags=["llm"])

_flows = FlowRepository()
_jobs = JobRepository()


@router.get("/providers")
async def providers() -> dict:
    """What the Settings page and the setup wizard offer.

    Served rather than hardcoded in the frontend so the two cannot drift, and so
    the base URL a role gets is the same string the backend matches its stored
    key against.
    """
    from app.llm import providers as catalog
    return {
        "items": catalog.to_public(),
        "roles": [{"role": r, "note": catalog.ROLE_NOTES[r],
                   "default_provider": catalog.DEFAULT_ASSIGNMENT.get(r, "")}
                  for r in catalog.ROLES],
    }


@router.get("/readiness")
async def readiness() -> dict:
    """Whether this install can actually think, and what is missing if not."""
    from app import settings_store
    return (await settings_store.llm_readiness()).to_public()


def _require_llm() -> None:
    if not get_llm().configured:
        raise HTTPException(
            status_code=503,
            detail="OPENROUTER_API_KEY is not set. Put it in .env and restart the backend.",
        )


@router.post("/flows/{flow_id}/suggest")
async def suggest_attacks(flow_id: str) -> dict:
    _require_llm()
    flow = await _flows.get_flow(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="flow not found")
    analyzer = get_analyzer()
    try:
        result = await analyzer.suggest_attacks(flow)
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"flow_id": flow_id, **result.to_public()}


@router.post("/jobs/{job_id}/explain")
async def explain_findings(job_id: str) -> dict:
    _require_llm()
    job = await _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    analyzer = get_analyzer()
    try:
        markdown = await analyzer.explain_findings(job.to_detail())
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"job_id": job_id, "markdown": markdown}


class ReportRequest(BaseModel):
    title: Optional[str] = None
    scope: Optional[str] = None
    job_ids: Optional[List[str]] = None  # if None, include all jobs


@router.post("/report")
async def generate_report(req: ReportRequest) -> dict:
    _require_llm()

    # Gather jobs.
    if req.job_ids:
        jobs = []
        for jid in req.job_ids:
            j = await _jobs.get(jid)
            if j is not None:
                jobs.append(j)
    else:
        jobs = await _jobs.list(limit=500, offset=0)

    jobs_public = [j.to_detail() for j in jobs]

    # Gather host summary from proxy capture.
    hosts = await _flows.list_hosts()

    analyzer = get_analyzer()
    try:
        markdown = await analyzer.generate_report(
            title=req.title or "Penetration Test Report",
            scope=req.scope or "",
            hosts=hosts,
            jobs=jobs_public,
        )
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "markdown": markdown,
        "jobs_included": len(jobs_public),
        "hosts_included": len(hosts),
    }
