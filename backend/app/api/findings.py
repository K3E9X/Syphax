"""Global, cross-engagement findings: dedup, triage status, retest, export.

Findings are stored per-engagement in validated_findings. This view collapses
the same issue seen by multiple tools/engagements into one deduped row
(hash of vuln_class + target), tracks an operator triage status that survives
re-validation, supports a safe per-finding retest (re-runs the validator,
authz + scope enforced) and a HackerOne-format export.
"""
from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from app import db
from app.audit import audit
from app.engagements import EngagementRepository, EngagementStatus
from app.findings_util import (
    CVSS as _CVSS,
    SEV_RANK as _SEV_RANK,
    TRIAGE_STATUSES as _TRIAGE_STATUSES,
    cvss_for,
    dedup as _dedup,
    h1_markdown,
)
from app.reporting.mappings import for_class
from app.validation import ValidatedFindingRepository, build_chains, validate_engagement

router = APIRouter(tags=["findings"])

_vf = ValidatedFindingRepository()
_engagements = EngagementRepository()

# Operator triage workflow status, keyed by dedup so it survives re-validation
# (which assigns fresh finding ids).
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS finding_triage (
    dedup       TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    updated_at  DOUBLE PRECISION NOT NULL
);
"""
db.register_schema(SCHEMA_SQL)

async def _triage_map() -> Dict[str, str]:
    async with db.acquire() as conn:
        rows = await conn.fetch("SELECT dedup, status FROM finding_triage")
    return {r["dedup"]: r["status"] for r in rows}


@router.get("/api/findings")
async def list_findings(severity: str = "", status: str = "", q: str = "",
                        engagement: str = "") -> Dict[str, Any]:
    all_vf = await _vf.list_all()
    engs = {e.id: e for e in await _engagements.list(limit=500)}
    triage = await _triage_map()

    groups: Dict[str, Dict[str, Any]] = {}
    for f in all_vf:
        if f.status == "false_positive":
            continue
        if engagement and f.engagement_id != engagement:
            continue
        key = _dedup(f.vuln_class, f.target)
        g = groups.get(key)
        meta = f.metadata or {}
        if g is None:
            g = {
                "id": f.id, "dedup": key, "severity": f.severity,
                "cvss": _CVSS.get((f.severity or "info").lower(), 1.0),
                "title": f.title, "target": f.target, "cls": f.vuln_class,
                "tool": f.tool, "tools": {f.tool}, "validation_status": f.status,
                "status": triage.get(key, "new"),
                "engagement": (engs.get(f.engagement_id).target_host if engs.get(f.engagement_id) else f.engagement_id),
                "engagement_id": f.engagement_id, "dup": 1, "last_seen": f.created_at,
                "desc": meta.get("description") or "", "evidence": f.evidence,
                "poc": f.poc, "req": meta.get("req") or "", "resp": meta.get("resp") or "",
                "confidence": f.confidence,
                # The shadow judge's second opinion, when one ran. Surfaced so
                # the operator sees where a candidate model disagreed with the
                # verdict that actually shipped, on this finding.
                "shadow_judge": meta.get("shadow_judge") or None,
            }
            groups[key] = g
        else:
            g["dup"] += 1
            g["tools"].add(f.tool)
            g["last_seen"] = max(g["last_seen"], f.created_at)
            if _SEV_RANK.get(f.severity, 9) < _SEV_RANK.get(g["severity"], 9):
                g["severity"] = f.severity
                g["cvss"] = _CVSS.get((f.severity or "info").lower(), 1.0)

    items = []
    for g in groups.values():
        g["tool"] = ", ".join(sorted(g.pop("tools")))
        items.append(g)
    if severity:
        items = [g for g in items if g["severity"] == severity]
    if status:
        items = [g for g in items if g["status"] == status]
    if q:
        ql = q.lower()
        items = [g for g in items if ql in f"{g['title']} {g['target']} {g['cls']}".lower()]
    items.sort(key=lambda g: (_SEV_RANK.get(g["severity"], 9), -g["last_seen"]))
    return {"count": len(items), "items": items}


class StatusBody(BaseModel):
    status: str


@router.post("/api/findings/{finding_id}/status")
async def set_status(finding_id: str, body: StatusBody) -> Dict[str, Any]:
    if body.status not in _TRIAGE_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(_TRIAGE_STATUSES)}")
    f = await _vf.get(finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding not found")
    key = _dedup(f.vuln_class, f.target)
    async with db.acquire() as conn:
        await conn.execute(
            "INSERT INTO finding_triage (dedup, status, updated_at) VALUES ($1,$2,$3) "
            "ON CONFLICT (dedup) DO UPDATE SET status=EXCLUDED.status, updated_at=EXCLUDED.updated_at",
            key, body.status, time.time())
    await audit("finding.status", finding_id=finding_id, dedup=key, status=body.status)
    return {"dedup": key, "status": body.status}


async def _retest(engagement_id: str, finding_id: str) -> Dict[str, Any]:
    eng = await _engagements.get(engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    if eng.status != EngagementStatus.AUTHORIZED:
        raise HTTPException(status_code=403, detail="engagement is not authorized")
    f = await _vf.get(finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding not found")
    key = _dedup(f.vuln_class, f.target)
    # Re-run the safe validator over the engagement, then return the refreshed
    # finding matched by its dedup key (ids are reassigned on re-validation).
    await validate_engagement(engagement_id)
    await build_chains(engagement_id)
    for nf in await _vf.list(engagement_id):
        if _dedup(nf.vuln_class, nf.target) == key:
            d = nf.to_public()
            d["dedup"] = key
            return d
    return {"dedup": key, "status": "false_positive", "note": "no longer reproduced"}


@router.post("/api/findings/{finding_id}/verify-proof")
async def verify_proof(finding_id: str) -> Dict[str, Any]:
    """Replay the proof the LLM judge suggested for this finding.

    The judge already paid a call to produce a single read-only request and the
    substring that settles the question; this sends it and reports whether it
    held. Goes through SafePoC, so the usual policy applies.
    """
    f = await _vf.get(finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding not found")
    eng = await _engagements.get(f.engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    if eng.status != EngagementStatus.AUTHORIZED:
        raise HTTPException(status_code=403, detail="engagement is not authorized")

    from app.validation.proof_replay import replay

    result = await replay(f, eng.host_in_scope)
    await audit("finding.proof_replayed", finding_id=finding_id,
                engagement_id=f.engagement_id, outcome=result.get("outcome"))
    return {"finding_id": finding_id, **result}


@router.post("/api/findings/{finding_id}/retest")
async def retest_finding(finding_id: str) -> Dict[str, Any]:
    f = await _vf.get(finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return await _retest(f.engagement_id, finding_id)


@router.post("/api/engagements/{engagement_id}/findings/{finding_id}/retest")
async def retest_engagement_finding(engagement_id: str, finding_id: str) -> Dict[str, Any]:
    return await _retest(engagement_id, finding_id)


@router.get("/api/findings/{finding_id}/export")
async def export_finding(finding_id: str, format: str = "h1") -> Response:
    f = await _vf.get(finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding not found")
    m = for_class(f.vuln_class)
    md = h1_markdown(f, m, cvss_for(f.severity))
    return Response(content=md, media_type="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="{finding_id}.md"'})
