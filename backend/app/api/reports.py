"""Report endpoints: Markdown, printable HTML, and JSON metadata."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from app.engagements import EngagementRepository
from app.reporting import build_report
from app.reporting.export import findings_json, sarif
from app.validation import ChainRepository, ValidatedFindingRepository

router = APIRouter(prefix="/api/engagements", tags=["reports"])


@router.get("/{engagement_id}/report.md", response_class=PlainTextResponse)
async def report_markdown(engagement_id: str) -> PlainTextResponse:
    try:
        report = await build_report(engagement_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="engagement not found") from exc
    return PlainTextResponse(
        report["markdown"],
        headers={"Content-Disposition": f'attachment; filename="report-{engagement_id}.md"'},
    )


@router.get("/{engagement_id}/report.html", response_class=HTMLResponse)
async def report_html(engagement_id: str) -> HTMLResponse:
    try:
        report = await build_report(engagement_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="engagement not found") from exc
    return HTMLResponse(report["html"])


@router.get("/{engagement_id}/report.json")
async def report_json(engagement_id: str) -> dict:
    try:
        report = await build_report(engagement_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="engagement not found") from exc
    return {"meta": report["meta"], "markdown": report["markdown"]}


@router.get("/{engagement_id}/report")
async def report_multi(engagement_id: str, format: str = "md"):
    """Unified multi-format export: md | pdf(print-html) | json | sarif."""
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    fmt = (format or "md").lower()

    if fmt in ("md", "markdown"):
        report = await build_report(engagement_id)
        return PlainTextResponse(report["markdown"], headers={
            "Content-Disposition": f'attachment; filename="report-{engagement_id}.md"'})
    if fmt in ("pdf", "html", "print"):
        report = await build_report(engagement_id)
        return HTMLResponse(report["html"])

    findings = [f for f in await ValidatedFindingRepository().list(engagement_id)
                if f.status in ("confirmed", "likely")]
    if fmt == "json":
        chains = await ChainRepository().list(engagement_id)
        return JSONResponse(findings_json(eng, findings, chains))
    if fmt == "sarif":
        return JSONResponse(sarif(eng, findings), headers={
            "Content-Disposition": f'attachment; filename="report-{engagement_id}.sarif"'})
    raise HTTPException(status_code=400, detail="format must be md|pdf|json|sarif")
