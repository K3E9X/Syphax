"""Attack surface + methodology coverage for a single engagement."""
from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException

from app import coverage_util
from app.engagements import EngagementRepository
from app.methodology import CATALOG
from app.orchestrator.state import EngagementState
from app.proxy import FlowRepository
from app.validation import ValidatedFindingRepository

router = APIRouter(prefix="/api/engagements", tags=["surface"])

_engagements = EngagementRepository()
_vf = ValidatedFindingRepository()


@router.get("/{engagement_id}/surface")
async def surface(engagement_id: str) -> Dict[str, Any]:
    eng = await _engagements.get(engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    state = EngagementState(engagement_id)
    assets = await state.assets()
    tech = await state.technologies()

    hosts: Dict[str, Dict[str, Any]] = {}

    def host_entry(h: str) -> Dict[str, Any]:
        return hosts.setdefault(h, {"host": h, "https": False, "source": "",
                                    "tech": [], "ports": [], "endpoints": []})

    for a in assets:
        if a.kind == "host":
            e = host_entry(a.value)
            e["https"] = e["https"] or a.is_https
            e["source"] = e["source"] or a.source
        elif a.kind == "endpoint":
            p = urlparse(a.value)
            h = (p.hostname or "").lower()
            if not h:
                continue
            e = host_entry(h)
            e["https"] = e["https"] or (p.scheme == "https")
            params = [kv.split("=")[0] for kv in (p.query.split("&") if p.query else []) if kv]
            e["endpoints"].append({"m": "GET", "path": p.path or "/", "params": params, "status": None})
        elif a.kind == "port":
            # value like "8443/tcp · host" or "8443/tcp"
            raw = a.value.replace("·", " ").split()
            portspec = raw[0] if raw else a.value
            h = raw[-1] if len(raw) > 1 else eng.target_host
            num, _, proto = portspec.partition("/")
            host_entry(h)["ports"].append({"port": num, "proto": proto or "tcp",
                                            "service": "", "version": "", "state": "open"})

    # Enrich endpoints/status from captured proxy flows.
    try:
        flows = await FlowRepository().list_flows(limit=1000)
    except Exception:  # noqa: BLE001
        flows = []
    seen = set()
    for f in flows:
        h = (f.host or "").lower()
        if not eng.host_in_scope(h):
            continue
        key = (h, f.method, f.path)
        if key in seen:
            continue
        seen.add(key)
        e = host_entry(h)
        params = [kv.split("=")[0] for kv in (urlparse(f.url).query.split("&") if urlparse(f.url).query else []) if kv]
        e["endpoints"].append({"m": f.method, "path": f.path, "params": params, "status": f.status_code})

    # Attach engagement technologies to the primary host.
    if eng.target_host in hosts:
        hosts[eng.target_host]["tech"] = tech
    elif hosts:
        next(iter(hosts.values()))["tech"] = tech

    return {"hosts": list(hosts.values())}


@router.get("/{engagement_id}/coverage")
async def coverage(engagement_id: str) -> Dict[str, Any]:
    eng = await _engagements.get(engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    state = EngagementState(engagement_id)
    rows = await state.coverage_rows()
    finding_classes = {f.vuln_class for f in await _vf.list(engagement_id)}
    groups = coverage_util.coverage_groups(CATALOG, rows, finding_classes)
    return {
        "categories": groups,
        "radar": coverage_util.radar(CATALOG, coverage_util.covered_ids(rows)),
        "radar_axes": coverage_util.AXES,
    }
