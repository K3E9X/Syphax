"""Attack surface + methodology coverage for a single engagement."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app import coverage_util
from app.audit import audit
from app.audit import list_events as audit_events
from app.engagements import EngagementRepository
from app.engagements import scope_util as _scope_util
from app.methodology import CATALOG
from app.orchestrator.state import EngagementState
from app.proxy import FlowRepository
from app.scans.storage import JobRepository
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
    # (host, port, proto) -> the port dict already in that host's "ports" list,
    # so naabu's bare entry and nmap's service-rich entry for the same port
    # collapse to one row (and the richer one wins).
    port_index: Dict[tuple, Dict[str, Any]] = {}

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
            # value like "8443/tcp · host · nginx 1.18", "8443/tcp · host" or
            # the bare "8443/tcp". Fields are "·"-separated: portspec, host,
            # then an optional "service version" blob.
            parts = [p.strip() for p in a.value.split("·")]
            portspec = parts[0] if parts else a.value
            h = (parts[1].lower() if len(parts) > 1 and parts[1] else eng.target_host)
            svc = parts[2] if len(parts) > 2 else ""
            num, _, proto = portspec.partition("/")
            key = (h, num, proto or "tcp")
            existing = port_index.get(key)
            if existing is None:
                entry = {"port": num, "proto": proto or "tcp",
                         "service": svc, "version": "", "state": "open"}
                host_entry(h)["ports"].append(entry)
                port_index[key] = entry
            elif svc and not existing.get("service"):
                # A richer entry (nmap) arriving after a bare one (naabu).
                existing["service"] = svc

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


# ---------------------------------------------------------------------------
# Scope candidates: hosts the run DISCOVERED but was not allowed to touch.
#
# An out-of-scope host is not an error, it is a finding about the surface:
# "there is an API/subdomain here you have not scoped". We surface them so the
# operator can admit the ones they are authorized for, in one click - the tool
# never widens its own authorization.
# ---------------------------------------------------------------------------

_MAX_CANDIDATES = 60


def _plausible_host(h: str) -> bool:
    """Filter artefacts (a bare port number, empty strings) out of the list."""
    h = (h or "").strip().lower()
    if not h or len(h) > 253:
        return False
    if _scope_util.is_ip(h):
        return True
    if "." not in h or h.replace(".", "").isdigit():
        return False
    return all(part and len(part) <= 63 for part in h.split("."))


async def _resolve(host: str) -> list:
    import socket
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
        return sorted({i[4][0] for i in infos if i and i[4]})
    except Exception:  # noqa: BLE001 - unresolved is information, not an error
        return []


@router.get("/{engagement_id}/scope/candidates")
async def scope_candidates(engagement_id: str) -> Dict[str, Any]:
    """Hosts discovered during the run that are not in the engagement scope."""
    eng = await _engagements.get(engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    found: Dict[str, Dict[str, Any]] = {}

    def note(host: str, source: str) -> None:
        host = (host or "").strip().lower().rstrip(".")
        if not _plausible_host(host) or eng.host_in_scope(host):
            return
        entry = found.setdefault(host, {"host": host, "sources": set()})
        entry["sources"].add(source)

    # Subdomains enumerated by subfinder (discovered, not necessarily admitted).
    try:
        for job in await JobRepository().list_by_engagement(engagement_id):
            if job.tool != "subfinder":
                continue
            for f in (job.findings or []):
                note(getattr(f, "target", ""), "subfinder")
    except Exception:  # noqa: BLE001
        pass

    # Anything a tool was pointed at and the scope gate refused.
    try:
        for ev in await audit_events(engagement_id=engagement_id, limit=500):
            if ev.get("action") != "scan.blocked_out_of_scope":
                continue
            note((ev.get("detail") or {}).get("target_host", ""), "blocked")
    except Exception:  # noqa: BLE001
        pass

    hosts = sorted(found)[:_MAX_CANDIDATES]
    # Resolve concurrently so the panel can say which ones are the same server.
    ip_lists = await asyncio.gather(*(_resolve(h) for h in hosts))
    target_ips = [h for h in eng.scope_hosts if _scope_util.is_ip(h)]
    if not target_ips:
        target_ips = await _resolve(eng.target_host)

    items = []
    for host, ips in zip(hosts, ip_lists, strict=True):
        same_dom = _scope_util.same_registrable_domain(host, eng.target_host)
        items.append({
            "host": host,
            "sources": sorted(found[host]["sources"]),
            "ips": ips,
            "same_domain": same_dom,
            "same_server": bool(ips) and _scope_util.same_server(ips, target_ips),
        })
    # Most-related first: same server, then same domain, then the rest.
    items.sort(key=lambda i: (not i["same_server"], not i["same_domain"], i["host"]))
    return {"count": len(items), "items": items, "scope": eng.scope_hosts}


class ScopeAddBody(BaseModel):
    hosts: List[str]


@router.post("/{engagement_id}/scope/add")
async def scope_add(engagement_id: str, body: ScopeAddBody) -> Dict[str, Any]:
    """Admit operator-chosen hosts into the engagement scope.

    This widens the authorization, so it is an explicit operator action and is
    audited. Entries may be hostnames, IPs or "*.example.com" wildcards.
    """
    eng = await _engagements.get(engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    added = []
    scope = list(eng.scope_hosts)
    for raw in (body.hosts or []):
        host = (raw or "").strip().lower().rstrip(".")
        bare = host[2:] if host.startswith("*.") else host.lstrip(".")
        if not _plausible_host(bare):
            raise HTTPException(status_code=400, detail=f"not a valid host: {raw!r}")
        if host not in scope:
            scope.append(host)
            added.append(host)

    if added:
        eng.scope_hosts = scope
        await _engagements.update(eng)
        await audit("engagement.scope_extended", engagement_id=eng.id, added=added)
    return {"scope": scope, "added": added}
