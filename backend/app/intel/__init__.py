"""Threat-intel enrichment: what the Internet already knows about the target.

Read-only. These providers query public databases ABOUT the target (Shodan /
Censys Internet-wide scan data, VirusTotal passive DNS + reputation); they
never send a packet to the target itself, so they run regardless of the active
exploitation gate and add value even on a WAF'd or rate-limited target.

Each provider is optional and best-effort: no key -> skipped; any error ->
logged and swallowed (enrichment never fails a run). Findings are stored as
synthetic analysis jobs (tool="intel_shodan"/"intel_censys"/"intel_vt") so they
flow through the normal validation -> report pipeline. Open ports Shodan/Censys
report are ALSO registered as "port" assets, so the Surface page shows the
externally-visible service exposure even when naabu/nmap did not run.

API shapes follow the documented public APIs: Shodan REST, Censys Search v2,
VirusTotal v3.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from app.analysis._store import save_analysis_job
from app.cve_refs import normalize_cve
from app.engagements import EngagementRepository
from app.orchestrator.state import EngagementState
from app.scans.models import Finding

logger = logging.getLogger("syphax.intel")

_TIMEOUT = httpx.Timeout(20.0)


async def run_intel(engagement_id: str) -> Dict[str, int]:
    """Run every configured intel provider for the engagement. Best-effort."""
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}
    host = (eng.target_host or "").strip().lower()
    if not host:
        return {"skipped": 1}

    # Keys come from the UI-saved settings (read at point of use so a token set
    # in Settings works immediately, in this process too), with a .env fallback.
    from app.settings_store import get_integration_key
    shodan_key = await get_integration_key("shodan")
    censys_id = await get_integration_key("censys_id")
    censys_secret = await get_integration_key("censys_secret")
    vt_key = await get_integration_key("virustotal")

    state = EngagementState(engagement_id)
    counts: Dict[str, int] = {}

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        ip = await _resolve_ip(client, host, shodan_key)

        if shodan_key and ip:
            try:
                findings = await _shodan(client, host, ip, shodan_key)
                await _persist(state, "intel_shodan", findings, host)
                counts["shodan"] = len(findings)
            except Exception:  # noqa: BLE001
                logger.exception("[%s] shodan enrichment failed", engagement_id)

        if censys_id and censys_secret and ip:
            try:
                findings = await _censys(client, host, ip, censys_id, censys_secret)
                await _persist(state, "intel_censys", findings, host)
                counts["censys"] = len(findings)
            except Exception:  # noqa: BLE001
                logger.exception("[%s] censys enrichment failed", engagement_id)

        if vt_key:
            try:
                findings = await _virustotal(client, host, ip, vt_key)
                await _persist(state, "intel_vt", findings, host)
                counts["virustotal"] = len(findings)
            except Exception:  # noqa: BLE001
                logger.exception("[%s] virustotal enrichment failed", engagement_id)

    return counts or {"skipped": 1}


async def _persist(state: EngagementState, tool: str, findings: List[Finding], host: str) -> None:
    await save_analysis_job(state.engagement_id, tool, findings, target=host)
    # Register externally-visible open ports as assets so Surface shows them.
    for f in findings:
        meta = f.metadata or {}
        if meta.get("port") and not meta.get("nse_script"):
            proto = (meta.get("protocol") or "tcp").lower()
            svc = str(meta.get("service") or "").strip()
            h = str(meta.get("host") or host).strip().lower()
            value = f"{meta['port']}/{proto} · {h} · {svc}".rstrip(" ·").rstrip()
            try:
                await state.add_asset("port", value, source=tool)
            except Exception:  # noqa: BLE001 - asset write must not fail enrichment
                logger.debug("intel: could not add port asset %s", value)


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #

async def _resolve_ip(client: httpx.AsyncClient, host: str, shodan_key: str) -> Optional[str]:
    """Resolve host -> IP. Prefer Shodan's resolver (no local DNS needed)."""
    if shodan_key:
        try:
            r = await client.get("https://api.shodan.io/dns/resolve",
                                  params={"hostnames": host, "key": shodan_key})
            if r.status_code == 200:
                ip = (r.json() or {}).get(host)
                if ip:
                    return str(ip)
        except Exception:  # noqa: BLE001
            pass
    try:
        import socket
        return socket.gethostbyname(host)
    except Exception:  # noqa: BLE001
        return None


async def _shodan(client: httpx.AsyncClient, host: str, ip: str, key: str) -> List[Finding]:
    r = await client.get(f"https://api.shodan.io/shodan/host/{ip}",
                          params={"key": key})
    if r.status_code != 200:
        return []
    data = r.json() or {}
    findings: List[Finding] = []

    for svc in data.get("data", []) or []:
        if not isinstance(svc, dict):
            continue
        port = svc.get("port")
        if not port:
            continue
        transport = (svc.get("transport") or "tcp").lower()
        product = (svc.get("product") or "").strip()
        version = (svc.get("version") or "").strip()
        sname = (svc.get("_shodan", {}) or {}).get("module") or product or "service"
        svc_str = " ".join(p for p in (product, version) if p) or sname
        findings.append(Finding(
            severity="info",
            title=f"Shodan: open {port}/{transport} ({svc_str}) on {ip}",
            description=f"Internet-visible service on {host} ({ip}) per Shodan.",
            target=f"{ip}:{port}",
            evidence=(svc.get("data") or "")[:800],
            metadata={"vuln_class": "recon", "host": host, "port": port,
                      "protocol": transport, "service": svc_str, "ip": ip,
                      "tool": "shodan"},
        ))
        # CVEs Shodan attributes to this service.
        for cve_raw in (svc.get("vulns") or {}):
            cve = normalize_cve(str(cve_raw))
            if not cve:
                continue
            findings.append(Finding(
                severity="high",
                title=f"{cve}: {svc_str} on {ip}:{port} (Shodan)",
                description=f"Shodan attributes {cve} to the service on {ip}:{port}.",
                target=f"{ip}:{port}",
                evidence=f"{cve} on {svc_str}",
                metadata={"vuln_class": "cve", "cve_id": cve, "host": host,
                          "port": port, "service": svc_str, "tool": "shodan"},
            ))
    return findings


async def _censys(client: httpx.AsyncClient, host: str, ip: str,
                  api_id: str, api_secret: str) -> List[Finding]:
    r = await client.get(
        f"https://search.censys.io/api/v2/hosts/{ip}",
        auth=(api_id, api_secret),
    )
    if r.status_code != 200:
        return []
    result = ((r.json() or {}).get("result") or {})
    findings: List[Finding] = []
    for svc in result.get("services", []) or []:
        if not isinstance(svc, dict):
            continue
        port = svc.get("port")
        if not port:
            continue
        transport = (svc.get("transport_protocol") or "tcp").lower()
        name = (svc.get("service_name") or "").strip()
        software = svc.get("software") or []
        prod = ""
        if software and isinstance(software, list) and isinstance(software[0], dict):
            prod = " ".join(p for p in (software[0].get("product", ""),
                                        software[0].get("version", "")) if p)
        svc_str = prod or name or "service"
        findings.append(Finding(
            severity="info",
            title=f"Censys: open {port}/{transport} ({svc_str}) on {ip}",
            description=f"Internet-visible service on {host} ({ip}) per Censys.",
            target=f"{ip}:{port}",
            evidence=name,
            metadata={"vuln_class": "recon", "host": host, "port": port,
                      "protocol": transport, "service": svc_str, "ip": ip,
                      "tool": "censys"},
        ))
    return findings


async def _virustotal(client: httpx.AsyncClient, host: str, ip: Optional[str], key: str) -> List[Finding]:
    headers = {"x-apikey": key}
    r = await client.get(f"https://www.virustotal.com/api/v3/domains/{host}", headers=headers)
    if r.status_code != 200:
        return []
    attrs = (((r.json() or {}).get("data") or {}).get("attributes") or {})
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    rep = attrs.get("reputation")

    findings: List[Finding] = []
    if malicious or suspicious:
        findings.append(Finding(
            severity="medium" if malicious else "low",
            title=f"VirusTotal: {host} flagged by {malicious} engine(s)"
                  + (f" (+{suspicious} suspicious)" if suspicious else ""),
            description=("Security vendors flag this domain as malicious/suspicious. "
                         "On an authorised target this usually means a stale blocklist "
                         "entry or a shared-host neighbour - verify before reporting."),
            target=host,
            evidence=f"malicious={malicious} suspicious={suspicious} reputation={rep}",
            metadata={"vuln_class": "recon", "host": host, "malicious": malicious,
                      "suspicious": suspicious, "reputation": rep, "tool": "virustotal"},
        ))
    return findings
