"""Names already published in Certificate Transparency.

Every publicly-trusted certificate issued since 2018 is logged, publicly, by
design. Reading that log is not enumeration of the target - the target is never
contacted - it is reading a public ledger the target's own CA wrote to.

It is also, in practice, the single most productive source of scope before an
engagement starts: staging hosts, admin panels, internal tools behind a VPN and
the vendor SaaS nobody mentioned all end up with certificates, and all of them
end up here. Discovering them now, on the scoping call, is much better than
discovering them in week two.

Best-effort. crt.sh is a free service run by one CA; when it is slow or down
this returns nothing and the view says so, rather than failing the recon.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger("syphax.recon.ct")

CRTSH = "https://crt.sh/"
# Short on purpose. crt.sh can take 30s on a large domain, and an operator
# waiting on a recon view will have given up long before it answers.
TIMEOUT = 12.0
MAX_NAMES = 300


async def subdomains(registrable_domain: str) -> Dict[str, Any]:
    """Names seen in CT for this domain. `{"available": False}` when the log
    could not be read - which is not the same as "there are none"."""
    if not registrable_domain or "." not in registrable_domain:
        return {"available": False, "reason": "no registrable domain to query"}

    import httpx  # noqa: PLC0415
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            response = await client.get(
                CRTSH, params={"q": f"%.{registrable_domain}", "output": "json"},
                headers={"Accept": "application/json"})
        if response.status_code != 200:
            return {"available": False, "reason": f"crt.sh answered {response.status_code}"}
        rows = response.json()
    except Exception as exc:  # noqa: BLE001 - a third-party outage is not our error
        logger.debug("crt.sh lookup failed", exc_info=True)
        return {"available": False, "reason": f"crt.sh unreachable: {exc.__class__.__name__}"}

    return {"available": True, **summarise(rows, registrable_domain)}


def summarise(rows: List[Dict[str, Any]], registrable_domain: str) -> Dict[str, Any]:
    """Pure: turn crt.sh rows into a name list and a note about wildcards.

    One certificate carries many names and one name appears on many
    certificates, so the raw response for a busy domain is tens of thousands of
    rows for a few hundred distinct names. Deduplicating is the whole job.
    """
    names = set()
    wildcards = set()
    issuers = {}

    for row in rows or []:
        issuer = (row.get("issuer_name") or "").strip()
        if issuer:
            short = _issuer_short(issuer)
            issuers[short] = issuers.get(short, 0) + 1
        raw = (row.get("name_value") or "")
        for name in raw.replace("\\n", "\n").splitlines():
            name = name.strip().lower().rstrip(".")
            if not name or " " in name:
                continue
            if not (name == registrable_domain or name.endswith("." + registrable_domain)):
                continue
            if name.startswith("*."):
                wildcards.add(name)
            else:
                names.add(name)

    ordered = sorted(names, key=lambda n: (n.count("."), n))
    return {
        "domain": registrable_domain,
        "names": ordered[:MAX_NAMES],
        "total": len(ordered),
        "truncated": len(ordered) > MAX_NAMES,
        "wildcards": sorted(wildcards)[:20],
        "issuers": sorted(issuers.items(), key=lambda kv: -kv[1])[:5],
        "certificates_seen": len(rows or []),
    }


def _issuer_short(issuer: str) -> str:
    """The CA's organisation out of an RDN string, or the whole thing."""
    for part in issuer.split(","):
        part = part.strip()
        if part.upper().startswith("O="):
            return part[2:].strip().strip('"')
    return issuer[:60]
