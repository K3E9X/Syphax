"""Whose network is this, and who registered the name.

Both answers come from public registries, not from the target. Two sources,
picked for different reasons:

  Team Cymru's DNS interface, for the ASN. It is a DNS query - no HTTP, no API
  key, no rate limit worth worrying about - and it answers the question an
  operator actually asks first: is this the client's own network, or is it
  Cloudflare/AWS/OVH? That single fact changes the scope conversation, because
  an IP that belongs to a hosting provider is not an IP the client can
  authorize you to attack at the network layer.

  RDAP, for the netblock's registration and the domain's. RDAP rather than
  WHOIS because it is JSON over HTTPS with no port 43 and no per-registry
  parsing, and because `whois` is not installed in this image.

Everything here is best-effort. A registry that is slow, rate-limiting or
simply has nothing returns an empty section, and the view says so rather than
failing the whole recon.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional

from app.recon.budget import CONNECT_TIMEOUT, READ_TIMEOUT

logger = logging.getLogger("syphax.recon.net")

RDAP_BASE = "https://rdap.org"
CYMRU_V4 = "origin.asn.cymru.com"
CYMRU_V6 = "origin6.asn.cymru.com"
CYMRU_AS = "asn.cymru.com"

# Networks an operator should be told about before they scope anything at the
# network layer. Not a blocklist - the substring is matched against the ASN's
# own description, which is the registry's word, not ours.
SHARED_INFRASTRUCTURE = (
    "cloudflare", "amazon", "aws", "google", "microsoft", "azure", "akamai",
    "fastly", "digitalocean", "linode", "ovh", "hetzner", "scaleway",
    "vercel", "netlify", "github", "shopify", "wix", "squarespace",
    "incapsula", "imperva", "sucuri", "cdn77", "stackpath", "bunny",
)


def _cymru_name(address: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return None
    if addr.version == 4:
        return ".".join(reversed(str(addr).split("."))) + "." + CYMRU_V4
    # The v6 form is the expanded address, nibble by nibble, reversed.
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + "." + CYMRU_V6


async def asn_for(address: str) -> Dict[str, Any]:
    """ASN, announced prefix, country and registry for one address."""
    name = _cymru_name(address)
    if not name:
        return {}
    from app.recon.dns_lookup import _query  # noqa: PLC0415

    answers = await _query(name, "TXT")
    if not answers:
        return {}
    # "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
    parts = [p.strip() for p in answers[0].strip('"').split("|")]
    if len(parts) < 4:
        return {}
    asn = parts[0].split()[0] if parts[0] else ""
    info: Dict[str, Any] = {
        "asn": asn,
        "prefix": parts[1],
        "country": parts[2],
        "registry": parts[3],
        "allocated": parts[4] if len(parts) > 4 else "",
    }
    if asn:
        info["as_name"] = await _as_name(asn)
        info["shared_infrastructure"] = _is_shared(info.get("as_name", ""))
    return info


async def _as_name(asn: str) -> str:
    from app.recon.dns_lookup import _query  # noqa: PLC0415
    answers = await _query(f"AS{asn}.{CYMRU_AS}", "TXT")
    if not answers:
        return ""
    # "15169 | US | arin | 2000-03-30 | GOOGLE, US"
    parts = [p.strip() for p in answers[0].strip('"').split("|")]
    return parts[-1] if parts else ""


def _is_shared(as_name: str) -> str:
    """Which shared provider this looks like, or "". Advisory: the operator
    still decides what is in scope, but they should not discover mid-engagement
    that the address belongs to a CDN."""
    low = (as_name or "").lower()
    for needle in SHARED_INFRASTRUCTURE:
        if needle in low:
            return needle
    return ""


async def _rdap(path: str) -> Optional[Dict[str, Any]]:
    import httpx  # noqa: PLC0415
    try:
        async with httpx.AsyncClient(
                timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
                follow_redirects=True,
                headers={"Accept": "application/rdap+json"}) as client:
            response = await client.get(f"{RDAP_BASE}{path}")
        if response.status_code != 200:
            return None
        return response.json()
    except Exception:  # noqa: BLE001 - a registry that is down is not an error here
        logger.debug("rdap lookup failed for %s", path, exc_info=True)
        return None


def _entity_names(entities) -> List[str]:
    """Pull human-readable names out of RDAP's jCard, which is a nested array
    format that nobody enjoys."""
    names: List[str] = []
    for entity in entities or []:
        vcard = entity.get("vcardArray") or []
        if len(vcard) > 1:
            for field in vcard[1]:
                if len(field) >= 4 and field[0] == "fn" and isinstance(field[3], str):
                    names.append(field[3])
        names.extend(_entity_names(entity.get("entities")))
    return names


def _events(data) -> Dict[str, str]:
    out = {}
    for event in (data or {}).get("events") or []:
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action and date:
            out[action] = date
    return out


async def network_for(address: str) -> Dict[str, Any]:
    """Netblock registration for one address."""
    data = await _rdap(f"/ip/{address}")
    if not data:
        return {}
    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
             for c in data.get("cidr0_cidrs") or []
             if c.get("length") is not None]
    return {
        "handle": data.get("handle", ""),
        "name": data.get("name", ""),
        "type": data.get("type", ""),
        "country": data.get("country", ""),
        "range": f"{data.get('startAddress','')} - {data.get('endAddress','')}".strip(" -"),
        "cidrs": cidrs,
        "organisations": sorted(set(_entity_names(data.get("entities"))))[:6],
        "events": _events(data),
    }


async def domain_for(domain: str) -> Dict[str, Any]:
    """Registration for a domain: registrar, dates, status, nameservers.

    The status codes are the interesting part. `clientTransferProhibited` on a
    production domain is normal hygiene; its absence, or a `pendingDelete`, is
    worth a sentence in a report.
    """
    if not domain:
        return {}
    data = await _rdap(f"/domain/{domain}")
    if not data:
        return {}
    events = _events(data)
    return {
        "domain": data.get("ldhName", domain),
        "handle": data.get("handle", ""),
        "status": data.get("status") or [],
        "registered": events.get("registration", ""),
        "expires": events.get("expiration", ""),
        "changed": events.get("last changed", "") or events.get("last update of RDAP database", ""),
        "registrar": next((n for n in _entity_names(data.get("entities"))), ""),
        "nameservers": sorted({ns.get("ldhName", "").lower()
                               for ns in data.get("nameservers") or [] if ns.get("ldhName")}),
        "dnssec": bool(data.get("secureDNS", {}).get("delegationSigned")),
    }
