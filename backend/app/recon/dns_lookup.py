"""DNS, as much of it as is worth showing.

Nothing here touches the target: every query goes to a resolver, which is what
makes it safe to run before an engagement exists.

The record set is chosen for what it tells a tester, not for completeness:

    A / AAAA    where it actually is - and how many places, which is the first
                hint of a CDN or a load balancer
    CNAME       who really runs it. A CNAME to a vendor is the fastest way to
                discover that the interesting application is not yours to test
    NS          who controls the zone
    MX          the mail path, and with it the mail vendor
    TXT         SPF, verification tokens, and the occasional accidental secret
    SOA         the primary, and the zone's contact
    CAA         which CAs may issue - absence is itself worth noting
    _dmarc TXT  whether the domain can be spoofed, which lands in reports

PTR is looked up separately, per resolved address.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

from app.recon.budget import DNS_TIMEOUT

logger = logging.getLogger("syphax.recon.dns")

RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA")

# A TXT record can be long and split into chunks; joining them is what makes an
# SPF record readable rather than a list of fragments.
MAX_VALUES_PER_TYPE = 25


def _resolver():
    import dns.asyncresolver  # noqa: PLC0415 - optional at import time
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    return resolver


def _render(rdata) -> str:
    """One record as a string. TXT arrives as chunks and has to be rejoined or
    a long SPF record reads as nonsense."""
    strings = getattr(rdata, "strings", None)
    if strings is not None:
        return "".join(s.decode("utf-8", "replace") for s in strings)
    return str(rdata).strip()


async def _query(host: str, rtype: str) -> List[str]:
    try:
        answers = await _resolver().resolve(host, rtype)
    except Exception:  # noqa: BLE001 - dnspython raises a dozen types, all "no"
        return []
    return [_render(r) for r in list(answers)[:MAX_VALUES_PER_TYPE]]


async def reverse(address: str) -> str:
    """PTR for one address. Empty when there is none, which is normal."""
    try:
        import dns.asyncresolver  # noqa: PLC0415
        import dns.reversename    # noqa: PLC0415
        name = dns.reversename.from_address(address)
        resolver = _resolver()
        answers = await resolver.resolve(name, "PTR")
        return str(list(answers)[0]).rstrip(".")
    except Exception:  # noqa: BLE001
        return ""


async def lookup(host: str) -> Dict[str, Any]:
    """Every record type at once. A failure of one type is an empty list, not
    an exception: a domain with no MX is a fact, not an error."""
    types = list(RECORD_TYPES)
    results = await asyncio.gather(*(_query(host, t) for t in types),
                                   return_exceptions=True)
    records: Dict[str, List[str]] = {}
    for rtype, result in zip(types, results, strict=True):
        records[rtype] = result if isinstance(result, list) else []

    dmarc = await _query(f"_dmarc.{host}", "TXT")

    addresses = records.get("A", []) + records.get("AAAA", [])
    ptrs = {}
    if addresses:
        found = await asyncio.gather(*(reverse(a) for a in addresses[:8]),
                                     return_exceptions=True)
        ptrs = {addr: (name if isinstance(name, str) else "")
                for addr, name in zip(addresses[:8], found, strict=True)}

    return {
        "records": records,
        "addresses": addresses,
        "reverse": ptrs,
        "dmarc": dmarc,
        "spf": [t for t in records.get("TXT", []) if t.lower().startswith("v=spf1")],
        "resolved": bool(addresses),
    }
