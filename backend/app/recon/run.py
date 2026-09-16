"""Run every recon section, concurrently, and let each one fail on its own.

The shape of this function is the whole design: `asyncio.gather` with
`return_exceptions=True`, and a per-section try. A recon view is made of eight
independent lookups against eight independent services, and the one that is
slow or down today has nothing to do with the seven that would have answered.
Failing the whole view because crt.sh is rate-limiting would make the feature
useless exactly when the operator is in a hurry.

So every section returns its own `{...}` or `{}`, the errors are collected and
shown, and the page renders what came back.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List

from app.recon import budget, ct_logs, dns_lookup, http_probe, net_info, summary, tech, tls_info
from app.recon.target import Target, parse

logger = logging.getLogger("syphax.recon")


async def _safe(name: str, coro, errors: List[Dict[str, str]], default):
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001 - one dead service must not kill the view
        logger.debug("recon section %s failed", name, exc_info=True)
        errors.append({"section": name, "error": f"{exc.__class__.__name__}: {exc}"})
        return default


async def run(raw_target: str, *, include_ct: bool = True) -> Dict[str, Any]:
    """The whole report for one target. Raises TargetError only for input that
    cannot be parsed; everything after that degrades section by section."""
    started = time.perf_counter()
    target: Target = parse(raw_target)
    errors: List[Dict[str, str]] = []

    # Phase one: everything that does not need a resolved address.
    dns_task = _safe("dns", dns_lookup.lookup(target.host), errors, {}) \
        if not target.is_ip else _noop({"addresses": [target.host], "records": {},
                                        "reverse": {}, "dmarc": [], "spf": [],
                                        "resolved": True})
    http_task = _safe("http", http_probe.probe(target), errors, None)
    tls_task = _safe("tls", tls_info.fetch(target.host, target.port if target.scheme == "https" else 443,
                                           server_name=target.host), errors,
                     {"available": False, "error": "not attempted"})
    domain_task = _safe("domain", net_info.domain_for(target.registrable_domain), errors, {}) \
        if not target.is_ip else _noop({})
    ct_task = _safe("certificate_transparency",
                    ct_logs.subdomains(target.registrable_domain), errors,
                    {"available": False, "reason": "lookup failed"}) \
        if include_ct and not target.is_ip else _noop(
            {"available": False, "reason": "skipped for an IP target"})

    dns, http, tls, domain, ct = await asyncio.gather(
        dns_task, http_task, tls_task, domain_task, ct_task)

    # Phase two: needs an address, so it waits for DNS.
    addresses = (dns or {}).get("addresses") or []
    asn, network = {}, {}
    if addresses:
        asn, network = await asyncio.gather(
            _safe("asn", net_info.asn_for(addresses[0]), errors, {}),
            _safe("network", net_info.network_for(addresses[0]), errors, {}),
        )

    report: Dict[str, Any] = {
        "target": target.to_public(),
        "dns": dns or {},
        "network": {"asn": asn, "registration": network,
                    "primary_address": addresses[0] if addresses else ""},
        "domain": domain or {},
        "tls": tls or {},
        "certificate_transparency": ct or {},
        "errors": errors,
        "scope_of_this_check": budget.describe(),
    }

    report.update(_from_http(http))
    report["highlights"] = summary.highlights(report)
    report["counts"] = summary.counts(report)
    report["candidate_hosts"] = summary.candidate_hosts(report)
    report["took_ms"] = round((time.perf_counter() - started) * 1000)
    return report


def _from_http(probe) -> Dict[str, Any]:
    """Everything derived from the single root response."""
    if probe is None:
        return {"http": {"error": "the HTTP probe did not run"}, "technologies": {},
                "headers": {}, "cookies": [], "public_files": {}}

    root = probe.root or {}
    if not root:
        # Nothing answered. Reviewing headers here would report all six as
        # missing, which reads as a finding about the target when it is a
        # finding about the connection.
        return {"http": {"error": probe.error or "the target did not answer",
                         "requests_made": probe.requests_made,
                         "redirects": probe.redirects, "root": {}},
                "technologies": {}, "headers": {}, "cookies": [],
                "public_files": probe.files}

    raw_cookies = root.get("set_cookie") or []
    detections = tech.detect(
        headers=root.get("headers") or {},
        cookies=root.get("cookies") or [],
        body=root.get("body") or "",
    )
    return {
        "http": {
            "error": probe.error,
            "requests_made": probe.requests_made,
            "redirects": probe.redirects,
            "root": {k: v for k, v in root.items()
                     if k not in ("body", "set_cookie")},
            # The body is not returned. It can be a megabyte of someone else's
            # markup, and everything this view needs from it is already
            # extracted above.
            "body_sample": (root.get("body") or "")[:1500],
        },
        "technologies": tech.by_layer(detections),
        "headers": http_probe.review_headers(root.get("headers") or {}),
        "cookies": http_probe.review_cookies(raw_cookies),
        "public_files": probe.files,
    }


async def _noop(value):
    return value
