"""What the operator should read first.

A recon view that returns eight panels of raw data makes the operator do the
synthesis, and the synthesis is the part that decides whether an engagement is
worth opening. These are pure functions over the collected sections, so the
same conclusions appear in the UI and could appear in a scoping note without a
second implementation drifting away from the first.

Deliberately not a score. A number invites comparison between targets that have
nothing in common, and the first time someone quotes "68/100" in a client
meeting the number has done more harm than the eight panels would have.
"""
from __future__ import annotations

from typing import Any, Dict, List

LEVEL_INFO = "info"
LEVEL_NOTE = "note"
LEVEL_WARN = "warn"

_ORDER = {LEVEL_WARN: 0, LEVEL_NOTE: 1, LEVEL_INFO: 2}


def _point(level: str, text: str, why: str = "") -> Dict[str, str]:
    return {"level": level, "text": text, "why": why}


def highlights(report: Dict[str, Any]) -> List[Dict[str, str]]:
    """The handful of sentences worth putting at the top."""
    out: List[Dict[str, str]] = []
    out += _scope_points(report)
    out += _reachability_points(report)
    out += _tls_points(report)
    out += _exposure_points(report)
    return sorted(out, key=lambda p: _ORDER.get(p["level"], 3))


def _scope_points(report) -> List[Dict[str, str]]:
    out = []
    network = report.get("network") or {}
    asn = network.get("asn") or {}
    shared = asn.get("shared_infrastructure")
    if shared:
        out.append(_point(
            LEVEL_WARN,
            f"The address belongs to {asn.get('as_name') or shared}, not to the client.",
            "Anything at the network layer here is that provider's to authorize, not "
            "your client's. Scope the application, not the host."))

    tech = report.get("technologies") or {}
    infra = [t for t in tech.get("infrastructure", [])]
    wafs = [t["name"] for t in infra if t.get("category") == "waf"]
    if wafs:
        out.append(_point(
            LEVEL_NOTE, f"A WAF is in the path: {', '.join(wafs)}.",
            "Expect 403s that are the WAF, not the application. Plan for that before "
            "reading a page of blocked requests as 'not vulnerable'."))

    ct = report.get("certificate_transparency") or {}
    if ct.get("available") and ct.get("total", 0) > 1:
        out.append(_point(
            LEVEL_NOTE,
            f"{ct['total']} names for this domain are already public in CT logs.",
            "Names that exist but are not on the scoping document are the conversation "
            "to have now, not in week two."))
    return out


def _reachability_points(report) -> List[Dict[str, str]]:
    out = []
    dns = report.get("dns") or {}
    http = report.get("http") or {}

    if dns and not dns.get("resolved") and not (report.get("target") or {}).get("is_ip"):
        out.append(_point(LEVEL_WARN, "The name does not resolve.",
                          "Nothing else below can be trusted; check the spelling, or "
                          "whether it only resolves on an internal resolver."))
        return out

    addresses = dns.get("addresses") or []
    if len(addresses) > 3:
        out.append(_point(
            LEVEL_INFO, f"{len(addresses)} addresses answer for this name.",
            "A load balancer or an anycast edge. Behaviour can differ per address."))

    root = http.get("root") or {}
    if http.get("error") and not root:
        out.append(_point(LEVEL_WARN, f"No HTTP answer: {http['error']}.",
                          "The name may resolve to something that is not a web server, "
                          "or reach this container's network differently than yours."))
    redirects = http.get("redirects") or []
    if redirects:
        last = redirects[-1].get("to", "")
        out.append(_point(LEVEL_INFO,
                          f"{len(redirects)} redirect(s), ending at {last[:100]}.",
                          "Where the application really lives."))
    if root.get("status", 0) in (401, 403):
        out.append(_point(LEVEL_NOTE, f"The root answers {root['status']}.",
                          "Authentication or a block sits in front. An engagement will "
                          "need credentials, or the traffic-driven path through the proxy."))
    return out


def _tls_points(report) -> List[Dict[str, str]]:
    out = []
    tls = report.get("tls") or {}
    if not tls:
        return out
    if not tls.get("available"):
        if (report.get("target") or {}).get("scheme") == "https":
            out.append(_point(LEVEL_WARN, f"TLS did not complete: {tls.get('error','')}.", ""))
        return out
    for issue in tls.get("issues") or []:
        level = LEVEL_WARN if ("expired" in issue or "self-signed" in issue
                               or "signed with" in issue) else LEVEL_NOTE
        out.append(_point(level, f"Certificate: {issue}.", ""))
    san_count = tls.get("san_count", 0)
    if san_count > 1:
        out.append(_point(LEVEL_INFO,
                          f"The certificate covers {san_count} names.",
                          "Each one is a candidate host; they are listed below."))
    return out


def _exposure_points(report) -> List[Dict[str, str]]:
    out = []
    headers = (report.get("headers") or {})
    missing = [m["name"] for m in headers.get("missing", [])]
    if missing:
        out.append(_point(
            LEVEL_NOTE, f"Missing security headers: {', '.join(missing)}.",
            "Each one is cheap to add and each absence widens something else. "
            "Worth confirming against an authenticated page before reporting."))
    disclosing = [d["name"] for d in headers.get("disclosing", [])]
    if disclosing:
        out.append(_point(LEVEL_INFO,
                          f"Version-disclosing headers: {', '.join(disclosing)}.",
                          "Useful to you now; useful to anyone else for the same reason."))

    cookies = report.get("cookies") or []
    bad = [c["name"] for c in cookies if not c["http_only"] or not c["secure"]]
    if bad:
        out.append(_point(LEVEL_NOTE,
                          f"Cookies without HttpOnly or Secure: {', '.join(bad[:5])}.",
                          "Set before login, so this is the pre-auth session only - "
                          "confirm after signing in."))

    files = report.get("public_files") or {}
    security_txt = files.get("/.well-known/security.txt") or {}
    if security_txt.get("present"):
        out.append(_point(LEVEL_INFO, "security.txt is published.",
                          "There is a disclosure contact; read it before reporting anything."))
    robots = files.get("/robots.txt") or {}
    if robots.get("present"):
        disallows = [line for line in (robots.get("preview") or "").splitlines()
                     if line.lower().startswith("disallow:")]
        if disallows:
            out.append(_point(LEVEL_INFO,
                              f"robots.txt lists {len(disallows)} disallowed path(s).",
                              "A list of paths someone did not want indexed. Not a "
                              "vulnerability; frequently a map."))
    return out


def counts(report: Dict[str, Any]) -> Dict[str, int]:
    """The numbers the page puts in its header row."""
    tech = report.get("technologies") or {}
    ct = report.get("certificate_transparency") or {}
    tls = report.get("tls") or {}
    return {
        "addresses": len((report.get("dns") or {}).get("addresses") or []),
        "technologies": sum(len(v) for v in tech.values()),
        "names_in_ct": ct.get("total", 0) if ct.get("available") else 0,
        "certificate_names": tls.get("san_count", 0) if tls.get("available") else 0,
        "missing_headers": len((report.get("headers") or {}).get("missing") or []),
    }


def candidate_hosts(report: Dict[str, Any]) -> List[str]:
    """Names worth carrying into the engagement's scope list.

    Suggestions, not a scope. The operator decides what they are authorized to
    test; this only saves them retyping what recon already found.
    """
    target = report.get("target") or {}
    out: List[str] = []
    if target.get("host"):
        out.append(target["host"])
    tls = report.get("tls") or {}
    if tls.get("available"):
        out += [n for n in tls.get("san") or [] if not n.startswith("*.")]
    ct = report.get("certificate_transparency") or {}
    if ct.get("available"):
        out += ct.get("names") or []
    seen, ordered = set(), []
    for name in out:
        low = name.strip().lower()
        if low and low not in seen:
            seen.add(low)
            ordered.append(low)
    return ordered[:200]
