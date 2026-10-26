"""Rate limiting: OWASP API4, measured by a bounded burst and stated honestly.

"No rate limiting" is the single easiest claim in API testing to get wrong,
because the only way to establish it is to not hit a limit, and not hitting a
limit is also what happens when you send too few requests. So the finding here
never says "this API has no rate limit". It says what was measured:

    no limit was reached in N requests over M seconds

and N is in the title. A reader can then judge it, and a limit set at 1000/min
is not reported as an absence.

The burst is read-only GETs through SafePoC, and it is small: 20 requests by
default, which is less traffic than one page load and is not a denial of
service by any reading. With the `denial_of_service` capability declared on the
engagement the burst goes to 120, which supports a stronger statement; without
it the ceiling stays where a scope document would put it.

Two endpoints are never touched: anything that looks like authentication,
because a burst there means lockouts for real users and an incident ticket the
client did not plan for (that is the `credential_spray` capability's territory,
and auth_brute is the module that owns it), and anything that looks like
payment.

Rate-limit HEADERS count as evidence of a limit even when the limit is not
reached: an API answering with `x-ratelimit-remaining: 4997` is throttled and
saying otherwise would be false. That check costs nothing and prevents the
most common wrong finding in this class.

Gated on `allow_active_exploit`: the burst is deliberate extra traffic.

Stored as a synthetic job (tool="rate_limit").
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from app.limits import cap
from app.analysis._store import save_analysis_job
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.rate_limit")

# Default burst: fewer requests than a single page load makes.
BURST_DEFAULT = 20
# With the denial_of_service capability declared. Still bounded: the point is
# a defensible measurement, not an outage.
BURST_WITH_CAPABILITY = 120
CONCURRENCY = 5
MAX_ENDPOINTS = cap(2, floor=8)

_RATE_HEADERS = ("x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit",
                 "x-ratelimit-remaining", "x-rate-limit-remaining",
                 "ratelimit-remaining", "retry-after", "x-ratelimit-reset")

# Never burst these. Authentication belongs to credential_spray and auth_brute;
# payment moves money.
_FORBIDDEN = ("login", "signin", "sign-in", "auth", "oauth", "token",
              "password", "reset", "mfa", "otp", "verify",
              "payment", "pay", "charge", "refund", "transfer", "checkout",
              "export", "report", "download", "search")


def may_burst(url: str) -> bool:
    """Whether this endpoint may be bursted at all.

    `export`, `report`, `download` and `search` are excluded for a different
    reason than authentication: they are the endpoints where twenty requests
    IS expensive for the target, and the measurement is not worth the load.
    """
    path = (urlparse(url).path or "").lower()
    return not any(marker in path for marker in _FORBIDDEN)


def burst_size(capabilities) -> int:
    from app.exploit.capabilities import CAP_DENIAL
    return (BURST_WITH_CAPABILITY if CAP_DENIAL in (capabilities or set())
            else BURST_DEFAULT)


def limit_headers(headers: Dict[str, str]) -> Dict[str, str]:
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    return {k: lower[k] for k in _RATE_HEADERS if k in lower}


def verdict(statuses: List[int], headers: Dict[str, str], *,
            sent: int, seconds: float) -> Tuple[str, str]:
    """(verdict, detail). One of: throttled, declared, unlimited, unusable."""
    if not statuses:
        return "unusable", "no response came back"
    throttled = sum(1 for s in statuses if s == 429)
    if throttled:
        first = statuses.index(429) + 1
        return "throttled", (f"HTTP 429 after {first} of {sent} requests "
                             f"in {seconds:.1f}s")
    declared = limit_headers(headers)
    if declared:
        pairs = ", ".join(f"{k}: {v}" for k, v in sorted(declared.items()))
        return "declared", (f"no 429 in {sent} requests, but the API declares "
                            f"a quota: {pairs}")
    ok = sum(1 for s in statuses if 200 <= s < 400)
    if not ok:
        return "unusable", (f"{sent} requests, none of them successful "
                            f"(statuses: {sorted(set(statuses))})")
    return "unlimited", (f"{ok} of {sent} requests succeeded in {seconds:.1f}s, "
                         f"no 429 and no rate-limit header")


def finding_for(url: str, detail: str, *, sent: int, seconds: float,
                capped_by_policy: bool) -> Finding:
    rate = sent / seconds if seconds > 0 else float(sent)
    extra = ("\n\nThe burst stopped at {sent} requests because the "
             "`denial_of_service` capability is not declared on this "
             "engagement. With it the measurement goes to {more}, which would "
             "support a stronger statement than this one."
             ).format(sent=sent, more=BURST_WITH_CAPABILITY) if capped_by_policy else ""
    return Finding(
        # Deliberately not high. The measurement is a bound, not an absence,
        # and a reader has to be able to tell the difference at a glance.
        severity="medium" if sent >= BURST_WITH_CAPABILITY else "low",
        title=f"No rate limit reached in {sent} requests: {urlparse(url).path}",
        description=(
            f"{sent} requests were sent to this endpoint in {seconds:.1f}s "
            f"({rate:.0f}/s) and none was throttled: no HTTP 429, and the "
            f"responses carry no rate-limit header. This does not prove the "
            f"API has no limit - a limit above {sent} requests would look "
            f"exactly the same from here - and the title says what was "
            f"actually measured for that reason.\n\n"
            f"What it does mean: an unauthenticated client can repeat this "
            f"operation at least {rate:.0f} times a second. Where the "
            f"operation costs the server real work, or where repeating it is "
            f"itself the attack (enumeration, credential stuffing, coupon "
            f"brute force, SMS or email flooding at the client's expense), "
            f"that rate is the finding. OWASP API4:2023.{extra}"),
        target=url,
        evidence=(f"GET {url} x{sent}\n{detail}\n"
                  f"burst concurrency: {CONCURRENCY}\n"
                  f"read-only: GET through the safe layer, no body sent"),
        metadata={"tool": "rate_limit", "vuln_class": "rate_limit",
                  "status": "confirmed", "confidence": 0.8,
                  "owasp_api": "API4:2023", "requests_sent": sent,
                  "seconds": round(seconds, 2),
                  "measured_rate_per_second": round(rate, 1),
                  "bounded_by_policy": capped_by_policy},
    )


# ---------------------------------------------------------------------------


async def analyze_rate_limit(engagement_id: str, *,
                             allow_active: bool = True) -> Dict[str, int]:
    from app.engagements import EngagementRepository
    from app.exploit.capabilities import granted
    from app.validation.safe_poc import SafePoC

    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    if not (allow_active and getattr(eng, "allow_active_exploit", False)):
        await _say(engagement_id,
                   "Rate limiting was not measured: the test is a burst of "
                   "requests, which needs active exploitation enabled on this "
                   "engagement. The contract-level half of API4 (no 429 "
                   "documented anywhere) is reported by the schema audit "
                   "either way.")
        return {"skipped": 1, "reason": "allow_active_exploit is off"}

    targets = await _targets(eng)
    if not targets:
        await _say(engagement_id,
                   "No endpoint was eligible for a rate-limit burst. "
                   "Authentication, payment and export paths are excluded by "
                   "policy, and nothing else that answered was left.")
        return {"endpoints": 0, "findings": 0}

    sent_total = 0
    size = burst_size(granted(eng))
    safe = SafePoC(in_scope=eng.host_in_scope)
    findings: List[Finding] = []
    outcomes: Dict[str, str] = {}

    for url in targets[:MAX_ENDPOINTS]:
        statuses, headers, seconds = await _burst(safe, url, size)
        sent_total += len(statuses)
        name, detail = verdict(statuses, headers, sent=len(statuses),
                               seconds=seconds)
        outcomes[url] = name
        if name == "unlimited":
            findings.append(finding_for(
                url, detail, sent=len(statuses), seconds=seconds,
                capped_by_policy=(size == BURST_DEFAULT)))
        else:
            # A limit that exists is worth saying out loud, because "we did
            # not report one" and "we found one" look identical in a report.
            await _say(engagement_id,
                       f"Rate limiting on {url}: {detail}.")

    await save_analysis_job(engagement_id, "rate_limit", findings,
                            target=eng.target_url)
    logger.info("[%s] rate_limit: endpoints=%d requests=%d findings=%d %s",
                engagement_id, len(targets[:MAX_ENDPOINTS]), sent_total,
                len(findings), outcomes)
    return {"endpoints": len(targets[:MAX_ENDPOINTS]), "requests": sent_total,
            "findings": len(findings)}


async def _burst(safe, url: str, size: int) -> Tuple[List[int], Dict[str, str], float]:
    """`size` GETs in chunks of CONCURRENCY. Returns statuses in order sent."""
    statuses: List[int] = []
    headers: Dict[str, str] = {}
    started = time.monotonic()
    for offset in range(0, size, CONCURRENCY):
        chunk = min(CONCURRENCY, size - offset)
        results = await asyncio.gather(
            *[_one(safe, url) for _ in range(chunk)], return_exceptions=True)
        stop = False
        for result in results:
            if isinstance(result, BaseException) or result is None:
                continue
            statuses.append(result.status_code)
            headers.update(result.headers or {})
            if result.status_code == 429:
                stop = True
        if stop:
            break   # the limit answered; sending more would be pointless load
    return statuses, headers, max(time.monotonic() - started, 0.001)


async def _one(safe, url: str):
    try:
        return await safe.fetch(url, method="GET")
    except Exception:  # noqa: BLE001 - scope/policy refusal
        return None


async def _targets(eng) -> List[str]:
    """In-scope endpoints that answered, cheapest-looking first.

    An /api path is preferred because that is where repetition is the attack;
    a static asset is behind a CDN and measuring it says nothing about the
    application.
    """
    from app.proxy import FlowRepository

    try:
        summaries = await FlowRepository().list_flows(limit=600)
    except Exception:  # noqa: BLE001
        return []

    seen = set()
    ranked: List[Tuple[int, int, str]] = []
    for flow in summaries:
        url = str(flow.url or "")
        if not url or url in seen or not may_burst(url):
            continue
        if not eng.host_in_scope((urlparse(url).hostname or "").lower()):
            continue
        status = flow.status_code or 0
        if status < 200 or status >= 400:
            continue
        ctype = str(flow.response_content_type or "").lower()
        if any(kind in ctype for kind in ("image/", "font/", "css", "javascript")):
            continue
        seen.add(url)
        is_api = "/api" in url.lower() or "json" in ctype
        # API first, then the smallest response: a 2 KB JSON answer costs the
        # target least per request of the things worth measuring.
        ranked.append((0 if is_api else 1, int(flow.response_size or 0), url))
    ranked.sort(key=lambda row: (row[0], row[1]))
    return [url for _api, _size, url in ranked]


async def _say(engagement_id: str, message: str) -> None:
    try:
        from app import events
        await events.emit(engagement_id, events.THOUGHT, message,
                          level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001
        logger.debug("could not report the rate-limit decision")
