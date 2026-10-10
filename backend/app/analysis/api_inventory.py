"""Shadow and zombie APIs: OWASP API9, Improper Inventory Management.

API9 is the one item on the API Top 10 that is not a bug in a line of code. It
is an organisational failure with a technical signature: /api/v2 is current,
documented and reviewed, and /api/v1 is still answering on the same host two
years after the team stopped thinking about it. Nobody shipped a vulnerability
into v1; the vulnerability is that v1 never received the three years of
security work v2 did.

Three kinds of thing are hunted here, all of them read-only GETs inside scope:

  * SHADOW versions - a sibling of an observed versioned path that answers.
    /api/v1/users when the application only ever called /api/v2/users, plus
    the named environments that get left exposed: internal, legacy, beta,
    debug, staging.
  * ZOMBIE endpoints - a path that exists in the archive data gau already
    collected but which the current crawl never touched, and which still
    answers. Those are the endpoints a team believes are gone.
  * POSTURE REGRESSIONS - the finding that matters. The current version
    answers 401/403 and the old one answers 200. That is not an inventory
    note, it is an authentication bypass with a version number, and it is
    reported as broken_access_control so the exploit layer can prove it.

What this does NOT do: guess. A candidate is only ever derived from a path the
application itself used or an archive recorded, every probe is one GET, and a
response is only called "live" after the soft-404 check - a host that answers
200 for everything would otherwise manufacture a shadow API per candidate.

Discovered live paths are seeded back as endpoint assets, so the vuln phase
tests the forgotten version with the same catalog the current one gets. That is
the whole point: finding v1 and not scanning it would be a worse outcome than
not finding it, because the report would say the surface was covered.

Stored as a synthetic job (tool="api_inventory").
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.models import Finding
from app.validation.safe_poc import SafePoC

logger = logging.getLogger("syphax.analysis.api_inventory")

MAX_FLOWS = 1000
MAX_PROBES = 60             # total GETs this analyser may send
MAX_CANDIDATES_PER_PATH = 8
MAX_ZOMBIE_PROBES = 20

# A version segment: v1, v2, v10, v1.1, v2beta, 2024-01-01 (date-versioned APIs).
_VERSION = re.compile(r"^(?:v\d+(?:[._]\d+)?[a-z]*|\d{4}-\d{2}-\d{2})$", re.I)

# Named environments that get deployed beside the real one and then forgotten.
# Ordered by how often they are both present and unprotected.
NAMED_SIBLINGS = ("internal", "legacy", "old", "deprecated", "beta", "alpha",
                  "debug", "staging", "dev", "test", "v0", "private", "admin")

# Rate-limit headers. Their presence on the current version and absence on the
# sibling is evidence that the sibling missed the protection, not a finding of
# its own - API4 is tested properly elsewhere.
_RATE_HEADERS = ("x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit",
                 "x-ratelimit-remaining", "retry-after")

_AUTH_STATUS = (401, 403, 407)
_LIVE_STATUS = (200, 201, 202, 204, 206, 405, 500)


def version_siblings(segment: str) -> List[str]:
    """Other versions of this one, nearest first.

    v2 -> v1, v3, v0 ... The neighbours matter more than the extremes: a team
    that ships v3 usually still runs v2, and rarely still runs v1.
    """
    match = re.match(r"^v(\d+)$", segment, re.I)
    if not match:
        return []
    n = int(match.group(1))
    out: List[str] = []
    for delta in (-1, 1, -2, 2, -3):
        other = n + delta
        if other >= 0 and other != n:
            out.append(f"v{other}")
    return out


def candidates_for(url: str) -> List[Tuple[str, str]]:
    """(candidate_url, why) for one observed URL. Pure, sends nothing."""
    parts = urlparse(url)
    segments = (parts.path or "/").split("/")
    out: List[Tuple[str, str]] = []
    seen: Set[str] = set()

    def add(new_segments: List[str], why: str) -> None:
        path = "/".join(new_segments)
        if not path.startswith("/"):
            path = "/" + path
        candidate = urlunparse((parts.scheme, parts.netloc, path, "", "", ""))
        if candidate != url and candidate not in seen:
            seen.add(candidate)
            out.append((candidate, why))

    for index, segment in enumerate(segments):
        if not _VERSION.match(segment or ""):
            continue
        for other in version_siblings(segment):
            replaced = list(segments)
            replaced[index] = other
            add(replaced, f"version sibling of '{segment}'")
        for name in NAMED_SIBLINGS[:6]:
            replaced = list(segments)
            replaced[index] = name
            add(replaced, f"named environment in place of '{segment}'")
        break   # one version segment per path; the first is the API's own

    # A path under /api with no version segment at all: the versions may exist
    # one level in. /api/users -> /api/v1/users, /api/internal/users.
    if not out:
        lowered = [s.lower() for s in segments]
        if "api" in lowered:
            at = lowered.index("api")
            if at + 1 < len(segments) and not _VERSION.match(segments[at + 1] or ""):
                for name in ("v1", "v2", "internal", "debug"):
                    inserted = segments[:at + 1] + [name] + segments[at + 1:]
                    add(inserted, f"undeclared '{name}' tier under /api")

    return out[:MAX_CANDIDATES_PER_PATH]


def is_soft_404(status: int, body: str) -> bool:
    """A 200 that is really "not found". Without this a catch-all host
    manufactures one shadow API per candidate probed."""
    if status not in (200, 201, 202):
        return False
    lowered = (body or "")[:4000].lower()
    for phrase in ("not found", "404", "page introuvable", "does not exist",
                   "no route matched", "cannot get ", "unknown endpoint"):
        if phrase in lowered:
            return True
    return False


def posture_of(status: int, headers: Dict[str, str]) -> Dict[str, object]:
    """How protected a response looks. Compared between versions."""
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    return {
        "status": status,
        "needs_auth": status in _AUTH_STATUS,
        "rate_limited": any(h in lower for h in _RATE_HEADERS),
    }


def regression(current: Dict[str, object], sibling: Dict[str, object]) -> str:
    """What the sibling lost relative to the current version. "" if nothing."""
    losses = []
    if current.get("needs_auth") and not sibling.get("needs_auth"):
        losses.append("authentication")
    if current.get("rate_limited") and not sibling.get("rate_limited"):
        losses.append("rate limiting")
    return ", ".join(losses)


async def analyze_api_inventory(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    observed, archived = await _surface(eng)
    if not observed and not archived:
        await _say(engagement_id,
                   "No in-scope URL to derive API versions from, so the "
                   "shadow/zombie hunt had nothing to work on. Every candidate "
                   "here comes from a path the application itself used or the "
                   "archives recorded - guessing versions on a host we have "
                   "not seen would be sending requests with no hypothesis.")
        return {"observed": 0, "candidates": 0, "live": 0, "findings": 0}

    safe = SafePoC(in_scope=eng.host_in_scope)
    findings: List[Finding] = []
    live_urls: List[str] = []
    probes = 0
    checked: Set[str] = set()

    # ---- shadow versions, measured against the version that is live ----
    for url in observed:
        if probes >= MAX_PROBES:
            break
        pairs = candidates_for(url)
        if not pairs:
            continue
        current = await _probe(safe, url)
        probes += 1
        if current is None:
            continue
        for candidate, why in pairs:
            if probes >= MAX_PROBES:
                break
            if candidate in checked or not eng.url_in_scope(candidate):
                continue
            checked.add(candidate)
            sibling = await _probe(safe, candidate)
            probes += 1
            if sibling is None or not sibling["live"]:
                continue
            live_urls.append(candidate)
            findings.append(_shadow_finding(url, candidate, why,
                                            current, sibling))

    # ---- zombies: in the archives, never in this crawl, still answering ----
    zombie_probes = 0
    for url in archived:
        if probes >= MAX_PROBES or zombie_probes >= MAX_ZOMBIE_PROBES:
            break
        if url in checked or not eng.url_in_scope(url):
            continue
        checked.add(url)
        result = await _probe(safe, url)
        probes += 1
        zombie_probes += 1
        if result is None or not result["live"]:
            continue
        live_urls.append(url)
        findings.append(_zombie_finding(url, result))

    seeded = await _seed(engagement_id, eng, live_urls)
    await save_analysis_job(engagement_id, "api_inventory", findings,
                            target=eng.target_url)
    logger.info("[%s] api_inventory: observed=%d probes=%d live=%d findings=%d seeded=%d",
                engagement_id, len(observed), probes, len(live_urls),
                len(findings), seeded)
    return {"observed": len(observed), "candidates": len(checked),
            "probes": probes, "live": len(live_urls),
            "findings": len(findings), "seeded": seeded}


# ---------------------------------------------------------------------------


async def _surface(eng) -> Tuple[List[str], List[str]]:
    """(paths the application used, paths only the archives know about)."""
    in_crawl: Set[str] = set()
    observed: List[str] = []
    # One representative per OPERATION, not per URL. /api/v2/users/1 and
    # /api/v2/users/2 are the same route, and probing both would spend the
    # whole budget rewriting the same path twice. The probe still uses a
    # concrete URL - a templated one would 404 on the {id}.
    shapes: Set[str] = set()

    def consider(url: str) -> bool:
        base = _strip(url)
        if not base or base in in_crawl:
            return False
        if not eng.host_in_scope((urlparse(base).hostname or "").lower()):
            return False
        in_crawl.add(base)
        shape = _shape(base)
        if shape in shapes:
            return False
        shapes.add(shape)
        observed.append(base)
        return True

    try:
        summaries = await FlowRepository().list_flows(limit=MAX_FLOWS)
    except Exception:  # noqa: BLE001 - no traffic table is not a failure
        summaries = []
    for flow in summaries:
        consider(flow.url)

    # Assets gau/katana produced. The archive-only ones are the zombie leads:
    # a path the team believes is gone, which the Wayback Machine remembers.
    archived: List[str] = []
    try:
        from app.orchestrator.state import EngagementState
        for asset in await EngagementState(eng.id).assets("endpoint"):
            value = _strip(getattr(asset, "value", "") or "")
            if not value or value in in_crawl or value in set(archived):
                continue
            if not eng.host_in_scope((urlparse(value).hostname or "").lower()):
                continue
            source = (getattr(asset, "source", "") or "").lower()
            if source in ("gau", "wayback", "archive"):
                shape = _shape(value)
                if shape not in shapes:
                    shapes.add(shape)
                    archived.append(value)
            else:
                consider(value)
    except Exception:  # noqa: BLE001 - the assets are a bonus, not a requirement
        logger.debug("could not read the endpoint assets")

    # An API path first: a versioned /api route is where this analyser pays.
    observed.sort(key=lambda u: (0 if "/api" in u.lower() else 1, len(u)))
    archived.sort(key=lambda u: (0 if "/api" in u.lower() else 1, len(u)))
    return observed[:200], archived[:120]


def _shape(url: str) -> str:
    """The operation this URL addresses, identifiers folded away.

    Reuses the same templating the synthesised schema uses, so the two agree
    on what counts as one route.
    """
    try:
        from app.analysis.openapi_synth import templated
        parts = urlparse(url)
        return f"{parts.netloc}{templated(parts.path or '/')}"
    except Exception:  # noqa: BLE001 - worst case we probe one path twice
        return url


def _strip(url: str) -> str:
    """The URL without query or fragment. A version sibling is about the path."""
    if not url or "://" not in url:
        return ""
    parts = urlparse(url)
    if not parts.hostname:
        return ""
    return urlunparse((parts.scheme, parts.netloc, parts.path or "/", "", "", ""))


async def _probe(safe: SafePoC, url: str) -> Optional[Dict[str, object]]:
    try:
        resp = await safe.fetch(url)
    except Exception:  # noqa: BLE001 - out of scope / policy refusal
        return None
    if resp is None:
        return None
    posture = posture_of(resp.status_code, resp.headers)
    posture["live"] = (resp.status_code in _LIVE_STATUS
                       and not is_soft_404(resp.status_code, resp.text))
    posture["body_len"] = len(resp.text or "")
    posture["content_type"] = (resp.headers or {}).get("content-type", "")
    return posture


def _shadow_finding(current_url: str, candidate: str, why: str,
                    current: Dict[str, object],
                    sibling: Dict[str, object]) -> Finding:
    lost = regression(current, sibling)
    evidence = (
        f"live version : GET {current_url} -> {current['status']}"
        f"{' (auth required)' if current.get('needs_auth') else ''}\n"
        f"forgotten    : GET {candidate} -> {sibling['status']}"
        f"{' (auth required)' if sibling.get('needs_auth') else ''}\n"
        f"derived as   : {why}\n"
        f"body         : {sibling['body_len']} bytes, "
        f"{sibling['content_type'] or 'no content-type'}"
    )
    if lost:
        return Finding(
            severity="high" if "authentication" in lost else "medium",
            title=f"Forgotten API version answers without {lost}: {candidate}",
            description=(
                f"{candidate} is live and reachable while the version the "
                f"application actually calls ({current_url}) enforces {lost}. "
                f"An old version that kept the route and lost the control is "
                f"an access-control break with a version number: the current "
                f"endpoint's protection can be stepped around by addressing "
                f"the previous one. OWASP API9 (improper inventory) is how it "
                f"gets there; API1/API5 is what it costs."),
            target=candidate,
            evidence=evidence,
            metadata={"tool": "api_inventory",
                      "vuln_class": "broken_access_control",
                      "owasp_api": "API9:2023",
                      "lost_controls": lost,
                      "live_version": current_url,
                      "derivation": why,
                      # Both halves of the comparison are responses we
                      # obtained, so the validator keeps the verdict rather
                      # than re-deriving a weaker one from the severity.
                      "status": "confirmed", "confidence": 0.9},
        )
    return Finding(
        severity="low",
        title=f"Undocumented API version is still live: {candidate}",
        description=(
            f"{candidate} answers {sibling['status']}, and the application "
            f"itself only ever called {current_url}. A version nobody calls "
            f"is a version nobody reviews: it keeps receiving traffic and "
            f"stops receiving security work. Its auth posture currently "
            f"matches the live version, so this is an inventory finding "
            f"rather than a break - it is in the report so the surface is "
            f"known, and it has been added to the scan surface so the rest "
            f"of the methodology tests it too. OWASP API9:2023."),
        target=candidate,
        evidence=evidence,
        metadata={"tool": "api_inventory", "vuln_class": "shadow_api",
                  "owasp_api": "API9:2023", "live_version": current_url,
                  "derivation": why,
                  "status": "confirmed", "confidence": 0.85},
    )


def _zombie_finding(url: str, result: Dict[str, object]) -> Finding:
    api = "/api" in url.lower()
    return Finding(
        severity="medium" if api and not result.get("needs_auth") else "low",
        title=f"Archived endpoint is still answering: {url}",
        description=(
            f"This path exists in the archive data collected for this host but "
            f"the crawl of the current application never reached it - nothing "
            f"links to it any more. It still answers "
            f"{result['status']}. An endpoint that has been removed from the "
            f"application but not from the server is the clearest form of "
            f"OWASP API9: the team's mental model says it is gone, so nothing "
            f"about it is maintained, and no change to the current code "
            f"affects it. It has been added to the scan surface."),
        target=url,
        evidence=(f"GET {url} -> {result['status']}\n"
                  f"not reached by the crawl; present in archive data\n"
                  f"body: {result['body_len']} bytes, "
                  f"{result['content_type'] or 'no content-type'}"
                  + ("\nno authentication required" if not result.get("needs_auth")
                     else "")),
        metadata={"tool": "api_inventory", "vuln_class": "shadow_api",
                  "owasp_api": "API9:2023", "source": "archive",
                  "status": "confirmed", "confidence": 0.85},
    )


async def _say(engagement_id: str, message: str) -> None:
    try:
        from app import events
        await events.emit(engagement_id, events.THOUGHT, message,
                          level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001 - reporting never fails the pass
        logger.debug("could not report the inventory decision")


async def _seed(engagement_id: str, eng, urls: List[str]) -> int:
    """Put every live forgotten endpoint on the scan surface.

    Finding v1 and not scanning it would be worse than not finding it: the
    report would then say the surface was covered while the one version with
    no security work behind it was never tested.
    """
    if not urls:
        return 0
    seeded = 0
    try:
        from app.orchestrator.state import EngagementState
        state = EngagementState(engagement_id)
        for url in urls[:80]:
            if not eng.url_in_scope(url):
                continue
            await state.add_asset("endpoint", url, source="api-inventory")
            seeded += 1
    except Exception:  # noqa: BLE001 - the findings stand without the seeding
        logger.exception("[%s] could not seed forgotten endpoints", engagement_id)
    return seeded
