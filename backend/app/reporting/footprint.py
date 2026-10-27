"""How loud the run was, measured from what is actually knowable.

OWASP GenAI's "LLM Exploit Generation - Phase 2" gives defenders a signature
for an autonomous attacker: "high-frequency, low-diversity tool invocation
against a single target with no advance in target state", a pattern that
"differs from what a skilled human produces". A classic session, by contrast,
"is quiet by construction: one operator, one chat, and a handful of commands
issued at human pace".

syphax is an authorised tool - it sends an X-Pentest-ID attribution header on
purpose and has no business hiding - so this is not about evasion. It answers
two questions worth answering anyway:

  * for the client's report: what footprint did this test leave, and should
    their monitoring have seen it?
  * for the operator: where is the run spending effort that buys nothing?

WHAT IT DOES NOT CLAIM. It does not report "requests sent". Jobs do not record
a request count and the wrappers do not report one uniformly, so any number
here would be invented. Only katana and httpx are routed through the capture
proxy (see scans/identity.CAPTURE_WORTH_IT), so `captured_requests` is a floor
on the true volume and says so. What IS exact is the job ledger: how many
tool invocations went out, against how many distinct targets, and how that
compares to what the run learned.
"""
from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict, List

logger = logging.getLogger("syphax.reporting.footprint")

# Jobs on one target beyond which the pattern starts to look like the
# report's signature rather than like a methodology being worked through.
BUSY_TARGET_JOBS = 8


async def collect(engagement_id: str) -> Dict[str, Any]:
    """The run's footprint. Returns {} when it cannot be measured."""
    try:
        from app import db
        async with db.acquire() as conn:
            jobs = await conn.fetch(
                "SELECT tool, target, "
                "       COALESCE(jsonb_array_length(findings_json::jsonb), 0) AS n "
                "FROM jobs WHERE engagement_id = $1", engagement_id)
            facts = await conn.fetchrow(
                "SELECT (SELECT COUNT(*) FROM assets WHERE engagement_id=$1) AS a,"
                "       (SELECT COUNT(*) FROM leads  WHERE engagement_id=$1) AS l",
                engagement_id)
            captured = await conn.fetchrow(
                "SELECT COUNT(*) AS n FROM flows WHERE host = ANY("
                "  SELECT DISTINCT value FROM assets "
                "  WHERE engagement_id=$1 AND kind='host')", engagement_id)
    except Exception:  # noqa: BLE001 - a footprint is not worth failing a report
        logger.debug("[%s] could not measure the footprint", engagement_id)
        return {}

    if not jobs:
        return {}

    per_target: Counter = Counter()
    tools_per_target: Dict[str, set] = {}
    findings_total = 0
    for row in jobs:
        target = str(row["target"] or "")
        per_target[target] += 1
        tools_per_target.setdefault(target, set()).add(str(row["tool"] or ""))
        findings_total += int(row["n"] or 0)

    assets = int((facts or {}).get("a") or 0)
    leads = int((facts or {}).get("l") or 0)
    learned = assets + leads + findings_total

    busiest = per_target.most_common(1)[0] if per_target else ("", 0)
    noisy = [{"target": t, "jobs": n,
              "tools": sorted(tools_per_target.get(t, ()))}
             for t, n in per_target.most_common(5) if n >= BUSY_TARGET_JOBS]

    return {
        "jobs": len(jobs),
        "targets": len(per_target),
        "jobs_per_target": round(len(jobs) / max(1, len(per_target)), 1),
        "busiest_target": {"target": busiest[0], "jobs": busiest[1],
                           "tools": sorted(tools_per_target.get(busiest[0], ()))},
        "concentrated_on": noisy,
        "learned": {"assets": assets, "findings": findings_total,
                    "leads": leads, "total": learned},
        "jobs_per_fact": round(len(jobs) / learned, 1) if learned else None,
        # A FLOOR, not a total: only the crawl and probe tools are proxied.
        "captured_requests": int((captured or {}).get("n") or 0),
    }


def summarise(fp: Dict[str, Any]) -> List[str]:
    """Plain lines for the report and the diagnosis. Never raises."""
    if not fp:
        return []
    out = [
        f"{fp['jobs']} tool invocation(s) against {fp['targets']} distinct "
        f"target(s), {fp['jobs_per_target']} per target on average.",
    ]
    if fp.get("captured_requests"):
        out.append(
            f"At least {fp['captured_requests']} HTTP request(s) were captured "
            f"in full. That is a floor, not a total: only the crawl and probe "
            f"tools are routed through the proxy, so the scanners' own traffic "
            f"is not counted here.")
    learned = fp.get("learned") or {}
    if fp.get("jobs_per_fact") is not None:
        out.append(
            f"The run learned {learned.get('total', 0)} fact(s) "
            f"({learned.get('assets', 0)} asset(s), "
            f"{learned.get('findings', 0)} finding(s), "
            f"{learned.get('leads', 0)} lead(s)) - "
            f"{fp['jobs_per_fact']} invocation(s) per fact.")
    for row in fp.get("concentrated_on") or []:
        out.append(
            f"{row['target']} took {row['jobs']} invocation(s) "
            f"({', '.join(row['tools'])}). Concentrated, repetitive activity "
            f"against one target is the pattern defenders are told to look "
            f"for, so expect monitoring to have seen this one.")
    return out
