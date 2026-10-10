"""What the last run actually did, and where it stopped doing it.

    docker compose exec -T worker python -m app.diagnose_run

Written after five rounds of me inferring causes from source code while the
answer sat in the database. The self-test (app/selftest.py) says what the
INSTALLATION can do; this says what a RUN did with it. Between them there is
no room left for a guess.

Read-only: five SELECTs and no writes.
"""
from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from typing import Any, Dict, List

from app import db
from app.analysis import ANALYSER_TOOLS

# Catalog item ids are prefixed by phase, so the prefix says how far the run
# got without needing to join anything.
PHASE_OF_PREFIX = {
    "RECON": "recon",
    "MAP": "mapping",
    "VULN": "vuln_analysis",
    "EXP": "exploitation",
}
PHASE_ORDER = ["recon", "mapping", "vuln_analysis", "exploitation"]


def _phase_of(item_id: str) -> str:
    return PHASE_OF_PREFIX.get(str(item_id or "").split("-", 1)[0], "other")


async def _rows(conn, sql: str, *args) -> List[Dict[str, Any]]:
    return [dict(r) for r in await conn.fetch(sql, *args)]


async def run() -> int:
    await db.init_db()
    out: List[str] = ["syphax run diagnosis", "=" * 68]

    async with db.acquire() as conn:
        runs = await _rows(conn, """
            SELECT id, engagement_id, status, phase, stop_reason,
                   jobs_launched, iterations, error
            FROM runs ORDER BY created_at DESC LIMIT 1
        """)
        if not runs:
            print("No run has ever been recorded. Start an engagement first.")
            return 1
        run_row = runs[0]
        eng = run_row["engagement_id"]

        jobs = await _rows(conn, """
            SELECT tool, status, exit_code, catalog_item_id, findings_json, error
            FROM jobs WHERE engagement_id = $1
        """, eng)
        verdicts = await _rows(conn, """
            SELECT severity, status, vuln_class, tool
            FROM validated_findings WHERE engagement_id = $1
        """, eng)
        # What the analysers said about themselves. Every one of them emits a
        # THOUGHT when it declines - "not tested: it needs active
        # exploitation", "no captured traffic to build a schema from" - and
        # that sentence is the answer to "why did this find nothing", which
        # the diagnosis could not previously reach.
        thoughts = await _rows(conn, """
            SELECT message FROM events
            WHERE engagement_id = $1 AND type = 'agent_thought'
            ORDER BY ts DESC LIMIT 25
        """, eng)

    # ---- the run itself ---------------------------------------------------
    out.append("")
    out.append(f"LAST RUN   {run_row['id']}  engagement={eng}")
    out.append(f"  status       {run_row['status']}")
    out.append(f"  last phase   {run_row['phase']}")
    out.append(f"  ended as     {run_row['stop_reason'] or '(not recorded)'}")
    out.append(f"  jobs/iters   {run_row['jobs_launched']} jobs, "
               f"{run_row['iterations']} planning rounds")
    if run_row.get("error"):
        out.append(f"  error        {str(run_row['error'])[:200]}")

    # ---- how far the plan got --------------------------------------------
    by_phase: Counter = Counter()
    per_item: Dict[str, Dict[str, int]] = {}
    for job in jobs:
        item = job["catalog_item_id"]
        if not item:
            continue
        by_phase[_phase_of(item)] += 1
        slot = per_item.setdefault(item, {"jobs": 0, "with_findings": 0,
                                          "failed": 0, "skipped": 0})
        slot["jobs"] += 1
        raw = job["findings_json"]
        try:
            n = len(json.loads(raw)) if raw else 0
        except (TypeError, ValueError):
            n = 0
        if n:
            slot["with_findings"] += 1
        if str(job["status"]).lower() in ("failed", "error") or \
                (job["exit_code"] not in (0, None)):
            slot["failed"] += 1
        if str(job.get("error") or "").startswith("not run:"):
            slot["skipped"] = slot.get("skipped", 0) + 1

    out.append("")
    out.append("PHASES REACHED   tasks planned per phase")
    for phase in PHASE_ORDER:
        count = by_phase.get(phase, 0)
        mark = "  ok  " if count else " NONE "
        out.append(f"[{mark}] {phase:16s} {count} task(s)")
    if by_phase.get("other"):
        out.append(f"[      ] other            {by_phase['other']} task(s)")

    out.append("")
    out.append("PER CATALOG ITEM   jobs / produced findings / non-zero exit")
    for item in sorted(per_item):
        s = per_item[item]
        flag = (f" <- {s['skipped']} not run (nothing to work on)"
                if s.get("skipped")
                else " <- ran and found nothing"
                if s["jobs"] and not s["with_findings"] and not s["failed"]
                else " <- FAILED" if s["failed"] else "")
        out.append(f"  {item:24s} {s['jobs']:3d} / {s['with_findings']:3d} / "
                   f"{s['failed']:3d}{flag}")

    # ---- the traffic-driven half ------------------------------------------
    #
    # An analyser's job carries no catalog_item_id, so none of them appeared
    # in the section above: nineteen analysers - every API check, the JWT
    # pass, access control, the JavaScript mining - could each produce nothing
    # and the diagnosis would not mention them. That is most of what a run
    # does on an application.
    analyser_jobs: Dict[str, Dict[str, int]] = {}
    for job in jobs:
        if job["catalog_item_id"]:
            continue
        tool = str(job["tool"] or "?")
        slot = analyser_jobs.setdefault(tool, {"jobs": 0, "findings": 0})
        slot["jobs"] += 1
        raw = job["findings_json"]
        try:
            slot["findings"] += len(json.loads(raw)) if raw else 0
        except (TypeError, ValueError):
            pass

    out.append("")
    out.append("ANALYSERS   traffic-driven checks: ran? / findings")
    never_ran = []
    for tool in ANALYSER_TOOLS:
        slot = analyser_jobs.get(tool)
        if slot is None:
            never_ran.append(tool)
            continue
        flag = "" if slot["findings"] else "  <- ran, found nothing"
        out.append(f"  {tool:20s} {'yes':4s} / {slot['findings']:3d}{flag}")
    for tool in sorted(set(analyser_jobs) - set(ANALYSER_TOOLS)):
        slot = analyser_jobs[tool]
        out.append(f"  {tool:20s} {'yes':4s} / {slot['findings']:3d}  <- not in "
                   f"ANALYSER_TOOLS")
    if never_ran:
        out.append(f"  never ran: {', '.join(never_ran)}")
        out.append("    An analyser that never ran stored no job at all - it")
        out.append("    was skipped before it got that far, or the run ended")
        out.append("    before finalisation. The reasons are below.")

    if thoughts:
        out.append("")
        out.append("WHAT THE ANALYSERS SAID   most recent first")
        for row in thoughts[:12]:
            message = " ".join(str(row["message"] or "").split())
            out.append(f"  - {message[:160]}")

    # ---- what came out ----------------------------------------------------
    out.append("")
    out.append("VALIDATED FINDINGS   severity x status")
    if not verdicts:
        out.append("  (none)")
    else:
        grid: Counter = Counter()
        for v in verdicts:
            grid[(str(v["severity"] or "?"), str(v["status"] or "?"))] += 1
        for (sev, status), n in sorted(grid.items()):
            out.append(f"  {sev:10s} {status:16s} {n}")

    # ---- the verdict ------------------------------------------------------
    out.append("")
    out.append("=" * 68)

    # A run that is still going has not failed to reach anything yet, and
    # saying "it never planned an exploitation task" about one that is three
    # minutes into recon is worse than saying nothing: it reads as a verdict.
    if str(run_row["status"]).lower() in ("running", "queued"):
        out.append(f"This run is STILL {run_row['status'].upper()} - currently "
                   f"in '{run_row['phase']}', {run_row['jobs_launched']} job(s) "
                   f"launched.")
        out.append("  The phases below it have not been skipped, they have not")
        out.append("  been reached YET. Re-run this once the run finishes for a")
        out.append("  verdict; what is already worth acting on is any item above")
        out.append("  marked FAILED - a tool that errors now will error later.")
        print("\n".join(out))
        try:
            await db.close_pool()
        except Exception:  # noqa: BLE001
            pass
        return 0

    reached = [p for p in PHASE_ORDER if by_phase.get(p)]
    missing = [p for p in PHASE_ORDER if not by_phase.get(p)]
    if "exploitation" not in reached:
        out.append("DIAGNOSIS: the run never planned an exploitation task.")
        out.append(f"  It reached: {', '.join(reached) or 'nothing'}.")
        out.append(f"  It never reached: {', '.join(missing)}.")
        out.append("  Nothing downstream of the planner can matter until this")
        out.append("  changes - no injection test, CVE check, PoC or authored")
        out.append(f"  payload was ever planned. Ended as "
                   f"'{run_row['stop_reason'] or 'unknown'}'; if that is a")
        out.append("  budget, raise budget_requests on the engagement.")
    else:
        silent = [i for i, s in sorted(per_item.items())
                  if s["jobs"] and not s["with_findings"] and not s["failed"]]
        failed = [i for i, s in sorted(per_item.items()) if s["failed"]]
        out.append("DIAGNOSIS: every phase was planned, so the planner is not")
        out.append("  the limit any more.")
        if failed:
            out.append(f"  {len(failed)} item(s) exited non-zero: "
                       f"{', '.join(failed[:8])}")
            out.append("  Those are tool or argument failures - look there first.")
        if silent:
            out.append(f"  {len(silent)} item(s) ran cleanly and produced no")
            out.append(f"  finding: {', '.join(silent[:8])}")
            out.append("  If one of those is a scanner you expect to fire on")
            out.append("  this target, its output parser is the next suspect.")
        if not failed and not silent:
            out.append("  Every item produced something; the question is then")
            out.append("  severity and validation, in the grid above.")
    print("\n".join(out))

    try:
        await db.close_pool()
    except Exception:  # noqa: BLE001
        pass
    return 0


def main() -> int:
    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
