"""What the last run actually did, and where it stopped doing it.

    docker compose exec -T worker python -m app.diagnose_run

Written after five rounds of me inferring causes from source code while the
answer sat in the database. The self-test (app/selftest.py) says what the
INSTALLATION can do; this says what a RUN did with it. Between them there is
no room left for a guess.

Read-only: four SELECTs and no writes.
"""
from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from typing import Any, Dict, List

from app import db

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
            SELECT tool, status, exit_code, catalog_item_id, findings_json
            FROM jobs WHERE engagement_id = $1
        """, eng)
        verdicts = await _rows(conn, """
            SELECT severity, status, vuln_class, tool
            FROM validated_findings WHERE engagement_id = $1
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
                                          "failed": 0})
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
        flag = (" <- ran and found nothing"
                if s["jobs"] and not s["with_findings"] and not s["failed"]
                else " <- FAILED" if s["failed"] else "")
        out.append(f"  {item:24s} {s['jobs']:3d} / {s['with_findings']:3d} / "
                   f"{s['failed']:3d}{flag}")

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
