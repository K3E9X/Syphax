"""Delete one engagement and everything it produced.

`close` only changes a status: the findings stay, and every cross-engagement
screen keeps mixing them in. The Findings page defaults to "all engagements
(deduped)", so after a second target the operator reads one list describing
two different systems - which is how a stale `.git` finding from yesterday ends
up next to today's scan.

The hard part is not the DELETE, it is missing a table. A partial purge leaves
rows that still surface in those aggregate views, and nothing fails loudly. So
the list of tables lives here, next to the invariant test that reads the
registered schemas and fails if a table with an `engagement_id` column is not
covered.

Two things deliberately survive:

  * `audit_log` - the record that the engagement existed, what was authorised
    and what ran. Destroying it on delete would defeat the point of keeping an
    audit trail for an offensive tool; the deletion is itself audited.
  * `lessons` - cross-engagement memory is aggregated learning about a kind of
    stack, not the engagement's data. It is what makes the next run smarter.

`flows` is global proxy capture, not engagement-scoped, and has its own
endpoint (DELETE /api/proxy/flows).
"""
from __future__ import annotations

import logging
import re
import shutil
from typing import Dict, List

from app import db

logger = logging.getLogger("syphax.engagements.purge")

# Every table holding rows that belong to one engagement. Ordered so children
# go before the row they describe.
ENGAGEMENT_TABLES: List[str] = [
    "events",
    "approvals",
    "chains",
    "validated_findings",
    "coverage",
    "fingerprints",
    "assets",
    "staged_pocs",
    "runs",
    "jobs",
    "llm_usage",
]

# Carries an engagement_id but is kept on purpose. The invariant test reads
# this, so adding a table here is a deliberate, visible decision.
KEPT_ON_PURPOSE: Dict[str, str] = {
    "audit_log": "the record that this engagement existed and what it was "
                 "authorised to do; the deletion is audited too",
    "lessons": "cross-engagement memory is learning about a stack, not this "
               "engagement's data",
}

_TABLE_RE = re.compile(r"CREATE TABLE IF NOT EXISTS (\w+)\s*\((.*?)\n\);", re.S)


def tables_with_engagement_id(schemas: List[str]) -> List[str]:
    """Tables whose CREATE TABLE declares an engagement_id column.

    Read from the registered schemas rather than hardcoded, so a table added
    later cannot quietly escape the purge.
    """
    found = []
    for sql in schemas:
        for name, body in _TABLE_RE.findall(sql or ""):
            if re.search(r"^\s*engagement_id\b", body, re.M):
                found.append(name)
    return sorted(set(found))


def uncovered_tables(schemas: List[str]) -> List[str]:
    """Engagement-scoped tables that neither purge nor deliberately survive."""
    known = set(ENGAGEMENT_TABLES) | set(KEPT_ON_PURPOSE)
    return sorted(t for t in tables_with_engagement_id(schemas) if t not in known)


async def hosts_only_used_by(engagement_id: str, hosts: List[str]) -> List[str]:
    """Of `hosts`, those no other engagement targets.

    Artifacts on disk are keyed by host, not by engagement: the recovered git
    tree and the cached JavaScript live in {data_dir}/artifacts/{host}/. Two
    engagements can share a host, so deleting one must not blind the other.
    """
    if not hosts:
        return []
    async with db.acquire() as conn:
        rows = await conn.fetch(
            "SELECT DISTINCT target_host FROM engagements WHERE id <> $1",
            engagement_id,
        )
    still_used = {(r["target_host"] or "").lower() for r in rows}
    return [h for h in hosts if h and h.lower() not in still_used]


async def purge_engagement(engagement_id: str, *, hosts: List[str] | None = None
                           ) -> Dict[str, int]:
    """Delete the engagement and every row it owns. Returns rows per table."""
    deleted: Dict[str, int] = {}
    async with db.acquire() as conn:
        async with conn.transaction():
            for table in ENGAGEMENT_TABLES:
                try:
                    tag = await conn.execute(
                        f"DELETE FROM {table} WHERE engagement_id = $1", engagement_id)
                except Exception:  # noqa: BLE001 - a table may not exist yet
                    logger.debug("purge: skipped %s", table, exc_info=True)
                    continue
                deleted[table] = int(str(tag).rsplit(" ", 1)[-1] or 0)
            tag = await conn.execute("DELETE FROM engagements WHERE id = $1",
                                     engagement_id)
            deleted["engagements"] = int(str(tag).rsplit(" ", 1)[-1] or 0)

    # On-disk artifacts, only for hosts nothing else is testing.
    removed_dirs = 0
    for host in await hosts_only_used_by(engagement_id, hosts or []):
        from app.scans.artifacts import artifact_dir, GIT, JS
        for kind in (GIT, JS):
            path = artifact_dir(host, kind)
            if path is None or not path.exists():
                continue
            try:
                shutil.rmtree(path)
                removed_dirs += 1
            except OSError:
                logger.debug("purge: could not remove %s", path, exc_info=True)
    deleted["artifact_dirs"] = removed_dirs

    logger.info("[%s] purged: %s", engagement_id,
                ", ".join(f"{k}={v}" for k, v in deleted.items() if v))
    return deleted
