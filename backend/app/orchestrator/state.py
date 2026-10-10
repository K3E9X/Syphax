"""Engagement state / memory (spec §4.2).

The shared brain the agents read and write across a run:

  * assets        - discovered hosts / endpoints / params (the attack surface)
  * fingerprints  - technologies seen (server, framework, CMS, language)
  * coverage      - which catalog item ran against which asset, and its status

Findings live on jobs (jobs.engagement_id links them here); the orchestrator
aggregates them rather than duplicating storage.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app import db

logger = logging.getLogger("syphax.orchestrator.state")

# How many PARAM-LESS endpoints may become scan targets for one engagement.
# Endpoints with query parameters are never capped: they are injection points,
# and seven catalog items apply only to an endpoint that has them.
MAX_ENDPOINT_ASSETS = 300

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS assets (
    id            BIGSERIAL PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    kind          TEXT NOT NULL,          -- host | endpoint
    value         TEXT NOT NULL,          -- hostname or full URL
    has_params    BOOLEAN NOT NULL DEFAULT FALSE,
    is_https      BOOLEAN NOT NULL DEFAULT FALSE,
    source        TEXT,                   -- tool/catalog item that found it
    created_at    DOUBLE PRECISION NOT NULL,
    UNIQUE (engagement_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_assets_engagement ON assets(engagement_id);

CREATE TABLE IF NOT EXISTS fingerprints (
    id            BIGSERIAL PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    technology    TEXT NOT NULL,
    source        TEXT,
    created_at    DOUBLE PRECISION NOT NULL,
    UNIQUE (engagement_id, technology)
);
CREATE INDEX IF NOT EXISTS idx_fp_engagement ON fingerprints(engagement_id);

CREATE TABLE IF NOT EXISTS coverage (
    id              BIGSERIAL PRIMARY KEY,
    engagement_id   TEXT NOT NULL,
    catalog_item_id TEXT NOT NULL,
    asset_value     TEXT NOT NULL,
    status          TEXT NOT NULL,        -- pending | running | done | skipped | error
    job_id          TEXT,
    updated_at      DOUBLE PRECISION NOT NULL,
    UNIQUE (engagement_id, catalog_item_id, asset_value)
);
CREATE INDEX IF NOT EXISTS idx_cov_engagement ON coverage(engagement_id);
"""

db.register_schema(SCHEMA_SQL)

# A coverage row counts as "covered" (don't re-plan it) once we have ATTEMPTED
# it - including terminal failures. This is critical: the planner advances one
# phase at a time, so if 'skipped' (tool missing) or 'error' (tool exited non-
# zero - common for scanners that return non-zero when they find nothing) did
# NOT count as covered, a single stuck recon task would stay an "uncovered"
# candidate forever, pinning earliest_phase=recon and starving mapping / vuln /
# exploitation. One attempt per (item, asset) per run; re-run the engagement to
# retry. Every status the executor writes therefore means "attempted".
COVERED_STATUSES = frozenset({"pending", "running", "done", "skipped", "error"})


def status_is_covered(status: Optional[str]) -> bool:
    """Whether a coverage status means the (item, asset) was already attempted
    and must not be re-planned this run."""
    return status in COVERED_STATUSES



@dataclass
class Asset:
    kind: str           # host | endpoint
    value: str
    has_params: bool = False
    is_https: bool = False
    source: Optional[str] = None

    def context(self, tech: List[str]) -> Dict[str, Any]:
        """Build the dict consumed by methodology.applies()."""
        return {
            "is_host": self.kind == "host",
            "is_https": self.is_https,
            "requires_params": self.has_params,
            "url": self.value,
            "source": self.source or "",
            "tech": tech,
        }


class EngagementState:
    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id

    # ----- assets -----
    async def add_asset(
        self,
        kind: str,
        value: str,
        *,
        source: Optional[str] = None,
    ) -> None:
        from urllib.parse import parse_qs
        has_params = bool(parse_qs(urlparse(value).query))
        is_https = value.startswith("https://")
        if kind == "host" and "://" in value:
            value = urlparse(value).hostname or value

        # A ceiling on scan targets, as a structural guard rather than a tuning
        # knob. The planner builds one task per (catalog item x asset), so the
        # asset count multiplies everything downstream: a single gau run that
        # turned 2162 archived URLs into assets made a run exhaust its TIME
        # budget at iteration 8, having launched 62 jobs and tested nothing.
        #
        # gau no longer does that (see wrappers/gau.py), but the next tool that
        # discovers a lot of URLs would, so the limit lives here where it
        # covers all of them. A parameterised endpoint is always admitted: it
        # is an injection point, and it is what the param-gated catalog items
        # need to exist at all.
        if kind == "endpoint" and not has_params:
            if await self._endpoint_count() >= MAX_ENDPOINT_ASSETS:
                await self._say_capped(value, source)
                return

        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO assets (engagement_id, kind, value, has_params, is_https, source, created_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7)
                ON CONFLICT (engagement_id, kind, value) DO NOTHING
                """,
                self.engagement_id, kind, value, has_params, is_https, source, time.time(),
            )

    async def _endpoint_count(self) -> int:
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COUNT(*) AS n FROM assets "
                "WHERE engagement_id=$1 AND kind='endpoint' AND has_params=FALSE",
                self.engagement_id)
        return int(row["n"]) if row else 0

    async def _say_capped(self, value: str, source: Optional[str]) -> None:
        """Say it once per run, not once per discarded URL."""
        if getattr(self, "_capped_reported", False):
            return
        self._capped_reported = True
        try:
            from app import events
            await events.emit(
                self.engagement_id, events.THOUGHT,
                f"Reached the ceiling of {MAX_ENDPOINT_ASSETS} param-less "
                f"endpoints to scan; further ones (from {source or 'a tool'}) "
                f"are recorded as findings but not queued as targets. Endpoints "
                f"WITH parameters are still admitted - those are the injection "
                f"points. Raise it only if the budget can afford it: every "
                f"asset multiplies the task count.",
                level=events.LEVEL_INFO)
        except Exception:  # noqa: BLE001 - never fail an ingest on reporting
            logger.debug("could not report the asset ceiling")

    async def assets(self, kind: Optional[str] = None) -> List[Asset]:
        async with db.acquire() as conn:
            if kind:
                rows = await conn.fetch(
                    "SELECT * FROM assets WHERE engagement_id=$1 AND kind=$2 ORDER BY id",
                    self.engagement_id, kind,
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM assets WHERE engagement_id=$1 ORDER BY id",
                    self.engagement_id,
                )
        return [
            Asset(
                kind=r["kind"], value=r["value"], has_params=r["has_params"],
                is_https=r["is_https"], source=r["source"],
            )
            for r in rows
        ]

    # ----- fingerprints -----
    async def add_fingerprint(self, technology: str, *, source: Optional[str] = None) -> None:
        tech = technology.strip().lower()
        if not tech:
            return
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO fingerprints (engagement_id, technology, source, created_at)
                VALUES ($1,$2,$3,$4)
                ON CONFLICT (engagement_id, technology) DO NOTHING
                """,
                self.engagement_id, tech, source, time.time(),
            )

    async def technologies(self) -> List[str]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT technology FROM fingerprints WHERE engagement_id=$1", self.engagement_id
            )
        return [r["technology"] for r in rows]

    # ----- coverage -----
    async def mark_coverage(
        self,
        catalog_item_id: str,
        asset_value: str,
        status: str,
        *,
        job_id: Optional[str] = None,
    ) -> None:
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO coverage (engagement_id, catalog_item_id, asset_value, status, job_id, updated_at)
                VALUES ($1,$2,$3,$4,$5,$6)
                ON CONFLICT (engagement_id, catalog_item_id, asset_value)
                DO UPDATE SET status=EXCLUDED.status, job_id=EXCLUDED.job_id, updated_at=EXCLUDED.updated_at
                """,
                self.engagement_id, catalog_item_id, asset_value, status, job_id, time.time(),
            )

    async def is_covered(self, catalog_item_id: str, asset_value: str) -> bool:
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT status FROM coverage WHERE engagement_id=$1 AND catalog_item_id=$2 AND asset_value=$3",
                self.engagement_id, catalog_item_id, asset_value,
            )
        # Any attempted status counts as covered (see COVERED_STATUSES) so a
        # skipped/errored task can't pin the planner on an early phase.
        return row is not None and status_is_covered(row["status"])

    async def coverage_rows(self) -> List[Dict[str, Any]]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT catalog_item_id, asset_value, status, job_id, updated_at "
                "FROM coverage WHERE engagement_id=$1 ORDER BY updated_at DESC",
                self.engagement_id,
            )
        return [dict(r) for r in rows]

    async def coverage_summary(self) -> Dict[str, int]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT status, COUNT(*) AS n FROM coverage WHERE engagement_id=$1 GROUP BY status",
                self.engagement_id,
            )
        return {r["status"]: int(r["n"]) for r in rows}
