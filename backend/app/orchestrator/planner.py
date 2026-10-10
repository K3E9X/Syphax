"""Planner agent (spec §4.1).

Given the engagement state, decide the next batch of tasks: which catalog
items to run against which assets, in what order. The planner is
deterministic-first (methodology engine), with an optional LLM re-ordering
pass that is strictly constrained to the candidate tasks it is given - it can
reorder and drop, never invent. If no planner LLM is configured or its reply
doesn't parse, we keep the deterministic order. That guarantees the loop
always makes progress, with or without a model.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from app import events
from app.llm import ROLE_PLANNER, LLMError, get_router
from app.methodology import CATALOG, CATALOG_BY_ID, PHASE_ORDER, applies
from app.orchestrator.state import Asset, EngagementState
from urllib.parse import urlparse

logger = logging.getLogger("syphax.orchestrator.planner")

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Task:
    catalog_item_id: str
    asset_value: str
    tool: str
    options: List[str]
    phase: str
    # Where the asset came from. "engagement" is the operator's own target,
    # which outranks everything inferred from it when the budget is spent.
    asset_source: str = ""

    @property
    def key(self) -> str:
        return f"{self.catalog_item_id}@{self.asset_value}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "catalog_item_id": self.catalog_item_id,
            "asset_value": self.asset_value,
            "tool": self.tool,
            "options": self.options,
            "phase": self.phase,
            "key": self.key,
        }


class Planner:
    def __init__(self, state: EngagementState) -> None:
        self.state = state
        # Said once per run, not once per iteration: the loop re-plans every
        # cycle and a per-iteration notice would bury the console.
        self._degradation_reported = False

    async def _report_degraded(self, reason: str) -> None:
        """Say out loud that planning fell back to the deterministic order.

        The fallback is deliberate - a planner that cannot answer must not stop
        a run - but it used to be invisible: `if not client.configured: return`
        with no log at all, and a logger.warning that only reached the
        container's stderr. The operator saw a normal-looking run and had no
        way to know the LLM never participated, short of noticing a zero in the
        token panel.
        """
        if self._degradation_reported:
            return
        self._degradation_reported = True
        logger.info("[%s] planner degraded: %s", self.state.engagement_id, reason)
        try:
            await events.emit(
                self.state.engagement_id, events.THOUGHT,
                f"Planner LLM not used ({reason}). Tests run in catalog order - "
                "the run continues, it is just not being prioritised.",
                level=events.LEVEL_INFO,
            )
        except Exception:  # noqa: BLE001 - telling the operator must never break planning
            logger.debug("could not emit the planner degradation notice", exc_info=True)

    async def plan(self, *, max_tasks: int = 12, use_llm: bool = True,
                   skip_phases: Optional[Set[str]] = None) -> List[Task]:
        """Return the next batch of uncovered, applicable tasks.

        `skip_phases` are phases that have spent their share of the run's job
        budget. Without it the earliest phase with ANY uncovered work wins
        forever, and the mapping phase can always produce more work than the
        budget allows - so the run never reaches vuln_analysis or exploitation.
        See the comment on `earliest_phase` below.
        """
        assets = await self.state.assets()
        tech = await self.state.technologies()

        # Enough to fill several batches of the earliest phase that has work,
        # with room for the LLM re-ordering pass to choose from.
        skip = {str(p) for p in (skip_phases or set())}
        candidates = await self._candidate_tasks(
            assets, tech, enough=max(max_tasks * 20, 200), skip_phases=skip)
        if not candidates:
            return []

        # Deterministic order: phase first, then severity of the catalog item.
        candidates.sort(key=_task_sort_key)

        # Cross-engagement memory: classes that held up on this stack before go
        # first within their phase. Advisory only - it reorders, it never adds a
        # task, drops one, or touches a gate.
        try:
            from app import memory
            remembered = memory.suggested_classes(await memory.all_lessons(), tech)
            if remembered:
                candidates.sort(key=lambda t: _memory_rank(t, remembered))
        except Exception:  # noqa: BLE001 - memory must never block planning
            logger.debug("memory unavailable for prioritisation", exc_info=True)

        # Only advance one phase at a time: take the earliest phase that still
        # has uncovered work, so we always recon/map before we exploit.
        #
        # "Earliest phase with ANY uncovered work" is a trap on its own, and it
        # is the reason a run on a real site found recon results and nothing
        # else. Mapping items applied to every endpoint asset, and the mapping
        # tools (katana, gau, ffuf) CREATE endpoint assets - so mapping
        # produced work faster than the budget could absorb it: 40 discovered
        # endpoints were 200 mapping tasks, which is the whole default job
        # budget, before a single vuln_analysis task existed. The run ended
        # inside mapping every time, so no injection test, no CVE check, no
        # exploitation and no authored PoC was ever planned - and every finding
        # was therefore recon-grade and "info".
        #
        # Two things fixed it. The per-host mapping items (whatweb, wafw00f,
        # katana, ffuf) are `is_base` now, so they run once instead of once per
        # page they themselves discovered. And `skip_phases` lets the caller cap
        # each phase's share of the budget, which is what makes reaching
        # exploitation a guarantee rather than a hope.
        # Already filtered in _candidate_tasks; kept as a guard.
        remaining = [t for t in candidates if t.phase not in skip]
        if not remaining:
            return []
        earliest_phase = remaining[0].phase
        batch = [t for t in remaining if t.phase == earliest_phase][:max_tasks]

        if use_llm:
            batch = await self._llm_reorder(batch, tech)

        return batch

    async def _candidate_tasks(self, assets: List[Asset], tech: List[str],
                               *, enough: int = 0,
                               skip_phases: Optional[Set[str]] = None) -> List[Task]:
        """Applicable, uncovered (item, asset) pairs.

        This is O(catalog x assets) and runs EVERY planning round. That was
        harmless while the asset ceiling was a few hundred; now that a large
        application keeps its whole surface - which is the point - it is not:
        5000 assets against 40 catalog items is 200000 pairs built and thrown
        away per round, 150 rounds per run.

        So the assets are visited best-first (asset_interest, the same ranking
        the final sort uses) and the walk stops once `enough` candidates exist.
        Stopping early is safe BECAUSE the order is right: what is left behind
        is always less promising than what was taken. It also makes the limit
        self-correcting - the next round re-ranks against whatever the last one
        covered.
        """
        assets = sorted(
            assets,
            key=lambda a: (asset_interest(a.value, source=a.source or ""),
                           a.value))
        skip = {str(p) for p in (skip_phases or set())}
        tasks: List[Task] = []
        for item in CATALOG:
            # Phases that have spent their share are skipped HERE, not after
            # the fact: with an early exit, building candidates for a phase
            # that will be discarded can use up the whole allowance and leave
            # the run with nothing to plan at all.
            if item.phase in skip:
                continue
            if enough and len(tasks) >= enough:
                break
            for asset in assets:
                # "port" assets are surface data for the UI (host:port + service),
                # not scannable targets: their value is "80/tcp . host . svc", and
                # feeding that to a tool parses the host as the port number and the
                # whole task is blocked out of scope. The host they belong to is
                # already an asset in its own right.
                if asset.kind == "port":
                    continue
                # A stylesheet, font or image has no parameters and no server
                # behaviour to attack: pointing dalfox/sqlmap/nuclei-dast at
                # /static/assets/index-Dn2E.css burned a job per file and
                # reported CSS colour codes as "extracted results".
                if asset.kind == "endpoint" and _is_static_asset(asset.value):
                    continue
                ctx = asset.context(tech)
                # Match the asset kind to the item's expectation.
                wants_host = bool(item.applies_when.get("is_host"))
                if wants_host and asset.kind != "host":
                    continue
                if not wants_host and asset.kind == "host":
                    # Non-host items run on endpoint assets (the base URL covers
                    # the host). Running them on a bare hostname would feed a
                    # scheme-less target to URL tools and duplicate coverage with
                    # the base-URL endpoint - skip.
                    continue
                if not applies(item, ctx):
                    continue
                if await self.state.is_covered(item.id, asset.value):
                    continue
                tasks.append(
                    Task(
                        catalog_item_id=item.id,
                        asset_value=asset.value,
                        asset_source=asset.source or "",
                        tool=item.tool,
                        options=list(item.default_options),
                        phase=item.phase,
                    )
                )
        return tasks

    async def _llm_reorder(self, batch: List[Task], tech: List[str]) -> List[Task]:
        if len(batch) <= 1:
            return batch
        client = get_router().get(ROLE_PLANNER)
        if not client.configured:
            await self._report_degraded("no API key or model configured for the "
                                        "planner role")
            return batch

        by_key = {t.key: t for t in batch}
        catalog_brief = {
            t.catalog_item_id: {
                "wstg": CATALOG_BY_ID[t.catalog_item_id].wstg_id,
                "vuln_class": CATALOG_BY_ID[t.catalog_item_id].vuln_class,
                "severity": CATALOG_BY_ID[t.catalog_item_id].severity_default,
            }
            for t in batch if t.catalog_item_id in CATALOG_BY_ID
        }
        asset_values = sorted({t.asset_value for t in batch})
        payload = {
            "technologies": tech,
            "candidate_tasks": [
                {"key": t.key, "tool": t.tool, "catalog_item": t.catalog_item_id,
                 "asset": t.asset_value, "phase": t.phase}
                for t in batch
            ],
            "catalog": catalog_brief,
            "assets": asset_values,
            "phase": batch[0].phase,
        }
        system = (
            "You are the planner of a web-app pentest. Given candidate tasks for "
            "the current phase, (1) reorder them by likely impact and drop clearly "
            "redundant ones, and (2) when the technologies suggest specific known "
            "vulnerabilities, propose targeted nuclei tag-hunts. Use ONLY the "
            "provided task keys and asset values; never invent tasks, tools or "
            "targets. Reply JSON only: {\"ordered_keys\":[...],\"extra_hunts\":"
            "[{\"asset\":\"<one of assets>\",\"tags\":[\"jira\",\"cve\"]}],"
            "\"rationale\":\"short\"}. extra_hunts may be empty."
        )
        try:
            reply = await client.chat(
                [
                    {"role": "system", "content": system},
                    {"role": "user", "content": json.dumps(payload)},
                ],
                temperature=0.1,
                max_tokens=900,
            )
        except LLMError as exc:
            await self._report_degraded(f"provider unavailable: {exc}")
            return batch
        except Exception as exc:  # noqa: BLE001 - never let reordering break planning
            await self._report_degraded(f"planner error: {exc}")
            return batch

        from app.llm.grounding import extract_json
        from app.orchestrator.hypothesis import build_hunt_tasks
        parsed = extract_json(reply)
        ordered = _ordered_keys_from(parsed)

        # Rebuild using only known keys, preserving the model's order, then
        # append any keys it dropped (we never silently lose coverage work).
        seen = set()
        result: List[Task] = []
        for k in ordered:
            t = by_key.get(k)
            if t and k not in seen:
                result.append(t)
                seen.add(k)
        for t in batch:
            if t.key not in seen:
                result.append(t)

        # Targeted nuclei hunts proposed from the fingerprints (grounded: real
        # assets only, sanitized tags). Prepend - they are high-value moves.
        hunts = build_hunt_tasks(parsed, asset_values, batch[0].phase, task_cls=Task)
        fresh: List[Task] = []
        for h in hunts:
            if any(h.key == t.key for t in result):
                continue
            if await self.state.is_covered(h.catalog_item_id, h.asset_value):
                continue
            fresh.append(h)
        return fresh + result


def _memory_rank(task: Task, remembered: List[str]):
    """Stable key that lifts remembered classes without crossing phases.

    Phase order is an invariant the approval checkpoint depends on (loop.py
    gates on batch[0].phase), so memory may only reorder inside a phase.
    """
    item = CATALOG_BY_ID.get(task.catalog_item_id)
    vuln_class = (item.vuln_class if item else "").lower()
    try:
        rank = remembered.index(vuln_class)
    except ValueError:
        rank = len(remembered)
    phase_idx = PHASE_ORDER.index(task.phase) if task.phase in PHASE_ORDER else 99
    return (phase_idx, rank) + _task_sort_key(task)[1:]


# Paths worth spending a job on before anything else. Ordered: the earlier a
# marker appears, the more interesting the asset.
_INTERESTING_PATH = (
    "admin", "login", "signin", "auth", "oauth", "token", "session",
    "account", "user", "profile", "password", "reset", "register",
    "api", "graphql", "rest", "v1", "v2", "rpc",
    "upload", "import", "export", "file", "download", "attachment",
    "search", "query", "filter", "report", "invoice", "order", "payment",
    "config", "setting", "debug", "status", "health", "actuator", "console",
    "backup", "db", "sql", "dump", "log",
)

# Paths that are almost never worth a job: archive noise and generated assets.
_DULL_PATH = ("/img/", "/image", "/css/", "/js/", "/font", "/static/",
              "/assets/", "/vendor/", "/node_modules/", "/dist/",
              "/wp-content/uploads/", "/media/", "/thumb")


def asset_interest(url: str, *, source: str = "") -> int:
    """How promising this target is. Lower is better; used to ORDER the budget.

    This is the half of the volume problem that capping does not solve. The
    planner took assets in insertion order (`ORDER BY id`), so on a target
    whose surface came from an archive, the exploitation phase spent its share
    on the first sixty URLs gau happened to return - archived .jsp pages -
    while /bank/login.jsp sat untested further down the list. Bounding the
    number of assets limits the damage; ordering them is what makes the budget
    buy something.

    Pure, so the ranking is testable without a database.
    """
    value = (url or "").lower()
    try:
        parsed = urlparse(value)
        path = parsed.path or "/"
        query = parsed.query
    except ValueError:
        path, query = value, ""

    # The engagement's own target first: it is the one host we are certain
    # matters, and everything else was inferred from it.
    if source == "engagement":
        return 0
    # Then anything carrying parameters - an injection point, and what the
    # seven param-gated catalog items need to exist at all.
    if query:
        return 1
    for marker in _DULL_PATH:
        if marker in path:
            return 90
    for rank, marker in enumerate(_INTERESTING_PATH):
        if marker in path:
            # 10..69, preserving the order of the table above.
            return 10 + min(rank, 59)
    # A short path is more likely to be a real entry point than a deep one.
    depth = path.count("/")
    return 70 + min(depth, 19)


def _task_sort_key(t: Task):
    phase_idx = PHASE_ORDER.index(t.phase) if t.phase in PHASE_ORDER else 99
    item = CATALOG_BY_ID.get(t.catalog_item_id)
    sev = _SEVERITY_RANK.get(item.severity_default if item else "info", 4)
    # Asset interest comes BEFORE the catalog item's severity, deliberately.
    # A job slot is spent on one (item, asset) pair, and a mediocre asset
    # wastes the slot whichever tool runs on it - so it is better to run every
    # applicable test against the best targets than one test against all of
    # them. This is what decides where a capped budget actually goes.
    return (phase_idx, asset_interest(t.asset_value, source=t.asset_source),
            sev, t.catalog_item_id, t.asset_value)


def _ordered_keys_from(parsed) -> List[str]:
    """Extract ordered_keys from already-decoded planner JSON."""
    if not isinstance(parsed, dict):
        return []
    keys = parsed.get("ordered_keys")
    return [str(k) for k in keys] if isinstance(keys, list) else []


def _parse_ordered_keys(reply: str) -> List[str]:
    text = reply.strip()
    if text.startswith("```"):
        text = text.strip("`")
        parts = text.split("\n", 1)
        if len(parts) == 2 and len(parts[0]) <= 10:
            text = parts[1]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            return []
        try:
            obj = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return []
    keys = obj.get("ordered_keys") if isinstance(obj, dict) else None
    return [str(k) for k in keys] if isinstance(keys, list) else []


# Extensions that are served as-is and carry no injectable surface. ".js" is
# deliberately NOT here: the JS tools read it, and a crawler still learns from
# it. ".map" is, because a source map is data, not an endpoint.
_STATIC_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
               ".avif", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".eot",
               ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".map")


def _is_static_asset(url: str) -> bool:
    """Is this endpoint a static file with nothing to test?"""
    from urllib.parse import urlparse
    try:
        path = (urlparse(url or "").path or "").lower()
    except ValueError:
        return False
    return path.endswith(_STATIC_EXT)
