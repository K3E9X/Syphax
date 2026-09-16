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
from typing import Any, Dict, List

from app import events
from app.llm import ROLE_PLANNER, LLMError, get_router
from app.methodology import CATALOG, CATALOG_BY_ID, PHASE_ORDER, applies
from app.orchestrator.state import Asset, EngagementState

logger = logging.getLogger("syphax.orchestrator.planner")

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Task:
    catalog_item_id: str
    asset_value: str
    tool: str
    options: List[str]
    phase: str

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

    async def plan(self, *, max_tasks: int = 12, use_llm: bool = True) -> List[Task]:
        """Return the next batch of uncovered, applicable tasks."""
        assets = await self.state.assets()
        tech = await self.state.technologies()

        candidates = await self._candidate_tasks(assets, tech)
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
        earliest_phase = candidates[0].phase
        batch = [t for t in candidates if t.phase == earliest_phase][:max_tasks]

        if use_llm:
            batch = await self._llm_reorder(batch, tech)

        return batch

    async def _candidate_tasks(self, assets: List[Asset], tech: List[str]) -> List[Task]:
        tasks: List[Task] = []
        for item in CATALOG:
            for asset in assets:
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


def _task_sort_key(t: Task):
    phase_idx = PHASE_ORDER.index(t.phase) if t.phase in PHASE_ORDER else 99
    item = CATALOG_BY_ID.get(t.catalog_item_id)
    sev = _SEVERITY_RANK.get(item.severity_default if item else "info", 4)
    return (phase_idx, sev, t.catalog_item_id, t.asset_value)


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
