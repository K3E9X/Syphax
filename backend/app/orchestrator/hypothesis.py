"""Hypothesis-driven planning (intelligence layer #2).

The deterministic planner walks the static catalog. This lets the planner LLM
propose *targeted* next moves grounded in what was actually fingerprinted - e.g.
"Atlassian + Jira detected -> run nuclei -tags jira,atlassian,cve on host X".

Safety: the model can only ever emit a nuclei tag-hunt against an asset that
already exists (grounding) with tags sanitized to a safe charset. It cannot
choose a different tool, an arbitrary target, or free-form options. The
deterministic candidates remain the floor; hunts are added on top.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List

from app.llm.grounding import safe_tokens

HUNT_TOOL = "nuclei"


@dataclass
class _HuntTask:
    catalog_item_id: str
    asset_value: str
    tool: str
    options: List[str]
    phase: str

    @property
    def key(self) -> str:
        return f"{self.catalog_item_id}@{self.asset_value}"


def build_hunt_tasks(parsed: Any, asset_values, phase: str,
                     task_cls=_HuntTask, *, limit: int = 4) -> List[Any]:
    """Turn the model's `extra_hunts` into validated nuclei tasks.

    `parsed` is the decoded LLM JSON. Each hunt must reference a real asset and
    yields at most one task. `task_cls` lets the planner pass its own Task type.
    """
    if not isinstance(parsed, dict):
        return []
    hunts = parsed.get("extra_hunts")
    if not isinstance(hunts, list):
        return []
    valid_assets = set(asset_values or [])
    out: List[Any] = []
    seen = set()
    for h in hunts:
        if not isinstance(h, dict):
            continue
        asset = str(h.get("asset", "")).strip()
        if asset not in valid_assets:
            continue  # grounding: the model can't invent a target
        tags = safe_tokens(h.get("tags"))
        if not tags:
            continue
        slug = "-".join(tags[:3])
        cid = f"LLM-HUNT-{slug}"
        key = f"{cid}@{asset}"
        if key in seen:
            continue
        seen.add(key)
        out.append(task_cls(
            catalog_item_id=cid,
            asset_value=asset,
            tool=HUNT_TOOL,
            options=["-tags", ",".join(tags)],
            phase=phase,
        ))
        if len(out) >= limit:
            break
    return out
