"""Dashboard + toolchain (SBOM) endpoints for the Home screen.

GET /api/dashboard -> headline counters (engagements, jobs, confirmed findings)
                      and global LLM usage with a per-model breakdown.
GET /api/tools     -> the orchestrated toolchain grouped-friendly by phase, with
                      availability. Versions are not claimed unless known.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter

from app import db
from app.scans.wrappers import available_wrappers

router = APIRouter(tags=["dashboard"])


def budget_exceeded(monthly_limit: float, spend: float) -> bool:
    """Is the LLM spend at or over the configured cap?

    No cap (0 / unset) means no ceiling, not "always over".
    """
    return bool(monthly_limit and spend >= monthly_limit)


def budget_pct(monthly_limit: float, spend: float) -> int:
    """Spend as a percentage of the cap; 0 when no cap is set."""
    if not monthly_limit:
        return 0
    return round(spend / monthly_limit * 100)


def _positive_float(value: Any) -> float:
    """Coerce an operator-supplied number, never raising. 0 means no limit."""
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return 0.0

# Map each real wrapper to a methodology phase for the SBOM grouping.
_PHASE_BY_TOOL = {
    "subfinder": "Reconnaissance", "naabu": "Reconnaissance", "httpx": "Reconnaissance",
    "dnsx": "Reconnaissance", "katana": "Reconnaissance", "gau": "Reconnaissance",
    "nmap": "Reconnaissance",
    "nuclei": "Scanning & enumeration", "ffuf": "Scanning & enumeration",
    "wafw00f": "Scanning & enumeration", "whatweb": "Scanning & enumeration",
    "nikto": "Scanning & enumeration", "testssl": "Scanning & enumeration",
    "sqlmap": "Exploitation", "dalfox": "Exploitation", "commix": "Exploitation",
    "wpscan": "Exploitation",
    "mitmproxy": "Capture & analysis",
}
_PHASE_ORDER = ["Reconnaissance", "Scanning & enumeration", "Exploitation",
                "Capture & analysis", "Other"]


@router.get("/api/tools")
async def tools() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for w in available_wrappers():
        name = w["name"]
        out.append({
            "name": name,
            "version": None,                 # not introspected; UI shows "-"
            "source": w.get("category") or "",
            "phase": _PHASE_BY_TOOL.get(name, "Other"),
            "available": bool(w["available"]),
        })
    out.sort(key=lambda t: (_PHASE_ORDER.index(t["phase"]) if t["phase"] in _PHASE_ORDER else 99,
                            t["name"]))
    return out


@router.get("/api/dashboard")
async def dashboard() -> Dict[str, Any]:
    async with db.acquire() as conn:
        active = int(await conn.fetchval(
            "SELECT COUNT(*) FROM engagements WHERE status = 'authorized'"))
        running = int(await conn.fetchval(
            "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')"))
        sev_rows = await conn.fetch(
            "SELECT severity, COUNT(*) AS n FROM validated_findings "
            "WHERE status = 'confirmed' GROUP BY severity")
        usage = await conn.fetchrow(
            "SELECT COUNT(*) AS calls, COALESCE(SUM(prompt_tokens),0) AS pt, "
            "COALESCE(SUM(completion_tokens),0) AS ct, COALESCE(SUM(cost_usd),0) AS cost "
            "FROM llm_usage")
        by_model_rows = await conn.fetch(
            "SELECT model, COALESCE(SUM(prompt_tokens+completion_tokens),0) AS tok "
            "FROM llm_usage GROUP BY model ORDER BY tok DESC")
        # Which ROLE is spending, not just which model. Two roles often sit on
        # the same model, so the per-model bar cannot answer "is the planner
        # burning this?" - and the planner runs once per loop iteration.
        by_role_rows = await conn.fetch(
            "SELECT COALESCE(role,'(unknown)') AS role, COUNT(*) AS calls, "
            "COALESCE(SUM(prompt_tokens),0) AS pt, "
            "COALESCE(SUM(completion_tokens),0) AS ct, "
            "COALESCE(SUM(cost_usd),0) AS cost "
            "FROM llm_usage GROUP BY role ORDER BY SUM(prompt_tokens+completion_tokens) DESC")
        # Spend since the start of the current calendar month, for the budget
        # guardrail. ts is epoch seconds, so compare against the month boundary.
        month_start = datetime.now(timezone.utc).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()
        month_cost = float(await conn.fetchval(
            "SELECT COALESCE(SUM(cost_usd),0) FROM llm_usage WHERE ts >= $1",
            month_start) or 0.0)

    sev = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for r in sev_rows:
        sev[(r["severity"] or "info").lower()] = int(r["n"])

    total_tokens = int(usage["pt"]) + int(usage["ct"])
    from app.llm.usage import pct_of

    by_role = []
    for r in by_role_rows:
        tok = int(r["pt"]) + int(r["ct"])
        by_role.append({
            "role": r["role"], "calls": int(r["calls"]), "tokens": tok,
            "prompt_tokens": int(r["pt"]), "completion_tokens": int(r["ct"]),
            "cost_usd": round(float(r["cost"]), 4),
            "pct": pct_of(tok, total_tokens),
        })

    by_model = []
    for r in by_model_rows:
        tok = int(r["tok"])
        by_model.append({
            "model": r["model"] or "(unknown)",
            "tokens": tok,
            "pct": round(tok / total_tokens * 100) if total_tokens else 0,
        })

    # Budget guardrail. `priced` tells the UI whether a $0 figure means "cheap"
    # or "LLM_PRICING is unset", which are very different situations.
    try:
        from app import settings_store
        budget_cfg = (await settings_store.get_public()).get("budget") or {}
    except Exception:  # noqa: BLE001 - the dashboard must never fail on settings
        budget_cfg = {}
    # The settings API takes budget as a free-form dict, so this value is
    # whatever a client sent. A non-numeric one used to raise here, outside the
    # guard above, and 500 the whole dashboard. Negatives are clamped too: a
    # limit below zero is always "exceeded", which would pin the alert on.
    monthly_limit = _positive_float(budget_cfg.get("monthly_usd"))

    from app.config import settings as app_settings
    budget = {
        "monthly_limit_usd": monthly_limit,
        "month_spend_usd": round(month_cost, 4),
        "over": budget_exceeded(monthly_limit, month_cost),
        "pct": budget_pct(monthly_limit, month_cost),
        "priced": bool((app_settings.llm_pricing or "").strip()),
    }

    return {
        "active_engagements": active,
        "running_jobs": running,
        "confirmed_findings": sev,
        "llm_usage": {
            "calls": int(usage["calls"]),
            "total_tokens": total_tokens,
            "prompt_tokens": int(usage["pt"]),
            "completion_tokens": int(usage["ct"]),
            "prompt_pct": pct_of(int(usage["pt"]), total_tokens),
            "cost_usd": round(float(usage["cost"]), 4),
            "by_model": by_model,
            "by_role": by_role,
        },
        "budget": budget,
    }
