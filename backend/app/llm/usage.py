"""LLM token / cost accounting.

Every chat() call records its token usage against the engagement that is
currently in scope (set via the `current_engagement` contextvar by the
orchestrator loop and the per-request API handlers). Cost is taken from the
provider response when present (OpenRouter can return `usage.cost`), otherwise
estimated from configurable per-model pricing (default 0, so free models read
as $0 while still showing tokens).
"""
from __future__ import annotations

import contextvars
import logging
import time
from typing import Any, Dict, Optional

from app import db
from app.config import settings

logger = logging.getLogger("syphax.llm.usage")

# Set by the loop / API handlers so chat() knows what to bill.
current_engagement: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_engagement", default=None
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS llm_usage (
    id                BIGSERIAL PRIMARY KEY,
    engagement_id     TEXT,
    ts                DOUBLE PRECISION NOT NULL,
    role              TEXT,
    model             TEXT,
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd          DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_llm_usage_engagement ON llm_usage(engagement_id);
"""

db.register_schema(SCHEMA_SQL)


def _price_map() -> Dict[str, tuple]:
    """Parse LLM_PRICING from settings: 'model=in/out,model2=in/out' where
    in/out are USD per 1M tokens. Returns {model: (in_per_1m, out_per_1m)}."""
    raw = getattr(settings, "llm_pricing", "") or ""
    out: Dict[str, tuple] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        model, rates = entry.split("=", 1)
        try:
            inp, outp = rates.split("/", 1)
            out[model.strip()] = (float(inp), float(outp))
        except ValueError:
            continue
    return out


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    rates = _price_map().get(model)
    if not rates:
        return 0.0
    inp, outp = rates
    return (prompt_tokens / 1_000_000) * inp + (completion_tokens / 1_000_000) * outp


async def record(
    *,
    role: Optional[str],
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    cost_usd: Optional[float] = None,
) -> None:
    """Record one LLM call's usage against the current engagement (best-effort)."""
    engagement_id = current_engagement.get()
    if cost_usd is None:
        cost_usd = estimate_cost(model, prompt_tokens, completion_tokens)
    try:
        async with db.acquire() as conn:
            await conn.execute(
                "INSERT INTO llm_usage (engagement_id, ts, role, model, "
                "prompt_tokens, completion_tokens, cost_usd) VALUES ($1,$2,$3,$4,$5,$6,$7)",
                engagement_id, time.time(), role, model,
                int(prompt_tokens), int(completion_tokens), float(cost_usd),
            )
    except Exception:  # noqa: BLE001
        logger.exception("llm usage record failed for model %s", model)


async def summary(engagement_id: str) -> Dict[str, Any]:
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS calls, "
            "COALESCE(SUM(prompt_tokens),0) AS prompt, "
            "COALESCE(SUM(completion_tokens),0) AS completion, "
            "COALESCE(SUM(cost_usd),0) AS cost "
            "FROM llm_usage WHERE engagement_id=$1",
            engagement_id,
        )
    return {
        "calls": int(row["calls"]),
        "prompt_tokens": int(row["prompt"]),
        "completion_tokens": int(row["completion"]),
        "total_tokens": int(row["prompt"]) + int(row["completion"]),
        "cost_usd": round(float(row["cost"]), 4),
    }

# --------------------------------------------------------------------------- #
# Breakdowns.
#
# The table already records `role`, `ts` and the prompt/completion split; none
# of it ever reached the UI, which showed one total and a per-model bar. So the
# question that actually matters - WHICH part of the system is spending this -
# had no answer, even though the planner is re-invoked on every loop iteration
# and is the usual reason a run costs more than expected.
#
# The shaping helpers below are pure so the arithmetic is testable without a
# database.
# --------------------------------------------------------------------------- #

# Buckets in a run's token timeline. Enough to see a spike, few enough to read
# at a glance in a narrow panel.
TIMELINE_BUCKETS = 40
TOP_CALLS = 8


def pct_of(part: float, total: float) -> int:
    """Percentage, 0 when the total is 0 (rather than a ZeroDivisionError)."""
    if not total:
        return 0
    return round(part / total * 100)


def per_minute(total: float, seconds: float) -> float:
    """Burn rate. A window under a second reports the raw total rather than
    extrapolating it to an absurd per-minute figure."""
    if not seconds or seconds < 1:
        return round(float(total), 3)
    return round(float(total) / (seconds / 60.0), 3)


def bucketize(points, *, buckets: int = TIMELINE_BUCKETS, start=None, end=None):
    """Sum (ts, value) points into `buckets` equal time slots.

    Returns {"buckets": [...], "bucket_seconds": n, "start": ts, "end": ts}.
    An empty input gives empty buckets, not a divide-by-zero: a run that made
    no LLM calls is a legitimate state.
    """
    pts = [(float(t), float(v)) for t, v in points if t is not None]
    if not pts:
        return {"buckets": [], "bucket_seconds": 0, "start": 0.0, "end": 0.0}
    lo = float(start) if start is not None else min(t for t, _ in pts)
    hi = float(end) if end is not None else max(t for t, _ in pts)
    if hi <= lo:
        hi = lo + 1.0
    n = max(1, int(buckets))
    width = (hi - lo) / n
    out = [0.0] * n
    for t, v in pts:
        idx = int((t - lo) / width)
        out[min(max(idx, 0), n - 1)] += v
    return {"buckets": [round(x, 3) for x in out], "bucket_seconds": round(width, 3),
            "start": lo, "end": hi}


def cost_per_finding(cost_usd: float, confirmed: int) -> float:
    """Dollars per confirmed finding - the only ratio that says whether the
    spend bought anything. Zero findings returns 0.0 rather than infinity;
    the caller shows the raw spend instead."""
    if not confirmed:
        return 0.0
    return round(float(cost_usd) / int(confirmed), 4)


async def _grouped(engagement_id, column: str):
    async with db.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT COALESCE({column}, '(unknown)') AS key, COUNT(*) AS calls, "
            "COALESCE(SUM(prompt_tokens),0) AS prompt, "
            "COALESCE(SUM(completion_tokens),0) AS completion, "
            "COALESCE(SUM(cost_usd),0) AS cost "
            "FROM llm_usage WHERE ($1::text IS NULL OR engagement_id=$1) "
            f"GROUP BY {column} ORDER BY SUM(prompt_tokens+completion_tokens) DESC",
            engagement_id,
        )
    total = sum(int(r["prompt"]) + int(r["completion"]) for r in rows)
    out = []
    for r in rows:
        tokens = int(r["prompt"]) + int(r["completion"])
        out.append({
            "key": r["key"], "calls": int(r["calls"]),
            "prompt_tokens": int(r["prompt"]),
            "completion_tokens": int(r["completion"]),
            "tokens": tokens,
            "cost_usd": round(float(r["cost"]), 4),
            "pct": pct_of(tokens, total),
        })
    return out


async def by_role(engagement_id=None):
    """Spend per model-router role (planner / executor / validator).

    The planner runs once per loop iteration, so this is where a runaway loop
    shows up first."""
    return await _grouped(engagement_id, "role")


async def by_model(engagement_id=None):
    return await _grouped(engagement_id, "model")


async def top_calls(engagement_id=None, limit: int = TOP_CALLS):
    """The individual calls that cost the most tokens.

    A summary cannot tell you that one 80k-token prompt is the whole bill; this
    can, and it names the role and model responsible."""
    async with db.acquire() as conn:
        rows = await conn.fetch(
            "SELECT ts, role, model, prompt_tokens, completion_tokens, cost_usd "
            "FROM llm_usage WHERE ($1::text IS NULL OR engagement_id=$1) "
            "ORDER BY (prompt_tokens + completion_tokens) DESC LIMIT $2",
            engagement_id, int(limit),
        )
    return [{
        "ts": float(r["ts"]),
        "role": r["role"] or "(unknown)",
        "model": r["model"] or "(unknown)",
        "prompt_tokens": int(r["prompt_tokens"]),
        "completion_tokens": int(r["completion_tokens"]),
        "tokens": int(r["prompt_tokens"]) + int(r["completion_tokens"]),
        "cost_usd": round(float(r["cost_usd"]), 4),
    } for r in rows]


async def timeline(engagement_id=None, *, buckets: int = TIMELINE_BUCKETS):
    """Tokens and cost over time, bucketed for a sparkline."""
    async with db.acquire() as conn:
        rows = await conn.fetch(
            "SELECT ts, prompt_tokens + completion_tokens AS tok, cost_usd "
            "FROM llm_usage WHERE ($1::text IS NULL OR engagement_id=$1) ORDER BY ts",
            engagement_id,
        )
    tok = bucketize([(r["ts"], r["tok"]) for r in rows], buckets=buckets)
    cost = bucketize([(r["ts"], r["cost_usd"]) for r in rows], buckets=buckets)
    tok["cost_buckets"] = cost["buckets"]
    return tok


def budget_verdict(limit_usd, spend_usd) -> Dict[str, Any]:
    """Where a spend sits against a cap. Pure, so both the orchestrator (which
    stops the run) and the API (which reports it) use the same rule.

    A cap of 0 / unset / unparseable means NO ceiling, never "always over" - a
    guardrail that cannot be read must not stop a run the operator asked for.
    """
    try:
        limit = max(0.0, float(limit_usd or 0))
    except (TypeError, ValueError):
        limit = 0.0
    try:
        spent = max(0.0, float(spend_usd or 0))
    except (TypeError, ValueError):
        spent = 0.0
    return {
        "limit_usd": round(limit, 4),
        "spend_usd": round(spent, 4),
        "over": bool(limit and spent >= limit),
        "pct": pct_of(spent, limit) if limit else 0,
    }


async def spend(engagement_id: str) -> float:
    """Total USD charged to one engagement. Used by the per-engagement budget
    guardrail, which the operator could set but nothing ever read."""
    async with db.acquire() as conn:
        value = await conn.fetchval(
            "SELECT COALESCE(SUM(cost_usd),0) FROM llm_usage WHERE engagement_id=$1",
            engagement_id,
        )
    return round(float(value or 0.0), 4)


async def detail(engagement_id: str) -> Dict[str, Any]:
    """Everything the token panel renders, in one round trip."""
    base = await summary(engagement_id)
    roles = await by_role(engagement_id)
    models = await by_model(engagement_id)
    series = await timeline(engagement_id)
    top = await top_calls(engagement_id)

    duration = max(0.0, (series.get("end") or 0.0) - (series.get("start") or 0.0))
    total = base["total_tokens"]
    return {
        **base,
        "prompt_pct": pct_of(base["prompt_tokens"], total),
        "completion_pct": pct_of(base["completion_tokens"], total),
        "by_role": roles,
        "by_model": models,
        "timeline": series,
        "top_calls": top,
        "duration_seconds": round(duration, 1),
        "tokens_per_min": per_minute(total, duration),
        "cost_per_min": per_minute(base["cost_usd"], duration),
    }
