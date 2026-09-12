"""FastAPI entrypoint for Syphax.

Storage is Postgres (asyncpg pool, shared by the API and the arq worker).
The mitmproxy addon writes flows synchronously via psycopg using the same
DATABASE_URL.
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Importing the storage modules registers their CREATE TABLE statements with
# app.db; init_db() then runs them all in lifespan startup.
import app.memory  # noqa: F401  - register schema
import app.network.shared_state  # noqa: F401  - register schema
import app.audit  # noqa: F401
import app.events  # noqa: F401
import app.llm.usage  # noqa: F401
import app.engagements.storage  # noqa: F401
import app.orchestrator.state  # noqa: F401
import app.orchestrator.runs  # noqa: F401
import app.orchestrator.approvals  # noqa: F401
import app.proxy.storage  # noqa: F401
import app.sandbox.staging  # noqa: F401
import app.scans.storage  # noqa: F401
import app.validation.storage  # noqa: F401

from app import db
from app.api.audit import router as audit_router
from app.api.dashboard import router as dashboard_router
from app.api.engagements import router as engagements_router
from app.api.findings import router as findings_router
from app.api.llm import router as llm_router
from app.api.methodology import router as methodology_router
from app.api.network import router as network_router
from app.api.poc import router as poc_router
from app.api.orchestrator import router as orchestrator_router
from app.api.proxy import router as proxy_router
from app.api.reports import router as reports_router
from app.api.sandbox import router as sandbox_router
from app.api.scans import router as scans_router
from app.api.settings import router as settings_router
from app.api.stream import router as stream_router
from app.api.surface import router as surface_router
from app.config import settings
from app.llm import LLMError, get_llm, get_router, iter_roles


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    await db.init_db()
    # Fresh start: drop the previous run's scan artefacts before anything else
    # reads them. Runs after init_db so the tables are guaranteed to exist.
    if settings.reset_on_start:
        from app.maintenance import reset_job_queue, reset_transient_data
        await reset_transient_data()
        # Redis outlives the containers too; a queued job whose row we just
        # deleted would otherwise be picked up by the worker after the restart.
        await reset_job_queue()
    from app import settings_store
    await settings_store.apply_saved_on_startup()
    # Record the real exit IP now, while nothing is tunnelled, so the kill
    # switch has something to compare against later.
    try:
        from app.network.privacy import get_network_manager
        await get_network_manager().record_baseline()
    except Exception:  # noqa: BLE001 - no outbound access must not block boot
        pass
    yield
    await db.close_pool()


app = FastAPI(title="syphax v2", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- API key (opt-in; see app/api_auth.py) -----------------------------------
@app.middleware("http")
async def _api_key_guard(request, call_next):
    from app.api_auth import authorize
    if not authorize(request.url.path, request.headers, settings.api_key,
                     request.query_params.get("key")):
        return JSONResponse(
            status_code=401,
            content={"detail": "missing or invalid API key "
                                "(send X-API-Key or Authorization: Bearer)"},
        )
    return await call_next(request)


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/api/config")
async def config() -> dict:
    llm = get_llm()
    return {
        "llm_configured": llm.configured,
        "llm_model": llm.model,
        "llm_fallback_models": llm.fallback_models,
        "llm_roles": get_router().status(),
        "mitm_port": settings.mitm_port,
        "data_dir": str(settings.data_dir),
    }


@app.post("/api/llm/ping")
async def llm_ping(role: str = "planner") -> dict:
    """Sanity-check the LLM client for a given role.

    `role` is one of: planner, executor, validator. Defaults to planner.
    Unknown roles fall back to the legacy single-client behaviour (the
    OpenRouter default) so the Phase 0-3 UI keeps working unmodified.
    """
    if role in iter_roles():
        llm = get_router().get(role)
    else:
        llm = get_llm()

    started = time.perf_counter()
    try:
        reply = await llm.chat(
            [
                {"role": "system", "content": "Respond with only the word: pong"},
                {"role": "user", "content": "ping"},
            ],
            temperature=0.0,
            max_tokens=16,
        )
    except LLMError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    latency_ms = round((time.perf_counter() - started) * 1000)

    # A reply alone does not tell you whether the model is usable in a loop:
    # a reasoning model answering in 12s changes how you budget a run.
    usage = getattr(llm, "last_usage", None) or {}
    return {
        "role": role,
        "primary_model": llm.model,
        "model_used": llm.last_used_model or llm.model,
        "fallback_used": (llm.last_used_model or llm.model) != llm.model,
        "reply": reply.strip(),
        "latency_ms": latency_ms,
        "prompt_tokens": usage.get("prompt_tokens", 0),
        "completion_tokens": usage.get("completion_tokens", 0),
    }


app.include_router(engagements_router)
app.include_router(orchestrator_router)
app.include_router(proxy_router)
app.include_router(scans_router)
app.include_router(llm_router)
app.include_router(audit_router)
app.include_router(methodology_router)
app.include_router(reports_router)
app.include_router(stream_router)
app.include_router(dashboard_router)
app.include_router(settings_router)
app.include_router(findings_router)
app.include_router(surface_router)
app.include_router(sandbox_router)
app.include_router(network_router)
app.include_router(poc_router)
