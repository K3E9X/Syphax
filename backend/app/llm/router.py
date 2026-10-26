"""Per-role LLM router.

The agent system (Phase 4) needs three roles with different capability/cost
tradeoffs:

    planner   - strongest reasoning (e.g. GLM-5.1, Kimi K2.6) - decides next moves
    executor  - cheap and fast (e.g. GLM-4.6, DeepSeek) - drives tool calls
    validator - accurate and grounded - confirms findings, kills false positives

Each role is an OpenAI-compatible endpoint configured via .env:

    {ROLE}_BASE_URL, {ROLE}_API_KEY, {ROLE}_MODEL

If a role has no API key configured it falls back to the OPENROUTER_* client,
which preserves Phase 0-3 behaviour out of the box.
"""
from __future__ import annotations

from typing import Dict, Iterable, Optional

from app.config import settings
from app.llm.client import LLMClient

# Stable role names. Code passes one of these strings; we keep them as
# plain strings (not an Enum) so they survive serialization round-trips.
ROLE_PLANNER = "planner"
ROLE_EXECUTOR = "executor"
ROLE_VALIDATOR = "validator"
ROLES: tuple = (ROLE_PLANNER, ROLE_EXECUTOR, ROLE_VALIDATOR)


class LLMRouter:
    """Holds one LLMClient per role. Lazy-built so we never instantiate a
    client we won't use."""

    def __init__(self) -> None:
        self._clients: Dict[str, LLMClient] = {}
        self._fallback: Optional[LLMClient] = None

    def fallback(self) -> LLMClient:
        if self._fallback is None:
            # The plain LLMClient() picks up OPENROUTER_* settings by default.
            self._fallback = LLMClient()
        return self._fallback

    def get(self, role: str) -> LLMClient:
        if role not in ROLES:
            raise KeyError(f"unknown LLM role: {role}")
        client = self._clients.get(role)
        if client is not None:
            return client

        base_url, api_key, model = _role_config(role)
        if not api_key:
            # No role-specific key -> reuse the OpenRouter fallback so the
            # caller still gets a working client.
            client = self.fallback()
        else:
            client = LLMClient(
                base_url=base_url or None,
                api_key=api_key,
                model=model or settings.openrouter_model,
                # Cross-PROVIDER fallback to OpenRouter free models when the
                # primary provider 429/5xx's or times out. These are OpenRouter
                # model ids, so they need OpenRouter's endpoint and key - this
                # client's own would send them to the wrong provider, which is
                # exactly what used to happen (see client._attempts).
                fallback_models=settings.openrouter_fallback_list,
                fallback_base_url=settings.openrouter_base_url,
                fallback_api_key=settings.openrouter_api_key,
                role=role,
            )
        self._clients[role] = client
        return client

    def reconfigure(self, role: str, *, base_url: str, api_key: str, model: str) -> None:
        """Override a role's client at runtime (from saved Settings). An empty
        api_key drops back to the OpenRouter fallback for that role."""
        if role not in ROLES:
            raise KeyError(f"unknown LLM role: {role}")
        if not api_key:
            self._clients.pop(role, None)  # next get() rebuilds from env/fallback
            return
        self._clients[role] = LLMClient(
            base_url=base_url or None,
            api_key=api_key,
            model=model or settings.openrouter_model,
            fallback_models=settings.openrouter_fallback_list,
            fallback_base_url=settings.openrouter_base_url,
            fallback_api_key=settings.openrouter_api_key,
            role=role,
        )

    def status(self) -> Dict[str, Dict[str, object]]:
        """Per-role view: which provider answers, is it configured, last used.

        Read from the ACTUAL client each role would use, not from the .env
        values in `_role_config`. A role's key is usually set in the UI, stored
        in the database and pushed into the router via `reconfigure()` - env is
        empty in that (normal) case. Reading env made this report "configured:
        false / OpenRouter fallback / base_url=<env default>" while the run was
        really calling the configured provider (and billing it), contradicting
        settings_store.llm_readiness() and reading as "my model is not wired"
        when it was. The client is the source of truth: a role falls back only
        when `get()` hands back the shared OpenRouter fallback instance.
        """
        out: Dict[str, Dict[str, object]] = {}
        for role in ROLES:
            client = self.get(role)
            using_fallback = client is self._fallback
            out[role] = {
                "configured": client.configured and not using_fallback,
                "using_openrouter_fallback": using_fallback,
                "base_url": client.base_url,
                "model": client.model,
                "fallback_models": client.fallback_models,
                "last_used_model": client.last_used_model,
            }
        return out


def _role_config(role: str) -> tuple:
    """Return (base_url, api_key, model) for a role."""
    if role == ROLE_PLANNER:
        return settings.planner_base_url, settings.planner_api_key, settings.planner_model
    if role == ROLE_EXECUTOR:
        return settings.executor_base_url, settings.executor_api_key, settings.executor_model
    if role == ROLE_VALIDATOR:
        return settings.validator_base_url, settings.validator_api_key, settings.validator_model
    raise KeyError(role)


_router: Optional[LLMRouter] = None


def get_router() -> LLMRouter:
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router


def iter_roles() -> Iterable[str]:
    return ROLES
