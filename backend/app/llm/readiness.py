"""Is this install actually able to think?

The three roles used to degrade quietly. A role with no key fell back to the
OpenRouter client, and an OpenRouter client with no key fell back to raising
inside the loop, where the exception was caught and turned into "the planner is
degraded" - one event, on one page, during a run the operator had already
started and would sit through. The first run on a fresh install therefore looked
like a tool that found nothing rather than a tool that was never configured.

This module answers the question before the run starts, in one place, from data
the caller already has. It is pure: no settings import, no router, no I/O - so
the API, the run gate and the setup wizard all reach the same verdict, and the
verdict is testable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from app.llm.providers import ROLE_NOTES, ROLES, provider_for_base_url

SOURCE_DIRECT = "direct"
SOURCE_FALLBACK = "openrouter_fallback"
SOURCE_NONE = "none"


@dataclass(frozen=True)
class RoleStatus:
    role: str
    configured: bool
    source: str
    provider: str = ""
    base_url: str = ""
    model: str = ""
    problems: List[str] = field(default_factory=list)

    def to_public(self) -> dict:
        return {
            "role": self.role,
            "configured": self.configured,
            "source": self.source,
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "problems": list(self.problems),
            "note": ROLE_NOTES.get(self.role, ""),
        }


@dataclass(frozen=True)
class Readiness:
    ready: bool
    roles: List[RoleStatus]
    missing: List[str]

    @property
    def summary(self) -> str:
        if self.ready:
            return "All three roles have a provider and a model."
        if len(self.missing) == len(ROLES):
            return ("No LLM provider is configured. The tool plans, drives its "
                    "tools and validates findings with a model - without one it "
                    "can only run a scanner and print its output.")
        return ("Not configured: " + ", ".join(self.missing)
                + ". Every role has to resolve to a provider and a model.")

    def to_public(self) -> dict:
        return {
            "ready": self.ready,
            "missing": list(self.missing),
            "summary": self.summary,
            "roles": [r.to_public() for r in self.roles],
        }


def role_status(role: str, *, base_url: str = "", model: str = "",
                api_key: str = "", fallback_key: str = "",
                fallback_base_url: str = "", fallback_model: str = "") -> RoleStatus:
    """One role's verdict.

    A role is configured when it resolves to an endpoint, a model AND a key -
    either its own, or the OpenRouter fallback's. Two out of three is not a
    working role, it is a 401 at the first call.
    """
    base_url = (base_url or "").strip()
    model = (model or "").strip()
    api_key = (api_key or "").strip()

    if api_key:
        problems: List[str] = []
        if not base_url:
            problems.append("no endpoint URL")
        if not model:
            problems.append("no model selected")
        return RoleStatus(
            role=role, configured=not problems, source=SOURCE_DIRECT,
            provider=provider_for_base_url(base_url), base_url=base_url,
            model=model, problems=problems,
        )

    if (fallback_key or "").strip():
        effective_model = model or (fallback_model or "").strip()
        problems = [] if effective_model else ["no model selected"]
        return RoleStatus(
            role=role, configured=not problems, source=SOURCE_FALLBACK,
            provider="openrouter",
            base_url=base_url or (fallback_base_url or "").strip(),
            model=effective_model, problems=problems,
        )

    return RoleStatus(
        role=role, configured=False, source=SOURCE_NONE,
        provider=provider_for_base_url(base_url), base_url=base_url, model=model,
        problems=["no API key"],
    )


def evaluate(role_configs: Dict[str, Dict[str, str]], *,
             fallback_key: str = "", fallback_base_url: str = "",
             fallback_model: str = "", roles: Sequence[str] = ROLES) -> Readiness:
    """Verdict for every role.

    `role_configs` maps a role to {base_url, model, api_key}. A missing role is
    treated as entirely unconfigured rather than skipped: a role the caller
    forgot to pass is not a role that works.
    """
    statuses = []
    for role in roles:
        cfg = role_configs.get(role) or {}
        statuses.append(role_status(
            role,
            base_url=cfg.get("base_url", ""),
            model=cfg.get("model", ""),
            api_key=cfg.get("api_key", ""),
            fallback_key=fallback_key,
            fallback_base_url=fallback_base_url,
            fallback_model=fallback_model,
        ))
    missing = [s.role for s in statuses if not s.configured]
    return Readiness(ready=not missing, roles=statuses, missing=missing)


def blocking_message(readiness: Readiness) -> Optional[str]:
    """What to tell an operator who just pressed Run on an unconfigured install.

    None when there is nothing to block on. The message names the fix rather
    than the symptom, because the symptom - a run that finds nothing - is what
    they would otherwise be left to interpret on their own.
    """
    if readiness.ready:
        return None
    return (readiness.summary
            + " Open Settings -> Model router, pick a provider and paste its API "
              "key, then start the run again.")


def from_router_status(status: Dict[str, Any], *, secrets: Dict[str, str],
                       fallback_key: str = "", fallback_base_url: str = "",
                       fallback_model: str = "") -> Readiness:
    """Adapter for LLMRouter.status(), which reports per-role config already."""
    configs: Dict[str, Dict[str, str]] = {}
    for role in ROLES:
        row = status.get(role) or {}
        base_url = str(row.get("base_url") or "")
        provider = provider_for_base_url(base_url)
        configs[role] = {
            "base_url": base_url,
            "model": str(row.get("model") or ""),
            "api_key": "set" if (row.get("configured") or secrets.get(provider)) else "",
        }
    return evaluate(configs, fallback_key=fallback_key,
                    fallback_base_url=fallback_base_url,
                    fallback_model=fallback_model)
