"""The providers the Settings page offers, and how to reach them.

Every entry is an OpenAI-compatible Chat Completions endpoint, which is the only
thing app/llm/client.py knows how to speak. That is why "custom" is in the list
and why the model field is free text everywhere: a provider that ships a new
model on a Tuesday should not need a release of this tool on Wednesday.

The suggested models are suggestions, not a whitelist. Nothing validates against
them - they exist so the operator does not have to go and look up a model string
to get started, and they will lag the provider's current line-up. If a model is
rejected, the provider's error says so and the ping button shows it.

Why these providers: the tool runs three roles - planner, executor, validator -
and the executor and validator do the volume. Cost per token decides whether a
long engagement is affordable, and the Chinese labs are several times cheaper
than the US frontier models at comparable quality for this workload, which is
tool-call driving and short structured judgements rather than open-ended prose.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

ROLE_PLANNER = "planner"
ROLE_EXECUTOR = "executor"
ROLE_VALIDATOR = "validator"
ROLES: Tuple[str, ...] = (ROLE_PLANNER, ROLE_EXECUTOR, ROLE_VALIDATOR)

ROLE_NOTES: Dict[str, str] = {
    ROLE_PLANNER: "Decides what to do next. The one role where reasoning quality "
                  "changes what gets found, and the one that runs least often.",
    ROLE_EXECUTOR: "Drives the tools and reads their output. Runs constantly, so "
                   "this is where speed and price per token actually land.",
    ROLE_VALIDATOR: "Confirms or kills a finding. Accuracy here is what keeps the "
                    "report free of false positives.",
}

CUSTOM = "custom"


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    base_url: str
    models: List[str] = field(default_factory=list)
    console_url: str = ""
    note: str = ""

    def to_public(self) -> dict:
        return {
            "id": self.id, "label": self.label, "base_url": self.base_url,
            "models": list(self.models), "console_url": self.console_url,
            "note": self.note,
        }


CATALOG: Tuple[Provider, ...] = (
    Provider(
        id="zai",
        label="Z.ai (GLM)",
        base_url="https://api.z.ai/api/paas/v4",
        models=["glm-5.2", "glm-4.6"],
        console_url="https://z.ai",
        note="Pay-as-you-go, fast, and the cheapest of these per token. The "
             "default for the executor and validator roles, which do the volume.",
    ),
    Provider(
        id="moonshot",
        label="Moonshot (Kimi)",
        base_url="https://api.moonshot.ai/v1",
        models=["kimi-k3", "kimi-k2.5"],
        console_url="https://platform.moonshot.ai",
        note="Long-horizon agentic reasoning and a very large context window. "
             "Always reasons, so it is slow - which is fine for the planner and "
             "expensive everywhere else. Prepaid credit, no subscription. Note "
             "that api.moonshot.CN is a separate platform with its own account.",
    ),
    Provider(
        id="deepseek",
        label="DeepSeek",
        base_url="https://api.deepseek.com/v1",
        models=["deepseek-chat", "deepseek-reasoner"],
        console_url="https://platform.deepseek.com",
        note="Cheapest per token of the three, with off-peak discounts. "
             "deepseek-reasoner is the planner-grade model; deepseek-chat is the "
             "fast one.",
    ),
    Provider(
        id="qwen",
        label="Qwen (Alibaba DashScope)",
        base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        models=["qwen-max", "qwen-plus", "qwen3-coder-plus"],
        console_url="https://www.alibabacloud.com/help/en/model-studio/",
        note="Very large context, which pays off directly on the executor role: "
             "that role runs the response analyst and is fed raw captured "
             "traffic. Use the -intl endpoint outside mainland China.",
    ),
    Provider(
        id="openrouter",
        label="OpenRouter",
        base_url="https://openrouter.ai/api/v1",
        models=["qwen/qwen3-coder", "z-ai/glm-4.6", "moonshotai/kimi-k2"],
        console_url="https://openrouter.ai/keys",
        note="An aggregator: one key, many models, a small markup. Useful for "
             "trying a model before opening an account with its provider, and "
             "as the cross-provider fallback when a primary returns 429.",
    ),
    Provider(
        id=CUSTOM,
        label="Other (OpenAI-compatible)",
        base_url="",
        models=[],
        note="Anything that speaks /v1/chat/completions: a self-hosted vLLM or "
             "Ollama, an in-house gateway, OpenAI or Anthropic through a proxy. "
             "Fill in the base URL and model yourself.",
    ),
)

BY_ID: Dict[str, Provider] = {p.id: p for p in CATALOG}

# Which provider key a base URL needs. Matched on substrings rather than exact
# equality because operators legitimately point a role at a regional host, a
# gateway, or a path suffix we did not anticipate.
_MATCHES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("zai", ("z.ai", "zhipu", "bigmodel")),
    ("moonshot", ("moonshot",)),
    ("deepseek", ("deepseek",)),
    ("qwen", ("dashscope", "aliyuncs")),
    ("openrouter", ("openrouter",)),
)

# Roles default to these when the operator has not chosen: quality where the
# decisions are made, price and speed where the volume is.
DEFAULT_ASSIGNMENT: Dict[str, str] = {
    ROLE_PLANNER: "moonshot",
    ROLE_EXECUTOR: "zai",
    ROLE_VALIDATOR: "zai",
}


def provider_for_base_url(base_url: str) -> str:
    """Which stored key a role using this base URL should be given.

    Falls back to `custom` rather than to openrouter. The old behaviour handed
    an unrecognised endpoint the OpenRouter key, which silently sent one
    provider's credential to another provider's server.
    """
    b = (base_url or "").strip().lower()
    if not b:
        return ""
    for provider_id, needles in _MATCHES:
        if any(n in b for n in needles):
            return provider_id
    return CUSTOM


def provider_ids() -> Tuple[str, ...]:
    """Every id a key can be stored under, including `custom`."""
    return tuple(p.id for p in CATALOG)


def get(provider_id: str) -> Optional[Provider]:
    return BY_ID.get((provider_id or "").strip().lower())


def suggested_model(provider_id: str) -> str:
    p = get(provider_id)
    return p.models[0] if p and p.models else ""


def to_public() -> List[dict]:
    return [p.to_public() for p in CATALOG]
