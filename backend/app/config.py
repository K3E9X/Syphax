"""Runtime configuration loaded from environment / .env."""
from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # OpenRouter (default + fallback for any role left blank below).
    openrouter_api_key: str = ""
    openrouter_model: str = "qwen/qwen3-coder:free"
    openrouter_fallback_models: str = (
        "meta-llama/llama-3.3-70b-instruct:free,"
        "openai/gpt-oss-120b:free,"
        "qwen/qwen3-next-80b-a3b-instruct:free"
    )
    openrouter_app_name: str = "syphax"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    # Per-role LLM router (Planner / Executor / Validator). Each role is an
    # OpenAI-compatible Chat Completions endpoint - works with OpenRouter,
    # Z.ai (GLM), Moonshot (Kimi), DeepSeek, OpenAI, etc. If a role's API
    # key is empty, it falls back to OpenRouter so the existing Phase 0-3
    # flows keep working without any new config.
    planner_base_url: str = ""
    planner_api_key: str = ""
    planner_model: str = ""

    executor_base_url: str = ""
    executor_api_key: str = ""
    executor_model: str = ""

    validator_base_url: str = ""
    validator_api_key: str = ""
    validator_model: str = ""

    # Exploit rehearsal. When > 0 and the engagement authorizes active
    # exploitation and the sandbox is up, an authored PoC is run in the sandbox
    # and the model revises it - up to this many rounds - until it demonstrates
    # the issue, before a human reads the final version. 0 = off: the model
    # still writes a PoC, it just does not get to rehearse it. See
    # app/exploit/refine.py. The rehearsal reaches the live target, so it is
    # gated behind allow_active_exploit exactly like every other active step.
    exploit_refine_iterations: int = 0

    # Shadow judge: run a SECOND judge alongside the real one and record where
    # they disagree, without ever letting it move a verdict. Empty = off. "llm"
    # re-reads with the validator model at a higher temperature (a baseline that
    # needs no new service); "jev" evaluates TypeSafe AI's Jev, which also needs
    # JEV_BASE_URL / JEV_API_KEY. See app/validation/shadow.py.
    shadow_judge_backend: str = ""

    # Optional cost accounting. Comma-separated 'model=IN/OUT' where IN/OUT are
    # USD per 1M tokens, e.g. "glm-4.6=0.6/2.2,kimi-k2-0905-preview=0.6/2.5".
    # Models not listed (e.g. OpenRouter :free) cost 0; tokens are still tracked.
    llm_pricing: str = ""

    # LLM response-analyst (analysis/llm_recon.py) context budget. The analyst
    # reasons better the more real traffic it sees, so these scale with the
    # model's context window. Defaults are safe for a ~128K-context model;
    # with a long-context model (e.g. Qwen3.8-27B, 262K native) raise them:
    #   LLM_RECON_MAX_FLOWS=200
    #   LLM_RECON_BUDGET_CHARS=600000
    # budget_chars is the hard ceiling on the prompt (~3.5-4 chars per token);
    # flows are added by priority until it is reached.
    llm_recon_max_flows: int = 60
    llm_recon_body_chars: int = 6000
    llm_recon_budget_chars: int = 150_000

    # API authentication. Empty = disabled (loopback-only local use). Set it to
    # require X-API-Key / Authorization: Bearer on every /api route - do that
    # before publishing the API or the proxy beyond 127.0.0.1.
    api_key: str = Field("", validation_alias=AliasChoices("SYPHAX_API_KEY", "API_KEY"))

    # Storage
    data_dir: Path = Path("/data")
    # Postgres + Redis are mandatory from Phase 1 onward. Defaults match the
    # docker-compose service names so a `docker compose up` works out of the box.
    database_url: str = "postgresql://syphax:syphax@postgres:5432/syphax"
    redis_url: str = "redis://redis:6379/0"

    # MITM
    mitm_port: int = 8080

    # ---- Scan identity ----
    # How the tools present themselves on the wire. "rotate" impersonates a
    # different real browser per job, headers included; "fixed" pins the
    # user_agent below. This controls tool fingerprinting, not traceability:
    # the source IP, request rate and payloads are still in the target's logs.
    user_agent_mode: str = "rotate"
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    )
    # OFF by default. When set, every request carries X-Pentest-ID so the
    # client's SOC can tell an authorized test from a real intrusion. Leave it
    # empty to blend in or to test their detection.
    pentest_id: str = ""

    # ---- Network privacy ----
    # Refuse to queue any scan unless the exit IP differs from the pre-VPN one.
    require_vpn: bool = False
    # SOCKS5/HTTP proxy for scan traffic, e.g. socks5://127.0.0.1:9050 (Tor).
    scan_proxy: str = ""
    # WireGuard/OpenVPN config brought up via the API. Needs NET_ADMIN.
    vpn_config_path: str = ""
    vpn_mode: str = "wireguard"  # wireguard | openvpn

    # ---- Fresh start ----
    # Truncate scan artefacts (jobs, findings, flows, events, runs, llm usage)
    # on backend startup so each boot begins clean.
    reset_on_start: bool = False
    # Engagements carry the authorization scope and audit_log is the legal
    # trail of what was run. Both survive a reset unless explicitly included.
    reset_engagements_on_start: bool = False
    reset_audit_on_start: bool = False

    # CORS
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def openrouter_fallback_list(self) -> List[str]:
        return [m.strip() for m in self.openrouter_fallback_models.split(",") if m.strip()]


settings = Settings()
# Best-effort: never crash app import if the data dir isn't creatable (e.g.
# a read-only mount, or a non-root CI runner where "/data" can't be made).
try:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
except OSError:
    pass
