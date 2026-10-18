"""router.status() must report the client a role will actually use.

Regression guard: status() used to read the .env values (_role_config), so a
role whose key was set in the UI (saved in the DB, applied via reconfigure())
showed up as configured=false / OpenRouter fallback / env base_url - while the
run was really calling the configured provider and billing it. The dashboard
read "my model is not wired" when it was.
"""
from __future__ import annotations

from app.llm.router import ROLE_EXECUTOR, ROLE_PLANNER, LLMRouter


def test_status_reflects_a_reconfigured_role_and_a_fallback_role():
    r = LLMRouter()
    # Planner configured at runtime (as the UI would, via the DB -> reconfigure).
    r.reconfigure(ROLE_PLANNER, base_url="https://api.moonshot.ai/v1",
                  api_key="sk-test-key", model="kimi-k3")
    # Executor left to the OpenRouter fallback (empty key drops the role).
    r.reconfigure(ROLE_EXECUTOR, base_url="", api_key="", model="")

    s = r.status()

    assert s[ROLE_PLANNER]["configured"] is True
    assert s[ROLE_PLANNER]["using_openrouter_fallback"] is False
    assert s[ROLE_PLANNER]["base_url"] == "https://api.moonshot.ai/v1"
    assert s[ROLE_PLANNER]["model"] == "kimi-k3"

    assert s[ROLE_EXECUTOR]["using_openrouter_fallback"] is True
    assert s[ROLE_EXECUTOR]["configured"] is False
