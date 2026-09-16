"""The provider catalog, and the check that stops a run this install cannot drive.

The failure this replaces was quiet and expensive: a fresh install started a
run, every LLM call raised because no key was set, the loop caught it, emitted
one "degraded" event, and the operator watched a twenty-minute run that could
only ever print a scanner's raw output. The verdict now happens before the run.
"""
from __future__ import annotations

import pytest

from app.llm import providers, readiness

ZAI = "https://api.z.ai/api/paas/v4"


def role(base_url="", model="", api_key=""):
    return {"base_url": base_url, "model": model, "api_key": api_key}


def all_roles(**kw):
    return {r: role(**kw) for r in providers.ROLES}


# ---- the catalog ------------------------------------------------------------

def test_every_provider_is_openai_compatible_and_reachable_as_written():
    """`custom` is the only entry allowed to have no base URL - it is the one
    the operator fills in."""
    for p in providers.CATALOG:
        assert p.id and p.label
        if p.id == providers.CUSTOM:
            assert p.base_url == ""
        else:
            assert p.base_url.startswith("https://"), p.id
            assert p.models, f"{p.id} offers no model to start from"


def test_the_ids_a_key_can_be_stored_under_cover_the_whole_catalog():
    assert set(providers.provider_ids()) == {p.id for p in providers.CATALOG}
    assert "custom" in providers.provider_ids(), \
        "a key for an unrecognised endpoint has to be storable somewhere"


def test_each_role_has_a_default_and_a_note_explaining_what_it_costs():
    for r in providers.ROLES:
        assert providers.ROLE_NOTES.get(r)
        assert providers.DEFAULT_ASSIGNMENT.get(r) in providers.BY_ID


def test_base_url_maps_to_the_right_stored_key():
    assert providers.provider_for_base_url(ZAI) == "zai"
    assert providers.provider_for_base_url("https://api.moonshot.ai/v1") == "moonshot"
    assert providers.provider_for_base_url("https://api.moonshot.cn/v1") == "moonshot"
    assert providers.provider_for_base_url("https://api.deepseek.com/v1") == "deepseek"
    assert providers.provider_for_base_url("https://openrouter.ai/api/v1") == "openrouter"


def test_an_unknown_endpoint_gets_its_own_bucket_not_someone_elses_key():
    assert providers.provider_for_base_url("https://llm.internal/v1") == providers.CUSTOM
    assert providers.provider_for_base_url("") == ""


# ---- readiness --------------------------------------------------------------

def test_a_fresh_install_is_not_ready_and_says_so_in_one_sentence():
    r = readiness.evaluate({})
    assert not r.ready
    assert r.missing == list(providers.ROLES)
    assert "No LLM provider is configured" in r.summary
    assert readiness.blocking_message(r)


def test_three_configured_roles_are_ready():
    r = readiness.evaluate(all_roles(base_url=ZAI, model="glm-5.2", api_key="k"))
    assert r.ready and r.missing == []
    assert readiness.blocking_message(r) is None
    assert all(s.source == readiness.SOURCE_DIRECT for s in r.roles)
    assert all(s.provider == "zai" for s in r.roles)


def test_a_key_with_no_model_is_not_a_working_role():
    """Two out of three is a 401 or a 400 at the first call, not a warning."""
    r = readiness.evaluate(all_roles(base_url=ZAI, model="", api_key="k"))
    assert not r.ready
    assert all("no model selected" in s.problems for s in r.roles)


def test_a_key_with_no_endpoint_is_not_a_working_role():
    r = readiness.evaluate(all_roles(base_url="", model="glm-5.2", api_key="k"))
    assert not r.ready
    assert all("no endpoint URL" in s.problems for s in r.roles)


def test_a_model_with_no_key_is_not_a_working_role():
    r = readiness.evaluate(all_roles(base_url=ZAI, model="glm-5.2", api_key=""))
    assert not r.ready
    assert all("no API key" in s.problems for s in r.roles)
    assert all(s.source == readiness.SOURCE_NONE for s in r.roles)


def test_one_unconfigured_role_blocks_and_is_named():
    cfg = all_roles(base_url=ZAI, model="glm-5.2", api_key="k")
    cfg["validator"] = role()
    r = readiness.evaluate(cfg)
    assert not r.ready
    assert r.missing == ["validator"]
    assert "validator" in r.summary


def test_a_role_the_caller_forgot_to_pass_is_unconfigured_not_skipped():
    cfg = all_roles(base_url=ZAI, model="glm-5.2", api_key="k")
    del cfg["planner"]
    r = readiness.evaluate(cfg)
    assert not r.ready and r.missing == ["planner"]


def test_the_openrouter_fallback_counts_but_only_when_it_has_a_key():
    ready = readiness.evaluate(
        all_roles(), fallback_key="or-key",
        fallback_base_url="https://openrouter.ai/api/v1",
        fallback_model="qwen/qwen3-coder:free")
    assert ready.ready
    assert all(s.source == readiness.SOURCE_FALLBACK for s in ready.roles)

    # The shape that used to pass for "configured": a fallback with no key.
    not_ready = readiness.evaluate(
        all_roles(), fallback_key="",
        fallback_base_url="https://openrouter.ai/api/v1",
        fallback_model="qwen/qwen3-coder:free")
    assert not not_ready.ready


def test_a_configured_role_is_not_dragged_down_by_the_fallback_having_no_key():
    cfg = all_roles()
    cfg["planner"] = role(ZAI, "glm-5.2", "k")
    r = readiness.evaluate(cfg)
    assert r.missing == ["executor", "validator"]
    assert r.roles[0].configured


def test_the_blocking_message_names_the_fix_not_the_symptom():
    msg = readiness.blocking_message(readiness.evaluate({}))
    assert "Settings" in msg and "API key" in msg


def test_public_shape_is_what_the_ui_branches_on():
    pub = readiness.evaluate({}).to_public()
    assert set(pub) == {"ready", "missing", "summary", "roles"}
    for r in pub["roles"]:
        assert set(r) >= {"role", "configured", "source", "provider", "model",
                          "problems", "note"}


@pytest.mark.parametrize("role_name", list(providers.ROLES))
def test_each_role_can_use_a_different_provider(role_name):
    cfg = all_roles(base_url=ZAI, model="glm-5.2", api_key="k")
    cfg[role_name] = role("https://api.moonshot.ai/v1", "kimi-k3", "k2")
    r = readiness.evaluate(cfg)
    assert r.ready
    picked = {s.role: s.provider for s in r.roles}
    assert picked[role_name] == "moonshot"


def test_from_router_status_agrees_with_evaluate():
    status = {r: {"configured": True, "base_url": ZAI, "model": "glm-5.2"}
              for r in providers.ROLES}
    assert readiness.from_router_status(status, secrets={}).ready

    unconfigured = {r: {"configured": False, "base_url": "", "model": ""}
                    for r in providers.ROLES}
    assert not readiness.from_router_status(unconfigured, secrets={}).ready
