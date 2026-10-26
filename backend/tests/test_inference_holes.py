"""The inference layer: three holes the operator was right to suspect.

1. The cross-provider fallback never worked. The fallback models are
   OpenRouter model ids and they were posted to THIS client's base_url with
   THIS client's key - so for a role pointed at Moonshot, a 429 on kimi-k3
   sent `meta-llama/llama-3.3-70b-instruct:free` to api.moonshot.ai, got 400
   "model not found", decided that was not retryable, and raised the 400
   instead of the 429. Three wasted requests and a misleading error, every
   time, and the documented behaviour never happened once.

2. Transport errors were never LLMError. httpx.ReadTimeout - the single most
   common failure a reasoning model at a 120s timeout has - propagated raw, so
   the fallback chain never fired for it AND it escaped the 13 of 19 call
   sites that catch LLMError, including the validator's judge and PoC
   authoring.

3. `content` could be None. A reasoning model answers with content=null and
   the text in reasoning_content; the None went straight to the callers, and a
   parser that does reply.strip() crashes on it rather than degrading.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from app.llm.client import LLMClient, LLMError, _host_of


def _role_client(**kw):
    """A per-role client as router.get() builds one for Kimi on Moonshot."""
    defaults = dict(
        base_url="https://api.moonshot.ai/v1", api_key="sk-moonshot",
        model="kimi-k3",
        fallback_models=["meta-llama/llama-3.3-70b-instruct:free",
                         "openai/gpt-oss-120b:free"],
        fallback_base_url="https://openrouter.ai/api/v1",
        fallback_api_key="sk-or-test", role="planner")
    defaults.update(kw)
    return LLMClient(**defaults)


# ---- 1. the fallback goes to the right provider -----------------------

def test_a_fallback_model_goes_to_openrouter_not_the_role_provider():
    attempts = _role_client()._attempts(None)
    assert attempts[0] == ("https://api.moonshot.ai/v1", "sk-moonshot", "kimi-k3")
    for base, key, model in attempts[1:]:
        assert base == "https://openrouter.ai/api/v1", (
            f"{model} is an OpenRouter model id and was sent to {base}")
        assert key == "sk-or-test"


def test_no_openrouter_key_means_no_pointless_attempts():
    """Three requests that cannot succeed are worse than one honest failure:
    they cost time and they replace the real error with a 400."""
    attempts = _role_client(fallback_api_key="")._attempts(None)
    assert len(attempts) == 1
    assert attempts[0][2] == "kimi-k3"


def test_an_openrouter_client_still_falls_back_across_its_own_models():
    """The behaviour that did work must keep working."""
    c = LLMClient(base_url="https://openrouter.ai/api/v1", api_key="sk-or",
                  model="qwen/qwen3-coder:free",
                  fallback_models=["meta-llama/llama-3.3-70b-instruct:free"],
                  fallback_base_url="https://openrouter.ai/api/v1",
                  fallback_api_key="sk-or")
    attempts = c._attempts(None)
    assert [m for _b, _k, m in attempts] == [
        "qwen/qwen3-coder:free", "meta-llama/llama-3.3-70b-instruct:free"]
    assert {b for b, _k, _m in attempts} == {"https://openrouter.ai/api/v1"}


def test_an_explicit_model_override_tries_only_that_one():
    attempts = _role_client()._attempts("some/other-model")
    assert attempts == [("https://api.moonshot.ai/v1", "sk-moonshot",
                         "some/other-model")]


def test_the_same_model_on_the_same_endpoint_is_not_tried_twice():
    c = _role_client(model="shared", fallback_models=["shared", "other"],
                     fallback_base_url="https://api.moonshot.ai/v1",
                     fallback_api_key="sk-moonshot")
    pairs = [(b, m) for b, _k, m in c._attempts(None)]
    assert len(pairs) == len(set(pairs))


# ---- 2. transport errors are retryable LLMErrors ----------------------

@pytest.mark.parametrize("status,retry", [
    (429, True), (500, True), (502, True), (503, True), (504, True),
    (400, False), (401, False), (403, False), (404, False),
])
def test_which_statuses_earn_another_attempt(status, retry):
    exc = LLMError(f"api.moonshot.ai {status}: x", status=status)
    assert LLMClient._is_fallback_error(exc) is retry


def test_a_timeout_earns_another_attempt():
    """It did not, and it is the most common failure of all."""
    exc = LLMError("transport error: ReadTimeout", transport=True)
    assert LLMClient._is_fallback_error(exc) is True


def test_the_status_is_read_from_the_field_not_the_message():
    """It used to string-match our own message for "OpenRouter <code>:", so
    naming the real provider in the message silently disabled retrying - which
    is what happened while writing this fix."""
    exc = LLMError("something else entirely", status=429)
    assert LLMClient._is_fallback_error(exc) is True


def test_a_transport_failure_is_wrapped_so_callers_catch_it(monkeypatch):
    """13 of 19 call sites catch LLMError only. A raw httpx exception escaped
    all of them - the judge, authoring, refine, the analysers."""
    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _Client())
    c = _role_client(fallback_api_key="")
    with pytest.raises(LLMError) as got:
        asyncio.run(c.chat([{"role": "user", "content": "hi"}]))
    assert got.value.transport is True
    # and the message names the provider that actually failed
    assert "moonshot" in str(got.value)


def test_a_timeout_on_the_primary_actually_reaches_the_fallback(monkeypatch):
    seen = []

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            seen.append((url, json["model"]))
            if json["model"] == "kimi-k3":
                raise httpx.ReadTimeout("timed out")
            return httpx.Response(
                200, json={"choices": [{"message": {"content": "ok"},
                                        "finish_reason": "stop"}]})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _Client())
    c = _role_client()
    out = asyncio.run(c.chat([{"role": "user", "content": "hi"}]))
    assert out == "ok"
    assert seen[0][1] == "kimi-k3"
    assert "moonshot" in seen[0][0]
    # the second attempt went to OpenRouter, with an OpenRouter model
    assert "openrouter" in seen[1][0]
    assert seen[1][1] == "meta-llama/llama-3.3-70b-instruct:free"
    assert c.last_used_provider == "openrouter.ai"


# ---- 3. a reasoning model's reply is never None -----------------------

def _answer(monkeypatch, message, finish="stop"):
    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            return httpx.Response(200, json={
                "choices": [{"message": message, "finish_reason": finish}]})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _Client())
    return asyncio.run(_role_client(fallback_api_key="").chat(
        [{"role": "user", "content": "hi"}]))


def test_a_null_content_becomes_an_empty_string(monkeypatch):
    assert _answer(monkeypatch, {"content": None}) == ""


def test_a_reasoning_model_answer_is_recovered(monkeypatch):
    """kimi-k2/k3 and the GLM thinking models answer with content=null and
    the text in reasoning_content."""
    out = _answer(monkeypatch, {"content": None,
                                "reasoning_content": '{"ordered_keys":[]}'})
    assert out == '{"ordered_keys":[]}'


def test_a_present_content_wins_over_reasoning(monkeypatch):
    out = _answer(monkeypatch, {"content": "the answer",
                                "reasoning_content": "thinking out loud"})
    assert out == "the answer"


def test_a_truncated_reply_is_reported(monkeypatch, caplog):
    """max_tokens is a setting the operator can change, and a cut-off answer
    otherwise looks exactly like a complete one."""
    import logging
    with caplog.at_level(logging.WARNING):
        _answer(monkeypatch, {"content": "half an ans"}, finish="length")
    assert any("truncated" in r.getMessage() for r in caplog.records)
    assert any("max_tokens" in r.getMessage() for r in caplog.records)


def test_a_broken_response_shape_is_still_an_llm_error(monkeypatch):
    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            return httpx.Response(200, json={"nonsense": True})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _Client())
    with pytest.raises(LLMError):
        asyncio.run(_role_client(fallback_api_key="").chat(
            [{"role": "user", "content": "hi"}]))


# ---- the error message names the right provider -----------------------

@pytest.mark.parametrize("base,host", [
    ("https://api.moonshot.ai/v1", "api.moonshot.ai"),
    ("https://openrouter.ai/api/v1", "openrouter.ai"),
    ("https://open.bigmodel.cn/api/paas/v4", "open.bigmodel.cn"),
    ("", ""),
])
def test_the_host_is_what_gets_named(base, host):
    """Every failure used to read "OpenRouter <code>:" whatever the endpoint,
    so a rate limit from Moonshot sent the operator looking in the wrong
    place."""
    assert _host_of(base) == host


# ---- the router hands the fallback its own credentials ----------------

def test_the_router_gives_role_clients_a_real_fallback():
    import inspect

    from app.llm import router as router_mod
    src = inspect.getsource(router_mod)
    assert src.count("fallback_base_url=settings.openrouter_base_url") >= 2
    assert src.count("fallback_api_key=settings.openrouter_api_key") >= 2
