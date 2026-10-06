"""The LLM client must survive reasoning models that only accept their fixed
temperature (kimi-k2/k3, some GLM/o-series): a 400 'invalid temperature' is
retried once without the field instead of failing the call (or the sanity
ping)."""
import json

import pytest

from app.llm import client as mod
from app.llm.client import LLMClient, _is_temperature_rejection


def test_detector_matches_only_temperature_errors():
    assert _is_temperature_rejection(
        '{"error":{"message":"invalid temperature: only 1 is allowed for this model"}}')
    assert _is_temperature_rejection('temperature must be 1 for this model')
    assert not _is_temperature_rejection('{"error":{"message":"invalid api key"}}')
    assert not _is_temperature_rejection('')


class _FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text

    def json(self):
        return json.loads(self.text)


@pytest.mark.asyncio
async def test_retries_without_temperature(monkeypatch):
    sent = []
    scripted = [
        _FakeResp(400, '{"error":{"message":"invalid temperature: only 1 is allowed for this model"}}'),
        _FakeResp(200, '{"choices":[{"message":{"content":"pong"}}],"usage":{}}'),
    ]

    class _FakeAsyncClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            sent.append(dict(json))   # snapshot: the code mutates the payload on retry
            return scripted.pop(0)

    monkeypatch.setattr(mod.httpx, "AsyncClient", _FakeAsyncClient)

    async def _noop_usage(self, *a, **k):
        return None
    monkeypatch.setattr(LLMClient, "_record_usage", _noop_usage)

    llm = LLMClient(api_key="x", model="kimi-k3",
                    base_url="https://api.moonshot.ai/v1", fallback_models=[])
    out = await llm.chat([{"role": "user", "content": "ping"}], temperature=0.0)

    assert out == "pong"
    assert len(sent) == 2                 # one reject, one retry
    assert "temperature" in sent[0]       # first try carried it
    assert "temperature" not in sent[1]   # retry dropped it
