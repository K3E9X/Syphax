"""OpenRouter client (OpenAI-compatible Chat Completions API).

Two public methods:
  - chat()   : single turn, returns the full assistant string.
  - stream() : SSE, yields chunks as they arrive.

Both methods automatically fall back to alternative free models when the
upstream provider returns 429 / 5xx ("temporarily rate-limited", "provider
unavailable", etc.). The fallback chain is:

    [self.model] + settings.openrouter_fallback_list

After a successful call, `self.last_used_model` records which model
actually answered, so the UI can show it.
"""
from __future__ import annotations

import json
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from app.config import settings


class LLMError(RuntimeError):
    pass


# HTTP status codes for which we should try the next model in the chain.
# 429: provider rate-limited. 5xx: provider transient failure.
_FALLBACK_STATUS_CODES = {429, 500, 502, 503, 504}


def _is_temperature_rejection(body: str) -> bool:
    """A 400 where the model refuses the temperature we sent. Reasoning models
    (kimi-k2/k3, some GLM and o-series) only accept their fixed default, e.g.
    'invalid temperature: only 1 is allowed for this model'. We retry without
    the field so one setting does not break every call."""
    b = (body or "").lower()
    return "temperature" in b and (
        "only 1 is allowed" in b
        or "invalid temperature" in b
        or "does not support" in b
        or "unsupported" in b
        or "must be 1" in b
    )


class LLMClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        app_name: Optional[str] = None,
        fallback_models: Optional[List[str]] = None,
        timeout: float = 120.0,
        role: Optional[str] = None,
    ) -> None:
        self.role = role
        self.api_key = api_key or settings.openrouter_api_key
        self.model = model or settings.openrouter_model
        self.base_url = (base_url or settings.openrouter_base_url).rstrip("/")
        self.app_name = app_name or settings.openrouter_app_name
        self.fallback_models = (
            list(fallback_models)
            if fallback_models is not None
            else list(settings.openrouter_fallback_list)
        )
        self.timeout = timeout
        # Updated by chat()/stream() after a successful call.
        self.last_used_model: Optional[str] = None
        # Raw `usage` block from the last response, when the provider sent one.
        self.last_usage: Optional[Dict[str, Any]] = None

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        if not self.configured:
            raise LLMError(
                "OPENROUTER_API_KEY is not set. Put it in .env and restart the backend."
            )
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            # OpenRouter uses these to attribute usage to your app (helps with free tier).
            "HTTP-Referer": "http://localhost",
            "X-Title": self.app_name,
        }

    def _models_chain(self, override: Optional[str]) -> List[str]:
        """Models to try in order. If override is set, it takes precedence and
        no fallback is attempted (caller knows what they want)."""
        if override:
            return [override]
        chain = [self.model] + [m for m in self.fallback_models if m != self.model]
        # Deduplicate while preserving order.
        seen: set = set()
        return [m for m in chain if not (m in seen or seen.add(m))]

    @staticmethod
    def _is_fallback_error(exc: BaseException) -> bool:
        if not isinstance(exc, LLMError):
            return False
        msg = str(exc)
        # Our LLMError messages start with "OpenRouter <status>:"; parse the code.
        for code in _FALLBACK_STATUS_CODES:
            if f"OpenRouter {code}:" in msg:
                return True
        # Some providers return 200 OK with an error envelope; catch a few keywords.
        lowered = msg.lower()
        if "rate-lim" in lowered or "temporarily" in lowered or "provider returned error" in lowered:
            return True
        return False

    async def chat(
        self,
        messages: List[Dict[str, str]],
        *,
        model: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Return the full assistant message. Tries fallback models on 429/5xx."""
        last_exc: Optional[LLMError] = None
        for candidate in self._models_chain(model):
            try:
                reply = await self._chat_once(
                    messages,
                    model=candidate,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                self.last_used_model = candidate
                return reply
            except LLMError as exc:
                last_exc = exc
                if not self._is_fallback_error(exc):
                    raise
        raise last_exc or LLMError("no model in chain succeeded")

    async def _chat_once(
        self,
        messages: List[Dict[str, str]],
        *,
        model: str,
        temperature: float,
        max_tokens: Optional[int],
    ) -> str:
        payload: Dict[str, object] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            # Reasoning models (kimi-k2/k3, some GLM and o-series) reject any
            # temperature other than their fixed default. Drop the field and
            # retry once rather than fail a whole run - or a sanity ping - on it.
            if response.status_code == 400 and _is_temperature_rejection(response.text):
                payload.pop("temperature", None)
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
        if response.status_code >= 400:
            raise LLMError(f"OpenRouter {response.status_code}: {response.text[:500]}")

        data = response.json()
        # Some providers wrap a logical error in a 200 response.
        if isinstance(data, dict) and "error" in data and "choices" not in data:
            raise LLMError(f"OpenRouter error envelope: {json.dumps(data)[:500]}")
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise LLMError(f"Unexpected response shape: {data}") from exc

        await self._record_usage(model, data.get("usage"))
        return content

    async def _record_usage(self, model: str, usage: Optional[Dict[str, Any]]) -> None:
        """Best-effort token/cost accounting against the current engagement."""
        if not isinstance(usage, dict):
            return
        # Kept on the instance so callers (e.g. /api/llm/ping) can report the
        # token counts of the call they just made without a DB round trip.
        self.last_usage = usage
        try:
            from app.llm import usage as usage_mod

            await usage_mod.record(
                role=self.role,
                model=model,
                prompt_tokens=int(usage.get("prompt_tokens") or 0),
                completion_tokens=int(usage.get("completion_tokens") or 0),
                # OpenRouter may include a real cost; otherwise estimate_cost runs.
                cost_usd=usage.get("cost") if isinstance(usage.get("cost"), (int, float)) else None,
            )
        except Exception:  # noqa: BLE001
            pass

    async def stream(
        self,
        messages: List[Dict[str, str]],
        *,
        model: Optional[str] = None,
        temperature: float = 0.2,
    ) -> AsyncIterator[str]:
        """Yield text chunks. Falls back to the next model only if the failure
        happens before any chunk has been yielded; otherwise re-raises so the
        caller does not see duplicated text from two providers."""
        last_exc: Optional[LLMError] = None
        for candidate in self._models_chain(model):
            yielded = False
            try:
                async for chunk in self._stream_once(messages, model=candidate, temperature=temperature):
                    yielded = True
                    yield chunk
                self.last_used_model = candidate
                return
            except LLMError as exc:
                last_exc = exc
                if yielded or not self._is_fallback_error(exc):
                    raise
        raise last_exc or LLMError("no model in chain succeeded")

    async def _stream_once(
        self,
        messages: List[Dict[str, str]],
        *,
        model: str,
        temperature: float,
    ) -> AsyncIterator[str]:
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
        }
        async with httpx.AsyncClient(timeout=None) as client:
            for attempt in (0, 1):
                async with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                ) as response:
                    if response.status_code >= 400:
                        body = await response.aread()
                        # Same temperature-rejection retry as the non-stream path.
                        if (attempt == 0 and response.status_code == 400
                                and _is_temperature_rejection(body.decode(errors="replace"))):
                            payload.pop("temperature", None)
                            continue
                        raise LLMError(f"OpenRouter {response.status_code}: {body.decode()[:500]}")
                    async for line in response.aiter_lines():
                        if not line or not line.startswith("data:"):
                            continue
                        data = line[len("data:"):].strip()
                        if data == "[DONE]":
                            return
                        try:
                            chunk = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content")
                        if delta:
                            yield delta
                    return


_client: Optional[LLMClient] = None


def get_llm() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
