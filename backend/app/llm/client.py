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
import logging
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from app.config import settings

logger = logging.getLogger("syphax.llm.client")


class LLMError(RuntimeError):
    """A provider call that did not produce an answer.

    Carries the HTTP status (when there was one) and whether it was a
    transport failure, so deciding "is this worth another attempt?" is a field
    lookup. It used to be decided by string-matching our own message for
    "OpenRouter <code>:" - which silently stopped working the moment the
    message started naming the real provider instead.
    """

    def __init__(self, message: str, *, status: Optional[int] = None,
                 transport: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.transport = transport


# HTTP status codes for which we should try the next model in the chain.
# 429: provider rate-limited. 5xx: provider transient failure.
_FALLBACK_STATUS_CODES = {429, 500, 502, 503, 504}

# Marker on an LLMError raised from a transport failure - a timeout, a reset
# connection, a DNS failure. These used to propagate as raw httpx exceptions,
# which had two consequences and both were bad: the fallback chain never fired
# for the single most common failure a reasoning model has (a 120s read
# timeout), and the exception escaped every caller that catches LLMError -
# thirteen of nineteen call sites, including the validator's judge and PoC
# authoring. Wrapping them here fixes all of them at once.
_TRANSPORT_PREFIX = "transport error:"


def _host_of(base_url: str) -> str:
    """The provider's host, for an error message that names the right one.

    Every failure used to be reported as "OpenRouter <code>:" whatever the
    endpoint, so a rate limit from Moonshot read as an OpenRouter problem and
    sent the operator looking in the wrong place.
    """
    try:
        from urllib.parse import urlparse
        return urlparse(str(base_url or "")).hostname or str(base_url or "")
    except Exception:  # noqa: BLE001
        return str(base_url or "")


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
        fallback_base_url: Optional[str] = None,
        fallback_api_key: Optional[str] = None,
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
        # Where the fallback models live. They are OpenRouter model ids, so
        # they need OpenRouter's endpoint and key - not this client's. See
        # _attempts() for what went wrong when they did not have them.
        self.fallback_base_url = (fallback_base_url
                                  or settings.openrouter_base_url).rstrip("/")
        self.fallback_api_key = (fallback_api_key
                                 if fallback_api_key is not None
                                 else settings.openrouter_api_key)
        self.timeout = timeout
        # Updated by chat()/stream() after a successful call.
        self.last_used_model: Optional[str] = None
        # Which provider actually answered. With a working cross-provider
        # fallback this is no longer always the configured one, and an
        # operator reading the token panel needs to know that.
        self.last_used_provider: Optional[str] = None
        # Raw `usage` block from the last response, when the provider sent one.
        self.last_usage: Optional[Dict[str, Any]] = None

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _headers(self, api_key: Optional[str] = None) -> Dict[str, str]:
        """Headers for one attempt. The key is per-attempt because a fallback
        attempt goes to a different provider with a different key."""
        key = api_key or self.api_key
        if not key:
            raise LLMError(
                "OPENROUTER_API_KEY is not set. Put it in .env and restart the backend."
            )
        return {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            # OpenRouter uses these to attribute usage to your app (helps with free tier).
            "HTTP-Referer": "http://localhost",
            "X-Title": self.app_name,
        }

    def _models_chain(self, override: Optional[str]) -> List[str]:
        """The model names this client would try, in order. Kept for callers
        and tests that only care about the names; chat() uses _attempts(),
        which also knows WHERE each one lives."""
        return [model for _base, _key, model in self._attempts(override)]

    def _attempts(self, override: Optional[str]) -> List[tuple]:
        """(base_url, api_key, model) to try in order.

        The fallback models are OpenRouter model ids. They were being posted to
        THIS client's base_url with THIS client's key - so for a role pointed
        at Moonshot, a 429 on kimi-k3 sent `meta-llama/llama-3.3-70b-instruct:
        free` to api.moonshot.ai, got 400 "model not found", decided that was
        not retryable, and raised the 400 instead of the 429. The documented
        cross-provider fallback never happened once; it only ever cost three
        wasted requests and a misleading error.

        They travel with their own endpoint and key now. If this client already
        IS the OpenRouter client, or there is no OpenRouter key to fall back
        to, the chain is just this provider's own model.
        """
        if override:
            return [(self.base_url, self.api_key, override)]
        attempts = [(self.base_url, self.api_key, self.model)]

        fb_base = (self.fallback_base_url or "").rstrip("/")
        fb_key = self.fallback_api_key or ""
        same_provider = not fb_base or fb_base == self.base_url
        if fb_key and not same_provider:
            for model in self.fallback_models:
                attempts.append((fb_base, fb_key, model))
        elif same_provider and fb_key:
            # An OpenRouter client falling back to other OpenRouter models:
            # same endpoint, different model, which is what already worked.
            for model in self.fallback_models:
                if model != self.model:
                    attempts.append((self.base_url, self.api_key, model))

        seen: set = set()
        out = []
        for base, key, model in attempts:
            if (base, model) in seen:
                continue
            seen.add((base, model))
            out.append((base, key, model))
        return out

    @staticmethod
    def _is_fallback_error(exc: BaseException) -> bool:
        if not isinstance(exc, LLMError):
            return False
        # A timeout or a dropped connection is the most transient thing there
        # is, so it is exactly what the next attempt exists for.
        if getattr(exc, "transport", False):
            return True
        status = getattr(exc, "status", None)
        if status in _FALLBACK_STATUS_CODES:
            return True
        msg = str(exc)
        # A safety net for LLMErrors raised elsewhere without a status set.
        for code in _FALLBACK_STATUS_CODES:
            if f" {code}:" in msg:
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
        for base_url, api_key, candidate in self._attempts(model):
            try:
                reply = await self._chat_once(
                    messages,
                    model=candidate,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    base_url=base_url,
                    api_key=api_key,
                )
                self.last_used_model = candidate
                self.last_used_provider = _host_of(base_url)
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
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> str:
        base_url = (base_url or self.base_url).rstrip("/")
        api_key = api_key or self.api_key
        payload: Dict[str, object] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        url = f"{base_url}/chat/completions"
        headers = self._headers(api_key)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, headers=headers, json=payload)
                # Reasoning models (kimi-k2/k3, some GLM and o-series) reject
                # any temperature other than their fixed default. Drop the
                # field and retry once rather than fail a whole run - or a
                # sanity ping - on it.
                if response.status_code == 400 and _is_temperature_rejection(response.text):
                    payload.pop("temperature", None)
                    response = await client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            # Timeouts, resets, DNS, TLS. Named so _is_fallback_error can see
            # it, and so the message says which provider actually failed.
            raise LLMError(
                f"{_TRANSPORT_PREFIX} {exc.__class__.__name__} talking to "
                f"{_host_of(base_url)}: {exc}", transport=True) from exc
        if response.status_code >= 400:
            raise LLMError(f"{_host_of(base_url)} {response.status_code}: "
                           f"{response.text[:500]}",
                           status=response.status_code)

        data = response.json()
        # Some providers wrap a logical error in a 200 response.
        if isinstance(data, dict) and "error" in data and "choices" not in data:
            raise LLMError(f"OpenRouter error envelope: {json.dumps(data)[:500]}")
        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError) as exc:
            raise LLMError(f"Unexpected response shape: {data}") from exc

        # A reasoning model can answer with content=null and put the text in
        # reasoning_content - kimi-k2/k3 and the GLM thinking models do. The
        # raw None was handed straight to the callers, and a parser that does
        # reply.strip() crashes on it rather than degrading.
        content = message.get("content")
        if not (content or "").strip():
            for alt in ("reasoning_content", "reasoning"):
                if str(message.get(alt) or "").strip():
                    content = message[alt]
                    break
        content = content or ""

        # The reply hit the token ceiling. Saying so matters because it is a
        # setting the operator can change, and because a truncated answer
        # otherwise looks exactly like a complete one.
        if str(choice.get("finish_reason") or "") == "length":
            logger.warning(
                "[%s] %s truncated its reply at the token limit (model=%s); "
                "raise max_tokens for this role if its answers look cut off",
                self.role or "llm", _host_of(base_url), model)

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
