"""API key authentication.

The tool holds the operator's captured sessions, their provider keys, and an
endpoint that runs wg-quick as root. Binding to loopback is the first control;
this is the second, for when the API is deliberately exposed (a VM, a phone
pointed at the proxy, a remote browser).

Opt-in by design: with SYPHAX_API_KEY unset every request is allowed, so an
existing local setup keeps working untouched. Set the variable and the whole
/api surface requires it.

The decision logic is pure and unit-tested; main.py only wires it as middleware.
"""
from __future__ import annotations

import hmac
from typing import Optional

# Reachable without a key. Deliberately tiny:
#   /api/health  - the compose healthcheck and the UI's "backend up" badge; it
#                  returns nothing but a status word.
EXEMPT_PATHS = frozenset({"/api/health"})

# Only paths under these prefixes are guarded at all.
GUARDED_PREFIXES = ("/api/",)

HEADER = "x-api-key"
BEARER_PREFIX = "bearer "


def is_guarded(path: str) -> bool:
    """True if this path needs a key (when one is configured)."""
    p = (path or "").rstrip("/") or "/"
    if p in EXEMPT_PATHS or path in EXEMPT_PATHS:
        return False
    return any((path or "").startswith(prefix) for prefix in GUARDED_PREFIXES)


def extract_key(headers, query_key: Optional[str] = None) -> str:
    """Read the key from X-API-Key, then Authorization: Bearer, then ?key=.

    The query fallback exists for WebSockets: browsers cannot set headers on a
    WebSocket handshake.
    """
    if headers is not None:
        direct = headers.get(HEADER) or headers.get(HEADER.title()) or ""
        if direct:
            return str(direct).strip()
        auth = str(headers.get("authorization") or headers.get("Authorization") or "")
        if auth.lower().startswith(BEARER_PREFIX):
            return auth[len(BEARER_PREFIX):].strip()
    return str(query_key or "").strip()


def key_ok(provided: str, expected: str) -> bool:
    """Constant-time comparison. An unset expected key means auth is disabled,
    which is decided by the caller - this returns False so a bug that reaches
    here with no expected key cannot accidentally authorise."""
    if not expected or not provided:
        return False
    return hmac.compare_digest(str(provided), str(expected))


def authorize(path: str, headers, expected: str,
              query_key: Optional[str] = None) -> bool:
    """Whole decision: may this request proceed?"""
    if not expected:
        return True              # auth disabled
    if not is_guarded(path):
        return True
    return key_ok(extract_key(headers, query_key), expected)
