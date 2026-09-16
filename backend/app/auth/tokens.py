"""Session tokens.

Opaque random tokens, not JWTs. A JWT would let the backend validate a session
without touching the database, which sounds like the advantage until you have to
revoke one: the operator clicks "sign out everywhere" and the token they are
worried about keeps working until it expires. This tool holds captured sessions
and an endpoint that brings up a VPN as root; revocation has to be immediate.

Only the SHA-256 of the token is stored. A database dump - the thing an operator
would hand to support, or lose in a snapshot - therefore contains nothing that
can be replayed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from typing import Optional

TOKEN_BYTES = 32                     # 256 bits
COOKIE_NAME = "syphax_session"

# A pentest run is long. Eight hours covers a working day without a re-login in
# the middle of an engagement; the sliding refresh below extends an active
# session, so the ceiling only bites on an idle one.
DEFAULT_TTL_SECONDS = 8 * 3600
# Absolute ceiling: no amount of activity keeps a session alive past this.
MAX_TTL_SECONDS = 7 * 24 * 3600
# Only rewrite expires_at when more than this has elapsed, so a page polling
# every 5s does not write to the sessions table 720 times an hour.
REFRESH_AFTER_SECONDS = 300


def new_token() -> str:
    """A fresh session token. Returned to the client exactly once."""
    return base64.urlsafe_b64encode(os.urandom(TOKEN_BYTES)).decode().rstrip("=")


def fingerprint(token: str) -> str:
    """What the database stores. Deterministic, one-way, no salt: the input is
    already 256 bits of entropy, so there is no dictionary to defend against and
    a salt would only prevent the lookup this has to perform."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def same_token(a: str, b: str) -> bool:
    return hmac.compare_digest(str(a or ""), str(b or ""))


def expiry_from(now: float, ttl: float = DEFAULT_TTL_SECONDS) -> float:
    return float(now) + min(float(ttl), MAX_TTL_SECONDS)


def is_expired(expires_at: Optional[float], now: Optional[float] = None) -> bool:
    """A missing expiry is expired. A session row we cannot reason about must
    not be the one that authorises a request."""
    if expires_at is None:
        return True
    return float(expires_at) <= (time.time() if now is None else float(now))


def should_refresh(expires_at: float, now: float,
                   ttl: float = DEFAULT_TTL_SECONDS) -> bool:
    """True when the sliding window has moved far enough to be worth a write."""
    if is_expired(expires_at, now):
        return False
    elapsed = ttl - (float(expires_at) - float(now))
    return elapsed >= REFRESH_AFTER_SECONDS


def cookie_attributes(*, secure: bool, max_age: int = DEFAULT_TTL_SECONDS) -> dict:
    """Attributes for the session cookie.

    httponly: the token is never readable from JavaScript, so an XSS in a
        findings table - which renders text an attacker controls - cannot read
        it out of document.cookie.
    samesite=lax: the API is state-changing; a cross-site POST must not carry
        the session. Lax rather than Strict so following a link into the UI
        does not land on a login page.
    secure: set when the deployment is served over TLS. Not hardcoded, because
        the default install is plain HTTP on a loopback port and a Secure
        cookie there is silently dropped - which looks exactly like a broken
        login.
    """
    return {
        "key": COOKIE_NAME,
        "httponly": True,
        "samesite": "lax",
        "secure": bool(secure),
        "path": "/",
        "max_age": int(max_age),
    }
