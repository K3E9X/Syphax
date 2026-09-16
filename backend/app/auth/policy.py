"""Who may call what. The whole decision, with no I/O in it.

The old gate (app/api_auth.py) was opt-in: with SYPHAX_API_KEY unset every
request was allowed, which is defensible for a loopback-only tool on a laptop
and indefensible the moment the same stack is installed on a VM. This one is
mandatory. There is no environment variable that turns it off - the only way to
reach the API is to finish setup and sign in, and the only way past that is a
credential someone deliberately created.

The API key gate remains, unchanged in meaning: a machine credential for scripts
and CI. It is now an alternative to a session, not a replacement for having any
authentication at all.

Nothing here touches the database. The caller looks up "is there a user" and
"does this token map to one" and hands both in, which is what makes every branch
below testable without a Postgres.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Optional

# Reachable with no credential at all. Each one is here for a reason that
# survives the question "what does an anonymous caller learn from this?":
#   /api/health       - one word, and the compose healthcheck needs it.
#   /api/auth/status  - whether setup is done and whether you are signed in.
#                       The login page cannot render without it.
#   /api/auth/login   - obviously. Throttled in app/auth/throttle.py.
#   /api/auth/setup   - only while no account exists; see below.
PUBLIC_PATHS = frozenset({
    "/api/health",
    "/api/auth/status",
    "/api/auth/login",
})

# Open only until the first account exists, then permanently closed. Without
# that second half, anyone who can reach the port could add themselves an
# account at any time - which is not a setup page, it is a backdoor.
SETUP_PATHS = frozenset({"/api/auth/setup"})

GUARDED_PREFIXES = ("/api/", "/ws/")

HEADER = "x-api-key"
BEARER_PREFIX = "bearer "

# Reasons, as stable strings, so the UI can branch on them instead of on prose.
REASON_SETUP_REQUIRED = "setup_required"
REASON_ALREADY_SET_UP = "already_set_up"
REASON_NO_CREDENTIAL = "no_credential"
REASON_BAD_CREDENTIAL = "bad_credential"


@dataclass(frozen=True)
class Decision:
    allow: bool
    status: int = 200
    reason: str = ""
    message: str = ""

    @property
    def setup_required(self) -> bool:
        return self.reason == REASON_SETUP_REQUIRED


ALLOW = Decision(allow=True)


def is_guarded(path: str) -> bool:
    """True if this path needs a credential. Static assets and the SPA itself
    are outside the gate: they are served by nginx, and they contain nothing.

    The prefix test runs on the NORMALISED path, not the raw one. `//api/x` does
    not start with `/api/`, so matching the raw string let a second spelling of
    a guarded path through un-gated - and a reverse proxy in front of this will
    happily forward a doubled slash.
    """
    p = normalise(path)
    if p in PUBLIC_PATHS:
        return False
    return any(p == prefix.rstrip("/") or p.startswith(prefix)
               for prefix in GUARDED_PREFIXES)


def normalise(path: str) -> str:
    """Trailing slashes and duplicate slashes must not create a second spelling
    of a guarded path that misses the prefix check."""
    p = "/" + (path or "").strip().strip("/")
    while "//" in p:
        p = p.replace("//", "/")
    return p


def is_setup_path(path: str) -> bool:
    return normalise(path) in SETUP_PATHS


def extract_key(headers, query_key: Optional[str] = None) -> str:
    """Read the machine credential from X-API-Key, Authorization: Bearer, or
    ?key=. The query fallback exists for WebSockets, which cannot carry
    headers on the handshake."""
    if headers is not None:
        direct = headers.get(HEADER) or headers.get(HEADER.title()) or ""
        if direct:
            return str(direct).strip()
        auth = str(headers.get("authorization") or headers.get("Authorization") or "")
        if auth.lower().startswith(BEARER_PREFIX):
            return auth[len(BEARER_PREFIX):].strip()
    return str(query_key or "").strip()


def key_ok(provided: str, expected: str) -> bool:
    """Constant-time. An unset expected key returns False rather than True:
    a bug that reaches here without a configured key must fail closed."""
    if not expected or not provided:
        return False
    return hmac.compare_digest(str(provided), str(expected))


def decide(*, path: str, has_users: bool, session_user: Optional[dict] = None,
           provided_key: str = "", expected_key: str = "") -> Decision:
    """The gate.

    `has_users`     - is there at least one account (setup finished)?
    `session_user`  - the user this request's session cookie resolves to, if any.
                      The caller has already checked expiry.
    `provided_key`  - the machine credential on this request, if any.
    `expected_key`  - the configured SYPHAX_API_KEY, empty when unset.
    """
    if is_setup_path(path):
        if has_users:
            return Decision(False, 409, REASON_ALREADY_SET_UP,
                            "setup has already been completed; sign in instead")
        return ALLOW

    if not is_guarded(path):
        return ALLOW

    if not has_users:
        return Decision(False, 401, REASON_SETUP_REQUIRED,
                        "no operator account exists yet; complete setup first")

    if session_user is not None:
        return ALLOW

    if expected_key and provided_key:
        if key_ok(provided_key, expected_key):
            return ALLOW
        return Decision(False, 401, REASON_BAD_CREDENTIAL, "invalid API key")

    return Decision(False, 401, REASON_NO_CREDENTIAL,
                    "sign in, or send a valid X-API-Key")
