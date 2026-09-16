"""Operator authentication: accounts, sessions, and the gate in front of /api.

Split so the decisions are testable without a database:
    passwords.py - hashing and what counts as an acceptable password
    tokens.py    - session token generation, storage fingerprint, expiry
    throttle.py  - login backoff
    policy.py    - the whole allow/deny decision, pure
    storage.py   - the only module here that talks to Postgres
"""
from app.auth.policy import Decision, decide, is_guarded
from app.auth.tokens import COOKIE_NAME

__all__ = ["Decision", "decide", "is_guarded", "COOKIE_NAME"]
