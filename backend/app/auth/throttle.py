"""Login throttling.

The password form is the one endpoint an unauthenticated caller can hit as many
times as it likes. PBKDF2 at 600k iterations already costs the attacker ~100ms
per guess, but it costs the server the same - so an unthrottled form is also a
CPU exhaustion primitive. Both problems have the same fix.

Counted per (username, source address). Per-username alone lets one attacker
lock out the operator; per-address alone is defeated by a list of proxies.
Requiring both to match means an attacker spraying one account from many hosts
is slowed per host, and the real operator at their own desk is unaffected by
someone else's failures.

State is in-process on purpose: this backend is a single process per install,
and a lockout that survives a restart would leave the operator locked out of
their own tool with no way in.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Tuple

# Free attempts before any delay. Typos happen.
FREE_ATTEMPTS = 3
# Then back off, capped. The cap matters: an unbounded lockout is a denial of
# service an attacker can trigger against the operator on purpose.
BASE_DELAY_SECONDS = 5
MAX_DELAY_SECONDS = 300
# Failures older than this are forgotten, so yesterday's fat-fingering does not
# add to today's count.
WINDOW_SECONDS = 3600


@dataclass
class Attempts:
    failures: int = 0
    last_failure_at: float = 0.0
    history: list = field(default_factory=list)


_state: Dict[Tuple[str, str], Attempts] = {}


def _key(username: str, source: str) -> Tuple[str, str]:
    return ((username or "").strip().lower(), (source or "").strip())


def lockout_seconds(failures: int) -> int:
    """Delay owed after this many failures inside the window."""
    over = max(0, int(failures) - FREE_ATTEMPTS)
    if over <= 0:
        return 0
    return int(min(MAX_DELAY_SECONDS, BASE_DELAY_SECONDS * (2 ** (over - 1))))


def retry_after(attempts: Attempts, now: float) -> int:
    """Seconds the caller must wait. 0 means they may try now."""
    if attempts is None or attempts.failures <= FREE_ATTEMPTS:
        return 0
    waited = now - attempts.last_failure_at
    owed = lockout_seconds(attempts.failures) - waited
    return int(owed) + 1 if owed > 0 else 0


def _prune(attempts: Attempts, now: float) -> Attempts:
    attempts.history = [t for t in attempts.history if now - t < WINDOW_SECONDS]
    attempts.failures = len(attempts.history)
    if attempts.history:
        attempts.last_failure_at = attempts.history[-1]
    return attempts


def check(username: str, source: str, now: float | None = None) -> int:
    """Seconds to wait before this login may be attempted. 0 = go ahead."""
    now = time.time() if now is None else now
    attempts = _state.get(_key(username, source))
    if attempts is None:
        return 0
    return retry_after(_prune(attempts, now), now)


def record_failure(username: str, source: str, now: float | None = None) -> int:
    """Count a failed login; return the delay now owed."""
    now = time.time() if now is None else now
    key = _key(username, source)
    attempts = _prune(_state.setdefault(key, Attempts()), now)
    attempts.history.append(now)
    attempts.failures = len(attempts.history)
    attempts.last_failure_at = now
    return retry_after(attempts, now)


def record_success(username: str, source: str) -> None:
    """A correct password clears the counter for that pair."""
    _state.pop(_key(username, source), None)


def reset() -> None:
    """Test hook."""
    _state.clear()
