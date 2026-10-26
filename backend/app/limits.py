"""How much testing is enough: the coverage caps, in one place.

Every analyser and exploiter had its own hardcoded ceiling - auth-brute sprayed
3 login endpoints, rate_limit checked 2, mass_assignment probed 4 operations,
cve_checks took 6 targets. Each number was reasonable alone and nobody chose
the total, so on a large application the run tested a sliver of the surface and
nothing said which sliver. The operator asked for no limitation on the tests;
this is where that is decided, and it is one setting instead of sixty literals.

    SYPHAX_TEST_DEPTH = standard | deep | exhaustive        (default: deep)

`deep` is the default because the old numbers were not a considered trade-off,
they were defaults nobody revisited. `exhaustive` removes the ceiling entirely:
the only remaining bounds are the engagement's scope, its capability grants and
the run's time budget.

WHAT THIS DOES NOT TOUCH, deliberately. The caps on how much DATA is held in
memory at once - MAX_BODY, MAX_BYTES, MAX_DOC_BYTES, MAX_FLOWS - are not
testing limits, they are what keeps a 2 GB host alive while parsing a few
thousand captured responses. Raising those does not test more, it gets the
worker OOM-killed mid-run and loses everything it had found. They stay where
they are, and they are a different kind of number: one is "how thorough are
we", the other is "how much fits in RAM".

Nor does depth relax a gate. An analyser that probes more endpoints still
needs allow_active_exploit for the writes, still stays in scope, and still
only does what the engagement's capabilities grant. Depth changes how many
times a permitted thing is done, never what is permitted.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger("syphax.limits")

STANDARD = "standard"
DEEP = "deep"
EXHAUSTIVE = "exhaustive"

# How much to multiply a cap by at each depth. `exhaustive` is handled
# separately - it is the absence of a cap, not a very large one.
_FACTOR = {STANDARD: 1, DEEP: 4, EXHAUSTIVE: 0}

DEFAULT_DEPTH = DEEP

# No cap at all. Returned at `exhaustive`, and every caller treats it the way
# it would treat a huge number - there is no branch to forget, because
# `min(n, UNLIMITED)` is wrong in exactly the way `itertools.islice(x, None)`
# is right.
UNLIMITED = 1 << 30


def depth() -> str:
    """The configured depth, read per call so a change needs no restart."""
    raw = str(os.environ.get("SYPHAX_TEST_DEPTH", "") or "").strip().lower()
    if raw in _FACTOR:
        return raw
    if raw:
        logger.warning("SYPHAX_TEST_DEPTH=%r is not one of %s; using %s",
                       raw, sorted(_FACTOR), DEFAULT_DEPTH)
    return DEFAULT_DEPTH


def cap(default: int, *, floor: Optional[int] = None) -> int:
    """Scale one coverage cap to the configured depth.

    `default` is the standard-depth number, kept as the argument so each call
    site still documents what a normal run does. `floor` raises the minimum for
    a cap whose standard value is so small that multiplying it is not enough -
    a 2 becomes an 8 at deep, which is still only 8.
    """
    try:
        base = int(default)
    except (TypeError, ValueError):
        return UNLIMITED
    if base <= 0:
        return UNLIMITED
    level = depth()
    if level == EXHAUSTIVE:
        return UNLIMITED
    scaled = base * _FACTOR.get(level, 1)
    if floor is not None and level != STANDARD:
        scaled = max(scaled, int(floor))
    return scaled


def unlimited() -> bool:
    """True when no coverage cap applies. For the few places that want to say
    so out loud rather than compare against UNLIMITED."""
    return depth() == EXHAUSTIVE


def describe() -> str:
    """One line for the console, so a run says how thorough it was told to be."""
    level = depth()
    if level == EXHAUSTIVE:
        return ("Test depth: exhaustive - no coverage cap. Scope, capability "
                "grants and the time budget are the only bounds.")
    factor = _FACTOR.get(level, 1)
    return (f"Test depth: {level} - coverage caps x{factor}. "
            f"Set SYPHAX_TEST_DEPTH=exhaustive to remove them.")
