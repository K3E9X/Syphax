"""Helpers for the coverage caps that follow SYPHAX_TEST_DEPTH.

The "is this bounded?" tests used to assert a frozen literal. The invariant
they protect is unchanged and still worth a test - an analyser that WRITES to
a target must not become unbounded by accident - but the number now comes from
app/limits, so they assert two things instead of one:

  * finite at whatever depth the suite runs at, i.e. not unbounded by accident;
  * the documented small value at `standard`, so the trade-off is still
    written down somewhere.

Unbounded is reachable, but only when the operator sets
SYPHAX_TEST_DEPTH=exhaustive, which is a decision rather than an oversight.
"""
from __future__ import annotations

import contextlib
import os

from app.limits import EXHAUSTIVE, STANDARD, UNLIMITED, cap  # noqa: F401


@contextlib.contextmanager
def at_depth(level: str):
    """Run a block with SYPHAX_TEST_DEPTH set, and restore it after."""
    before = os.environ.get("SYPHAX_TEST_DEPTH")
    os.environ["SYPHAX_TEST_DEPTH"] = level
    try:
        yield
    finally:
        if before is None:
            os.environ.pop("SYPHAX_TEST_DEPTH", None)
        else:
            os.environ["SYPHAX_TEST_DEPTH"] = before


def standard(default: int, *, floor: int | None = None) -> int:
    """What this cap is at the standard depth."""
    with at_depth(STANDARD):
        return cap(default, floor=floor)


def is_bounded(value: int) -> bool:
    """Finite - i.e. not unbounded by ACCIDENT.

    At `exhaustive` the absence of a cap is the configured answer, not an
    oversight, so UNLIMITED is correct there. The teeth in these tests are the
    `standard(...)` assertions beside this one: those force the standard depth
    and so hold at every setting.
    """
    from app.limits import depth
    if depth() == EXHAUSTIVE:
        return True
    return isinstance(value, int) and 0 < value < UNLIMITED
