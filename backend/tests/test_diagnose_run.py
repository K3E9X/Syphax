"""The run diagnosis has to classify every catalog item it may meet.

app/selftest.py says what the installation can do; app/diagnose_run.py says
what a run did with it. Both exist because five rounds of inferring causes
from source code, while the answer sat in the database, is a failure of method.

A diagnosis that mislabels a phase is worse than none - it would say "the
exploitation phase ran" about a run that never got there, and send the search
somewhere else again. So the prefix table is pinned against the real catalog.
"""
from __future__ import annotations

import inspect as _inspect

from app.diagnose_run import PHASE_OF_PREFIX, PHASE_ORDER, _phase_of
from app.methodology import PHASE_ORDER as REAL_PHASE_ORDER
from app.methodology.catalog import CATALOG


def test_every_catalog_item_is_classified():
    """A new item with an unknown prefix would be filed as "other" and silently
    dropped out of the phase tally."""
    unclassified = sorted({item.id for item in CATALOG
                           if _phase_of(item.id) == "other"})
    assert not unclassified, (
        f"these would not be counted in any phase: {unclassified}. Add the "
        f"prefix to PHASE_OF_PREFIX.")


def test_each_item_is_filed_under_the_phase_it_actually_belongs_to():
    """The prefix is a convention, not a guarantee. If an item's id says MAP
    and its phase is exploitation, the diagnosis lies about how far the run
    got - which is the single thing it exists to answer."""
    wrong = [(item.id, item.phase, _phase_of(item.id)) for item in CATALOG
             if _phase_of(item.id) != item.phase]
    assert not wrong, (
        "id prefix disagrees with the declared phase for: "
        + "; ".join(f"{i} is {p} but reads as {guess}" for i, p, guess in wrong))


def test_the_phase_order_matches_the_methodology():
    assert PHASE_ORDER == list(REAL_PHASE_ORDER)


def test_the_prefix_table_covers_every_phase():
    assert set(PHASE_OF_PREFIX.values()) == set(REAL_PHASE_ORDER)


def test_the_diagnosis_leads_with_the_phase_that_was_never_reached():
    """Nothing downstream of the planner can matter until that changes, so it
    is said first rather than buried under per-tool detail."""
    from app import diagnose_run

    src = _inspect.getsource(diagnose_run.run)
    assert "never planned an exploitation task" in src
    assert src.index('if "exploitation" not in reached') < \
        src.index("every phase was planned"), \
        "the blocking case must be the first branch"


def test_it_separates_a_tool_that_failed_from_one_that_found_nothing():
    """Different causes, different fixes: a non-zero exit is a tool or argument
    problem, a clean run with no findings points at the output parser."""
    from app import diagnose_run

    src = _inspect.getsource(diagnose_run.run)
    assert "ran and found nothing" in src
    assert "FAILED" in src
    assert "output parser is the next suspect" in src


def test_it_only_reads():
    """Safe to run against a live engagement."""
    from app import diagnose_run

    src = _inspect.getsource(diagnose_run)
    for write in ("INSERT", "UPDATE ", "DELETE", "DROP", "ALTER"):
        assert write not in src.upper().replace("UPDATE_TEMPLATES", ""), write
