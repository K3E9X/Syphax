"""Deleting an engagement, and the invariant that nothing is left behind.

`close` only flips a status: the findings stay, and every aggregate view keeps
mixing them with the next target's. That is how a stale exposed `.git` from
yesterday ends up next to today's scan.

The risk in a delete is not the DELETE, it is missing a table - a partial purge
leaves rows that still surface in those aggregate views and nothing fails
loudly. So the coverage is read from the registered schemas rather than
restated here.
"""
import pytest

import app.main  # noqa: F401 - importing registers every table's schema
from app import db
from app.engagements.purge import (
    ENGAGEMENT_TABLES,
    KEPT_ON_PURPOSE,
    tables_with_engagement_id,
    uncovered_tables,
)


def test_the_schemas_are_registered():
    """Without this the invariant below would pass vacuously."""
    assert len(db._schemas) > 10


def test_every_engagement_scoped_table_is_accounted_for():
    """The invariant. A table added later with an engagement_id column must be
    purged or explicitly kept - it cannot quietly survive a delete and keep
    showing rows for a target the operator removed."""
    missing = uncovered_tables(db._schemas)
    assert missing == [], (
        f"tables with an engagement_id that neither purge nor are kept: {missing}. "
        "Add them to ENGAGEMENT_TABLES, or to KEPT_ON_PURPOSE with a reason.")


def test_the_detector_actually_finds_tables():
    found = tables_with_engagement_id(db._schemas)
    for expected in ("validated_findings", "chains", "coverage", "assets",
                     "runs", "events", "approvals", "llm_usage"):
        assert expected in found, f"{expected} carries engagement_id but was not detected"


def test_the_detector_ignores_tables_without_the_column():
    found = tables_with_engagement_id(db._schemas)
    # finding_triage is keyed by dedup, settings is a single global row.
    assert "settings" not in found
    assert "finding_triage" not in found


@pytest.mark.parametrize("table", ["audit_log", "lessons"])
def test_what_survives_is_a_documented_decision(table):
    """Both are kept on purpose, and the reason is written down: the audit
    trail is the record of what was authorised, the memory is learning about a
    kind of stack rather than this engagement's data."""
    assert table in KEPT_ON_PURPOSE
    assert len(KEPT_ON_PURPOSE[table]) > 20
    assert table not in ENGAGEMENT_TABLES


def test_findings_are_purged_before_the_engagement_row():
    """Ordering matters: children first, so a failure cannot orphan rows whose
    parent is already gone."""
    assert "validated_findings" in ENGAGEMENT_TABLES
    assert "chains" in ENGAGEMENT_TABLES
    assert "engagements" not in ENGAGEMENT_TABLES   # handled last, separately


def test_no_table_is_listed_twice():
    assert len(ENGAGEMENT_TABLES) == len(set(ENGAGEMENT_TABLES))
    assert not (set(ENGAGEMENT_TABLES) & set(KEPT_ON_PURPOSE))


def test_the_delete_endpoint_exists_and_is_a_delete():
    from app.api.engagements import router
    routes = {(tuple(sorted(r.methods)), r.path) for r in router.routes
              if getattr(r, "methods", None)}
    assert (("DELETE",), "/api/engagements/{engagement_id}") in routes
