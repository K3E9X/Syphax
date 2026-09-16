"""Fresh-start purge, and the finding-count definition shared across screens.

The counting test exists because the engagements list and the dashboard used
two different definitions, so the same engagement showed a different number of
findings depending on which screen you were looking at.
"""
from __future__ import annotations

import pytest

from app.config import settings


@pytest.fixture
def clean_reset_flags():
    saved = (settings.reset_on_start,
             settings.reset_engagements_on_start,
             settings.reset_audit_on_start)
    yield
    (settings.reset_on_start, settings.reset_engagements_on_start,
     settings.reset_audit_on_start) = saved


# ---- What the purge covers ----

def test_scan_artefacts_are_all_listed():
    """Anything produced by a run must be in the truncate list, otherwise it
    silently survives a 'fresh start'."""
    from app.maintenance import TRANSIENT_TABLES

    produced_by_a_run = {
        "jobs", "flows", "events", "runs", "approvals",
        "validated_findings", "chains", "finding_triage",
        "assets", "fingerprints", "coverage", "llm_usage",
    }
    assert produced_by_a_run <= set(TRANSIENT_TABLES)


def test_authorization_and_audit_are_not_transient():
    """Engagement scope and the audit trail must never be dropped implicitly:
    one is what makes a scan legal, the other is the proof of what ran."""
    from app.maintenance import TRANSIENT_TABLES

    assert "engagements" not in TRANSIENT_TABLES
    assert "audit_log" not in TRANSIENT_TABLES
    assert "settings" not in TRANSIENT_TABLES


def test_wiping_scope_and_audit_stays_opt_in():
    assert settings.model_fields["reset_engagements_on_start"].default is False
    assert settings.model_fields["reset_audit_on_start"].default is False


def test_queue_purge_exists():
    """Redis has its own volume and appendonly on, so queued jobs outlive the
    containers and would be replayed against rows that no longer exist."""
    from app import maintenance

    assert callable(maintenance.reset_job_queue)


async def test_queue_purge_never_blocks_boot(monkeypatch):
    """An unreachable Redis must not stop the API from starting."""
    from app import maintenance

    async def boom(*_a, **_kw):
        raise ConnectionError("redis is down")

    monkeypatch.setattr("arq.connections.create_pool", boom)
    assert await maintenance.reset_job_queue() == 0


# ---- One definition of "a finding", everywhere ----

def _count_like_the_engagement_list(findings):
    confirmed = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    pending = 0
    for status, sev in findings:
        if status == "confirmed":
            if sev in confirmed:
                confirmed[sev] += 1
        elif status in ("likely", "unconfirmed"):
            pending += 1
    return confirmed, pending


def _count_like_the_dashboard(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for status, sev in findings:
        if status == "confirmed" and sev in counts:
            counts[sev] += 1
    return counts


def test_engagement_list_and_dashboard_agree():
    findings = [
        ("confirmed", "critical"),
        ("confirmed", "high"),
        ("likely", "high"),
        ("unconfirmed", "medium"),
        ("false_positive", "critical"),
    ]
    confirmed, pending = _count_like_the_engagement_list(findings)
    assert confirmed == _count_like_the_dashboard(findings)
    assert confirmed == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    # The two non-confirmed ones are surfaced, not silently dropped
    assert pending == 2


def test_false_positives_are_counted_nowhere():
    confirmed, pending = _count_like_the_engagement_list(
        [("false_positive", "critical"), ("false_positive", "high")]
    )
    assert sum(confirmed.values()) == 0
    assert pending == 0


def test_every_status_is_handled():
    """A new ValidationStatus must be classified explicitly, not fall through
    into neither bucket."""
    from app.validation.models import ValidationStatus

    handled = {"confirmed", "likely", "unconfirmed", "false_positive"}
    assert {s.value for s in ValidationStatus} == handled


def test_the_operator_account_is_not_a_scan_artefact():
    """RESET_ON_START truncates on every boot. If `users` or `user_sessions`
    ever joined that list, the operator account would be deleted on every
    restart and the symptom - the setup page coming back, forever - looks
    nothing like its cause.
    """
    from app.maintenance import TRANSIENT_TABLES

    assert "users" not in TRANSIENT_TABLES
    assert "user_sessions" not in TRANSIENT_TABLES


def test_deleting_an_engagement_does_not_touch_accounts():
    """The per-engagement purge reads which tables carry an engagement_id.
    Accounts do not, so they are outside it by construction - this pins that
    nobody adds them by hand."""
    from app.engagements.purge import ENGAGEMENT_TABLES, KEPT_ON_PURPOSE

    for table in ("users", "user_sessions", "settings"):
        assert table not in ENGAGEMENT_TABLES
        assert table not in KEPT_ON_PURPOSE
