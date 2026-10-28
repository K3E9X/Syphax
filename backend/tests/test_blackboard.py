"""The shared exploitation blackboard - the coordination backbone.

Pure-logic tests (no DB): what a lead is, what grants identity, how a value is
redacted for the UI, and the well-known kinds. The post/dedup/read round-trip
against real Postgres is in tests/live/test_blackboard_roundtrip.py.
"""
from __future__ import annotations

from app.orchestrator import blackboard as bb
from app.orchestrator.blackboard import (CREDENTIAL, IDENTITY_KINDS,
                                         PRIVILEGE, SECRET, SESSION,
                                         UNAUTH_ENDPOINT, Lead)


def _lead(kind, value="x", **kw):
    return Lead(id=1, engagement_id="e", kind=kind, value=value, **kw)


def test_identity_kinds_are_the_grey_box_bridge():
    """Credentials, secrets, sessions, privileges are what the run can act AS
    that it did not start with. Those grant identity; a reachable endpoint or
    an injectable param does not."""
    for kind in (CREDENTIAL, SECRET, SESSION, PRIVILEGE):
        assert _lead(kind).grants_identity
        assert kind in IDENTITY_KINDS
    for kind in (UNAUTH_ENDPOINT, "injectable", "cve", "host"):
        assert not _lead(kind).grants_identity


def test_an_identity_value_is_redacted_in_public_view():
    """The board proves the run HAS a credential; it does not reprint it."""
    pub = _lead(CREDENTIAL, "admin:S3cretP@ss").to_public()
    assert pub["value"] == "admin:****"
    assert "S3cret" not in pub["value"]
    # a token is shortened, not shown whole
    tok = _lead(SECRET, "AKIAIOSFODNN7EXAMPLE").to_public()
    assert tok["value"] != "AKIAIOSFODNN7EXAMPLE"
    assert tok["value"].startswith("AKI")


def test_a_non_identity_value_is_shown_in_full():
    """An operator needs the actual endpoint to act on it."""
    pub = _lead(UNAUTH_ENDPOINT, "https://t/api/v1/users").to_public()
    assert pub["value"] == "https://t/api/v1/users"
    assert pub["grants_identity"] is False


def test_redact_handles_short_and_plain_values():
    assert bb._redact("abc") == "****"
    assert bb._redact("ab") == "****"
    out = bb._redact("longishtoken123")
    assert out.startswith("lon") and out.endswith("23") and "…" in out


def test_row_to_lead_tolerates_bad_json():
    class _R(dict):
        pass
    row = {"id": 5, "engagement_id": "e", "kind": "secret", "value": "v",
           "data_json": "{not json", "source": "s", "confidence": 0.7,
           "consumed_by_json": None, "created_at": 1.0}
    lead = bb._row_to_lead(row)
    assert lead.data == {} and lead.consumed_by == []
    assert lead.kind == "secret" and lead.confidence == 0.7


def test_to_public_rounds_confidence_and_lists_consumers():
    lead = _lead("host", "h.example", confidence=0.8333, source="subfinder",
                 consumed_by=["recon-agent"])
    pub = lead.to_public()
    assert pub["confidence"] == 0.83
    assert pub["consumed_by"] == ["recon-agent"]
    assert pub["source"] == "subfinder"


# ---- the producers post their chainable facts to the board ------------

def test_auth_brute_posts_working_credentials():
    """A password that was accepted is the run's new identity - it must reach
    the board so the grey-box scanners can use it."""
    import inspect

    from app.exploit import auth_brute
    src = inspect.getsource(auth_brute.run_auth_spray)
    assert "Blackboard" in src
    assert "CREDENTIAL" in src
    assert "board.post(" in src


def test_api_inventory_posts_unauthenticated_endpoints():
    import inspect

    from app.analysis import api_inventory
    src = inspect.getsource(api_inventory.analyze_api_inventory)
    assert "UNAUTH_ENDPOINT" in src
    assert "board.post(" in src


def test_producers_never_let_the_board_fail_their_scan():
    """Posting is an enhancement; a board error must not fail the analyser."""
    import inspect

    from app.analysis import api_inventory
    from app.exploit import auth_brute
    for fn in (auth_brute.run_auth_spray, api_inventory.analyze_api_inventory):
        src = inspect.getsource(fn)
        block = src[src.index("Blackboard"):]
        assert "except Exception" in block


def test_the_schema_is_registered_at_import():
    """init_db must create the leads table, or every post fails."""
    from app import db
    from app.orchestrator import blackboard  # noqa: F401
    assert any("CREATE TABLE IF NOT EXISTS leads" in s for s in db._schemas)


def test_the_state_endpoint_carries_the_board():
    """The agentic layer was invisible: syphax grew a blackboard, a strategist
    reading it and a consumption loop, and the only way to see any of it was a
    psql prompt. The route existed and nothing called it.

    It rides on /state rather than needing its own fetch, so it refreshes with
    the rest of the run's working state."""
    import inspect

    from app.api import orchestrator
    src = inspect.getsource(orchestrator.engagement_state)
    assert "Blackboard" in src
    assert '"leads": leads' in src
    # and a board failure never takes the state view down with it
    block = src[src.index("Blackboard"):]
    assert "except Exception" in block


def test_the_state_view_shows_only_the_redacted_values():
    """to_public(), not the raw lead: an identity value must not reach the
    browser just because it travelled through a different endpoint."""
    import inspect

    from app.api import orchestrator
    src = inspect.getsource(orchestrator.engagement_state)
    assert "lead.to_public()" in src
