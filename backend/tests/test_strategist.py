"""The strategist: what the blackboard says, turned into what to run next.

The core is pure (_from_leads, _strategy_rank, _parse_advice), so it is tested
directly. The model pass is tested for its constraint - it may reorder, never
invent or shorten.
"""
from __future__ import annotations

import pytest

from app.methodology import CATALOG, CATALOG_BY_ID
from app.orchestrator import blackboard as bb
from app.orchestrator.planner import Task, _strategy_rank
from app.orchestrator.strategist import (LEAD_CHAIN, Advice, Strategist,
                                         _parse_advice)


def _lead(kind, value="https://t/x", *, conf=0.8, data=None, lid=1):
    return bb.Lead(id=lid, engagement_id="e", kind=kind, value=value,
                   confidence=conf, data=data or {})


class _State:
    engagement_id = "e"

    async def technologies(self):
        return ["nginx"]


def _strategist():
    return Strategist(_State())


# ---- the invariant that catches the silent typo -----------------------

def test_every_chained_class_exists_in_the_catalog():
    """A class name here that no catalog item carries advises nothing - it is
    silent, so it is checked. This is the same class of bug as a wrong
    vuln_class string anywhere else in the planner."""
    real = {item.vuln_class.lower() for item in CATALOG}
    for kind, classes in LEAD_CHAIN.items():
        for cls in classes:
            assert cls in real, (
                f"LEAD_CHAIN[{kind!r}] advises {cls!r}, which no catalog item "
                f"has. Known classes: {sorted(real)}")


def test_every_identity_kind_is_chained():
    """The grey-box bridge is the whole point: an identity that unlocks
    nothing would be found and then wasted."""
    for kind in bb.IDENTITY_KINDS:
        assert LEAD_CHAIN.get(kind), f"{kind} grants identity but unlocks nothing"


# ---- the deterministic core -------------------------------------------

def test_an_injectable_lead_pulls_the_injection_classes_first():
    advice = _strategist()._from_leads([_lead(bb.INJECTABLE, "https://t/p?id=1")])
    assert advice.chase_classes[0] == "sql_injection"
    assert "xss" in advice.chase_classes
    assert "https://t/p?id=1" in advice.hot_assets


def test_a_credential_lead_becomes_the_identity():
    advice = _strategist()._from_leads([
        _lead(bb.CREDENTIAL, "admin@https://t/login",
              data={"username": "admin", "login_url": "https://t/login"})])
    assert advice.identity is not None
    assert advice.identity["kind"] == bb.CREDENTIAL
    assert advice.identity["username"] == "admin"
    # the url carried in the lead's data is a hot asset too
    assert "https://t/login" in advice.hot_assets


def test_a_session_outranks_a_credential_as_the_identity():
    """A live session needs no replay, so it is the better thing to scan as."""
    advice = _strategist()._from_leads([
        _lead(bb.CREDENTIAL, "admin@x", lid=1),
        _lead(bb.SESSION, "cookie-abc", lid=2),
    ])
    assert advice.identity["kind"] == bb.SESSION
    assert advice.identity["lead_id"] == 2


def test_the_strongest_kind_leads_whatever_the_insertion_order():
    """A confirmed injection point outranks a freshly earned session.

    The order used to come from the board's own sort, so between two equally
    confident leads it was an accident of insertion - and a session (a wide new
    surface, but not yet a finding) would push sqlmap on a CONFIRMED hole down
    the list. Chasing the identity's classes later costs nothing: adopt_identity
    authenticates the run regardless of this order.
    """
    session = _lead(bb.SESSION, "sid=1", lid=9, conf=0.95)
    inject = _lead(bb.INJECTABLE, "https://t/p?id=1", lid=1, conf=0.95)
    for order in ([session, inject], [inject, session]):
        advice = _strategist()._from_leads(order)
        assert advice.chase_classes[0] == "sql_injection", (
            f"got {advice.chase_classes[:3]} for insertion order "
            f"{[l.kind for l in order]}")


def test_confidence_still_decides_within_one_kind():
    weak = _lead(bb.CVE, "CVE-1", conf=0.3, lid=1)
    strong = _lead(bb.CVE, "CVE-2", conf=0.9, lid=2)
    advice = _strategist()._from_leads([weak, strong])
    assert advice.chase_classes[0] == "cve"


def test_every_kind_the_chain_knows_has_a_priority():
    """A kind missing from KIND_PRIORITY sorts last by accident rather than by
    decision - the exact bug this table exists to remove."""
    from app.orchestrator.strategist import KIND_PRIORITY
    for kind in LEAD_CHAIN:
        assert kind in KIND_PRIORITY, f"{kind} chains to classes but has no priority"


def test_an_unknown_lead_kind_is_simply_ignored():
    """A producer may post any string; an unmapped kind must not break advice."""
    advice = _strategist()._from_leads([_lead("something_new", "v")])
    assert advice.chase_classes == []
    assert advice.is_empty


def test_no_leads_means_empty_advice():
    advice = Advice()
    assert advice.is_empty
    assert advice.to_public()["has_identity"] is False


def test_the_rationale_names_what_is_on_the_board():
    advice = _strategist()._from_leads([_lead(bb.INJECTABLE, "u")])
    assert "injectable" in advice.rationale
    assert "sql_injection" in advice.rationale


def test_public_advice_never_carries_the_identity_material():
    """to_public feeds the UI and the prompt; the credential stays out of it."""
    advice = _strategist()._from_leads([
        _lead(bb.CREDENTIAL, "admin@x", data={"username": "admin",
                                              "password": "hunter2"})])
    pub = advice.to_public()
    assert pub["has_identity"] is True
    assert "hunter2" not in repr(pub)
    assert "password" not in repr(pub)


# ---- the planner rank --------------------------------------------------

def _task(item_id, asset="https://t/a"):
    item = CATALOG_BY_ID[item_id]
    return Task(catalog_item_id=item_id, asset_value=asset, tool=item.tool,
                options=[], phase=item.phase)


def test_a_hot_asset_outranks_a_prettier_url():
    """The board beats the URL heuristic: /api/v2 that ANSWERED outranks
    /admin that was merely guessed from a wordlist."""
    advice = Advice(hot_assets={"https://t/api/v2/orders"})
    hot = _task("EXP-SQLI", "https://t/api/v2/orders")
    pretty = _task("EXP-SQLI", "https://t/admin/login?id=1")
    ranked = sorted([pretty, hot], key=lambda t: _strategy_rank(t, advice))
    assert ranked[0] is hot


def test_the_chased_class_goes_first_within_the_phase():
    advice = Advice(chase_classes=["xss"])
    xss = _task("EXP-XSS")
    sqli = _task("EXP-SQLI")
    ranked = sorted([sqli, xss], key=lambda t: _strategy_rank(t, advice))
    assert ranked[0].catalog_item_id == "EXP-XSS"


def test_advice_never_reorders_across_phases():
    """loop.py gates the approval checkpoint on batch[0].phase, so advice that
    could promote an exploitation task above a recon one would break the
    gate - not just the order."""
    advice = Advice(chase_classes=["sql_injection"], hot_assets={"https://t/a"})
    exp = _task("EXP-SQLI", "https://t/a")
    recon = _task("RECON-SUBDOMAINS", "t")
    ranked = sorted([exp, recon], key=lambda t: _strategy_rank(t, advice))
    assert ranked[0].phase == recon.phase


def test_an_unknown_class_sorts_last_not_first():
    """ValueError on .index() must mean 'not chased', never 'rank 0'."""
    advice = Advice(chase_classes=["xss"])
    chased = _strategy_rank(_task("EXP-XSS"), advice)
    other = _strategy_rank(_task("EXP-SQLI"), advice)
    assert chased < other


# ---- the model pass is constrained ------------------------------------

@pytest.mark.parametrize("reply,expected", [
    ('{"ordered_classes":["xss","sql_injection"]}', ["xss", "sql_injection"]),
    ('```json\n{"ordered_classes":["xss"]}\n```', ["xss"]),
    ('Sure! {"ordered_classes":["xss"],"rationale":"reflected"}', ["xss"]),
    ('["xss","cve"]', ["xss", "cve"]),
    ('not json at all', []),
    ('', []),
])
def test_advice_replies_parse_or_yield_nothing(reply, expected):
    got, _ = _parse_advice(reply)
    assert got == expected


def test_a_truncated_reply_still_yields_what_it_said():
    got, _ = _parse_advice('{"ordered_classes":["xss","sql_injection",')
    assert "xss" in got


@pytest.mark.asyncio
async def test_the_model_cannot_invent_a_class():
    s = _strategist()
    advice = Advice(chase_classes=["xss", "sql_injection"])

    class _C:
        configured = True

        async def chat(self, *a, **k):
            return '{"ordered_classes":["rce","xss"]}'

    import app.orchestrator.strategist as mod
    s_router = mod.get_router
    mod.get_router = lambda: type("R", (), {"get": lambda self, r: _C()})()
    try:
        out = await s._llm_reorder(advice, [_lead(bb.INJECTABLE)])
    finally:
        mod.get_router = s_router
    # 'rce' was not a candidate, so it is dropped; nothing is lost.
    assert "rce" not in out.chase_classes
    assert out.chase_classes == ["xss", "sql_injection"]


@pytest.mark.asyncio
async def test_the_model_cannot_shorten_the_run():
    """A class the model omits is appended, not dropped: it reprioritises
    what is tried first, it never makes a class unreachable."""
    s = _strategist()
    advice = Advice(chase_classes=["xss", "sql_injection", "cve"])

    class _C:
        configured = True

        async def chat(self, *a, **k):
            return '{"ordered_classes":["cve"]}'

    import app.orchestrator.strategist as mod
    s_router = mod.get_router
    mod.get_router = lambda: type("R", (), {"get": lambda self, r: _C()})()
    try:
        out = await s._llm_reorder(advice, [_lead(bb.CVE)])
    finally:
        mod.get_router = s_router
    assert out.chase_classes[0] == "cve"
    assert set(out.chase_classes) == {"xss", "sql_injection", "cve"}


@pytest.mark.asyncio
async def test_an_unconfigured_model_leaves_the_chain_order():
    s = _strategist()
    advice = Advice(chase_classes=["xss", "cve"])

    class _C:
        configured = False

    import app.orchestrator.strategist as mod
    s_router = mod.get_router
    mod.get_router = lambda: type("R", (), {"get": lambda self, r: _C()})()
    try:
        out = await s._llm_reorder(advice, [_lead(bb.CVE)])
    finally:
        mod.get_router = s_router
    assert out.chase_classes == ["xss", "cve"]
