"""A lead on the board must change what the planner actually plans.

The strategist's unit tests prove the advice is right; this proves it ARRIVES.
An advice object that the planner ignores would pass every test in
test_strategist.py and still leave the run behaving exactly as it did before
the blackboard existed - which is the failure mode worth a test of its own.
"""
from __future__ import annotations

import asyncio

from app.methodology import (PHASE_EXPLOIT, PHASE_MAPPING, PHASE_RECON,
                             PHASE_VULN)
from app.orchestrator import blackboard as bb
from app.orchestrator.planner import Planner
from app.orchestrator.state import Asset
from app.orchestrator.strategist import Strategist

# Everything before exploitation, so plan() picks the exploitation phase.
_EARLIER = {PHASE_RECON, PHASE_MAPPING, PHASE_VULN}


class _State:
    engagement_id = "sim"

    def __init__(self, assets):
        self._assets = assets

    async def assets(self, kind=None):
        return [a for a in self._assets if kind is None or a.kind == kind]

    async def technologies(self):
        return []

    async def is_covered(self, item_id, asset_value):
        return False


class _Board:
    """A blackboard with no database behind it."""

    def __init__(self, leads):
        self._leads = leads

    async def leads(self, kind=None):
        return [l for l in self._leads
                if kind is None or l.kind == kind]


def _surface():
    """A dull-looking endpoint the board knows about, and a prettier one it
    does not. asset_interest prefers /admin; the board prefers what answered."""
    return [
        Asset(kind="host", value="t.example", source="engagement"),
        Asset(kind="endpoint", value="https://t.example/", source="engagement",
              is_https=True),
        Asset(kind="endpoint", value="https://t.example/data?ref=7",
              source="katana", is_https=True, has_params=True),
        Asset(kind="endpoint", value="https://t.example/admin/panel?id=1",
              source="ffuf", is_https=True, has_params=True),
    ]


def _lead(kind, value, **data):
    return bb.Lead(id=1, engagement_id="sim", kind=kind, value=value,
                   confidence=0.9, data=data, source="test")


def _plan(advice):
    planner = Planner(_State(_surface()))
    return asyncio.run(planner.plan(max_tasks=6, use_llm=False,
                                    skip_phases=_EARLIER, advice=advice))


def _advice_from(leads):
    s = Strategist(_State(_surface()), board=_Board(leads))
    return asyncio.run(s.advise(use_llm=False))


def test_without_the_board_the_url_heuristic_decides():
    """The baseline the advice has to change.

    The operator's own target outranks everything inferred from it, so the
    root goes first either way. Among the DISCOVERED endpoints the heuristic
    decides, and it prefers /admin/panel - a path that merely looks
    interesting - over /data?ref=7, which nothing has confirmed."""
    batch = _plan(None)
    assert batch, "the exploitation phase produced no tasks at all"
    assert batch[0].asset_value == "https://t.example/"   # the engagement target
    discovered = [t.asset_value for t in batch
                  if t.asset_value != "https://t.example/"]
    assert discovered, "no discovered endpoint was planned at all"
    assert "/admin/panel" in discovered[0]


def test_an_injectable_lead_moves_the_plan_onto_that_asset():
    """A tool already reached /data?ref=7, so that is where the exploit budget
    goes - ahead of the /admin path nothing has confirmed. The engagement's own
    target keeps its place; what changes is the order of what was discovered."""
    advice = _advice_from([_lead(bb.INJECTABLE, "https://t.example/data?ref=7")])
    batch = _plan(advice)
    assert batch
    discovered = [t.asset_value for t in batch
                  if t.asset_value != "https://t.example/"]
    assert discovered, "no discovered endpoint was planned at all"
    assert discovered[0] == "https://t.example/data?ref=7", (
        f"the board named that asset and it was not planned first: {discovered[:3]}")


def test_the_injectable_lead_also_brings_sqlmap_first():
    """Not just WHERE but WHAT: the lead's class order pulls the dedicated
    injection tool ahead of the generic nuclei pass."""
    advice = _advice_from([_lead(bb.INJECTABLE, "https://t.example/data?ref=7")])
    batch = _plan(advice)
    on_the_lead = [t for t in batch
                   if t.asset_value == "https://t.example/data?ref=7"]
    assert on_the_lead
    assert on_the_lead[0].catalog_item_id == "EXP-SQLI", (
        f"expected sqlmap first on the injectable asset, got "
        f"{[t.catalog_item_id for t in on_the_lead[:3]]}")


def test_an_empty_board_leaves_the_plan_identical():
    """The run must behave exactly as before on a target where nothing is
    found - the blackboard may only ever add behaviour."""
    before = [t.key for t in _plan(None)]
    after = [t.key for t in _plan(_advice_from([]))]
    assert before == after


def test_advice_never_promotes_a_task_past_its_phase():
    """The gate invariant, through the real planner: even with exploitation
    advice, a plan that still has recon work returns recon."""
    advice = _advice_from([_lead(bb.INJECTABLE, "https://t.example/data?ref=7")])
    planner = Planner(_State(_surface()))
    batch = asyncio.run(planner.plan(max_tasks=6, use_llm=False, advice=advice))
    assert batch
    assert batch[0].phase == PHASE_RECON


def test_a_credential_lead_reaches_the_planner_as_an_identity():
    """The grey-box bridge: the advice the planner receives carries the
    identity the run acquired, so later steps can scan as that user."""
    advice = _advice_from([
        _lead(bb.CREDENTIAL, "admin@https://t.example/login",
              username="admin", login_url="https://t.example/login")])
    assert advice.identity is not None
    assert advice.identity["username"] == "admin"
    # and the login endpoint it names is now a hot asset
    assert "https://t.example/login" in advice.hot_assets


def test_the_exploitation_phase_is_what_we_think_it_is():
    """Guards the test itself: if PHASE_EXPLOIT were skipped by _EARLIER,
    every assertion above would pass against an empty batch."""
    assert PHASE_EXPLOIT not in _EARLIER
    batch = _plan(None)
    assert all(t.phase == PHASE_EXPLOIT for t in batch)
