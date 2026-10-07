"""The planner must never turn a "port" surface asset into a scan target.

Regression: port assets (value "80/tcp . host . svc") were fed to tools as
targets; the scope gate parsed the host as the port number and blocked every
task out of scope, so a whole run did nothing. Port assets are display-only;
the host they belong to is already its own asset.
"""
import pytest

from app.orchestrator.planner import Planner
from app.orchestrator.state import Asset


class _FakeState:
    engagement_id = "eng_test"

    async def is_covered(self, item_id, asset_value):
        return False


@pytest.mark.asyncio
async def test_port_assets_are_not_scanned():
    planner = Planner(_FakeState())
    assets = [
        Asset(kind="host", value="prospex.example", is_https=True),
        Asset(kind="port", value="443/tcp · prospex.example · https nginx"),
        Asset(kind="port", value="80/tcp · 51.159.110.74 · http"),
    ]
    tasks = await planner._candidate_tasks(assets, tech=[])
    # No task may target a port-asset value.
    for t in tasks:
        assert "/tcp" not in t.asset_value, f"port asset became a target: {t.asset_value}"
        assert "·" not in t.asset_value


@pytest.mark.asyncio
async def test_host_asset_still_produces_tasks():
    planner = Planner(_FakeState())
    tasks = await planner._candidate_tasks(
        [Asset(kind="host", value="prospex.example", is_https=True)], tech=[])
    # The host itself is still scanned (sanity: the skip did not nuke everything).
    assert tasks
    assert all(t.asset_value == "prospex.example" for t in tasks)
