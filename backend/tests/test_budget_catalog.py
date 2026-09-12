"""Budget guardrail and the standalone methodology catalog.

The budget tests pin down the distinction the UI depends on: a $0 figure can
mean "cheap" or "LLM_PRICING is unset and nothing is being measured", and those
must not look the same on screen.
"""
from __future__ import annotations

import pytest

from app.config import settings


@pytest.fixture
def clean_pricing():
    saved = settings.llm_pricing
    yield
    settings.llm_pricing = saved


# ---- Cost accounting ----

def test_unpriced_model_costs_zero(clean_pricing):
    from app.llm.usage import estimate_cost

    settings.llm_pricing = ""
    assert estimate_cost("kimi-k3", 1_000_000, 100_000) == 0.0


def test_priced_model_costs_what_the_provider_charges(clean_pricing):
    from app.llm.usage import estimate_cost

    settings.llm_pricing = "kimi-k3=3.0/15.0,glm-5.2=1.4/4.4"
    # 1M input at $3 + 100k output at $15 = 3.00 + 1.50
    assert estimate_cost("kimi-k3", 1_000_000, 100_000) == pytest.approx(4.50)
    # 1M input at $1.40 + 100k output at $4.40 = 1.40 + 0.44
    assert estimate_cost("glm-5.2", 1_000_000, 100_000) == pytest.approx(1.84)


def test_a_model_missing_from_the_price_list_is_free_not_an_error(clean_pricing):
    """Silently costing 0 is why the dashboard needs the `priced` flag."""
    from app.llm.usage import estimate_cost

    settings.llm_pricing = "kimi-k3=3.0/15.0"
    assert estimate_cost("some-other-model", 5_000_000, 1_000_000) == 0.0


def test_malformed_pricing_entries_are_skipped(clean_pricing):
    from app.llm.usage import _price_map

    settings.llm_pricing = "good=1.0/2.0,broken,alsobroken=x/y,other=3.0/4.0"
    assert _price_map() == {"good": (1.0, 2.0), "other": (3.0, 4.0)}


# ---- Budget threshold ----

@pytest.mark.parametrize("limit,spend,expected_over", [
    (0, 500.0, False),      # 0 disables the cap entirely
    (100.0, 42.0, False),
    (100.0, 100.0, True),   # reaching the cap counts as over
    (100.0, 250.0, True),
])
def test_budget_over_threshold(limit, spend, expected_over):
    # This used to recompute the rule inline, so deleting the dashboard's whole
    # budget block left it green. Exercise the real function instead.
    from app.api.dashboard import budget_exceeded
    assert budget_exceeded(limit, spend) is expected_over


def test_budget_pct_handles_no_cap():
    from app.api.dashboard import budget_pct
    assert budget_pct(0, 12.0) == 0          # no cap -> no percentage
    assert budget_pct(20.0, 5.0) == 25
    assert budget_pct(20.0, 30.0) == 150     # over 100 is meaningful, not clamped


def test_budget_defaults_are_off():
    from app.settings_store import DEFAULTS

    assert DEFAULTS["budget"]["monthly_usd"] == 0
    assert DEFAULTS["budget"]["per_engagement_usd"] == 0


def test_settings_api_accepts_budget():
    """Regression: a field missing from SettingsPatch is silently dropped.

    Skipped in CI, which installs only the pure-logic test dependencies and
    deliberately leaves FastAPI out.
    """
    pytest.importorskip("fastapi")
    from app.api.settings import SettingsPatch

    patch = SettingsPatch(budget={"monthly_usd": 50})
    assert patch.model_dump()["budget"] == {"monthly_usd": 50}


# ---- Standalone catalog ----
# These exercise catalog_entries() rather than the endpoint, so they run in CI
# without the web stack. The endpoint is a one-line wrapper over it.

def test_catalog_carries_grouping_labels():
    """The catalog view groups items itself, so it needs the same category
    labels the coverage view uses - otherwise the two screens disagree."""
    from app.coverage_util import catalog_entries
    from app.methodology import CATALOG

    entries = catalog_entries(CATALOG)
    assert entries
    for item in entries:
        assert item["wstg_category"], f"{item['id']} has no wstg_category"
        assert item["category"], f"{item['id']} has no category label"


def test_catalog_labels_match_the_coverage_view():
    from app.coverage_util import (WSTG_CAT, catalog_entries, coverage_groups,
                                   wstg_prefix)
    from app.methodology import CATALOG

    for item in catalog_entries(CATALOG):
        prefix = wstg_prefix(item["wstg_id"])
        assert item["category"] == WSTG_CAT.get(prefix, ("Other", "Recon"))[0]

    # And the labels the coverage view actually renders are the same set.
    coverage_labels = {g["cat"] for g in coverage_groups(CATALOG, [], set())}
    assert {i["category"] for i in catalog_entries(CATALOG)} == coverage_labels


def test_catalog_covers_every_item_in_the_engine():
    from app.coverage_util import catalog_entries
    from app.methodology import CATALOG

    assert {i["id"] for i in catalog_entries(CATALOG)} == {i.id for i in CATALOG}
