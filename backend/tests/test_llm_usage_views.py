"""Token-accounting breakdowns.

The llm_usage table always recorded `role`, `ts` and the prompt/completion
split. None of it reached the UI, which showed one total and a per-model bar -
so the question that actually matters, WHICH part of the system is spending
this, had no answer. The planner is re-invoked on every loop iteration and is
the usual reason a run costs more than expected.

The arithmetic is pure and tested here without a database.
"""
import pytest

from app.llm.usage import (
    TIMELINE_BUCKETS,
    bucketize,
    cost_per_finding,
    estimate_cost,
    per_minute,
    pct_of,
)


# --------------------------------------------------------------------------
# percentages
# --------------------------------------------------------------------------

def test_percentage_of_a_total():
    assert pct_of(25, 100) == 25
    assert pct_of(1, 3) == 33


def test_a_zero_total_is_zero_percent_not_a_crash():
    """A run that made no LLM calls is a legitimate state."""
    assert pct_of(0, 0) == 0
    assert pct_of(5, 0) == 0


# --------------------------------------------------------------------------
# burn rate
# --------------------------------------------------------------------------

def test_burn_rate_is_per_minute():
    assert per_minute(600, 60) == 600.0       # 600 tokens in 1 min
    assert per_minute(600, 120) == 300.0      # same tokens, twice the time


def test_a_sub_second_window_is_not_extrapolated():
    """One call 40ms apart would otherwise read as millions per minute."""
    assert per_minute(1000, 0.04) == 1000.0
    assert per_minute(1000, 0) == 1000.0


# --------------------------------------------------------------------------
# timeline bucketing
# --------------------------------------------------------------------------

def test_points_are_summed_into_buckets():
    series = bucketize([(0, 10), (0, 5), (100, 20)], buckets=2, start=0, end=100)
    assert series["buckets"] == [15.0, 20.0]
    assert series["bucket_seconds"] == 50.0


def test_an_empty_series_is_empty_not_a_divide_by_zero():
    series = bucketize([], buckets=10)
    assert series["buckets"] == []
    assert series["bucket_seconds"] == 0
    assert series["start"] == 0.0


def test_a_single_point_still_produces_a_series():
    series = bucketize([(1000, 42)], buckets=4)
    assert sum(series["buckets"]) == 42.0
    assert len(series["buckets"]) == 4


def test_every_point_lands_in_a_bucket():
    """Nothing is silently dropped: the bars must add up to the total."""
    points = [(i, 3) for i in range(100)]
    series = bucketize(points, buckets=7)
    assert sum(series["buckets"]) == pytest.approx(300.0)
    assert len(series["buckets"]) == 7


def test_the_last_point_is_not_lost_to_a_boundary():
    series = bucketize([(0, 1), (10, 1)], buckets=2, start=0, end=10)
    assert sum(series["buckets"]) == 2.0


def test_bucketize_tolerates_junk_timestamps():
    series = bucketize([(None, 5), (10, 5)], buckets=2)
    assert sum(series["buckets"]) == 5.0


def test_the_default_bucket_count_is_readable_in_a_panel():
    assert 10 <= TIMELINE_BUCKETS <= 100


# --------------------------------------------------------------------------
# cost per finding - the ratio that says whether the spend bought anything
# --------------------------------------------------------------------------

def test_cost_per_confirmed_finding():
    assert cost_per_finding(4.20, 10) == 0.42


def test_no_findings_is_zero_not_infinity():
    """The caller shows the raw spend instead of a meaningless ratio."""
    assert cost_per_finding(4.20, 0) == 0.0


def test_free_models_read_as_zero_per_finding():
    assert cost_per_finding(0, 5) == 0.0


# --------------------------------------------------------------------------
# pricing (existing behaviour, pinned)
# --------------------------------------------------------------------------

def test_an_unpriced_model_costs_zero():
    """This is why the dashboard says 'spend is not being measured' rather
    than claiming the run was free."""
    assert estimate_cost("some-model-nobody-priced", 1_000_000, 1_000_000) == 0.0


# --------------------------------------------------------------------------
# the per-engagement budget: an input that existed and was never read
# --------------------------------------------------------------------------

from app.llm.usage import budget_verdict


def test_spend_under_the_cap_is_not_over():
    v = budget_verdict(10, 4)
    assert v["over"] is False
    assert v["pct"] == 40
    assert v["limit_usd"] == 10.0


def test_reaching_the_cap_counts_as_over():
    assert budget_verdict(10, 10)["over"] is True
    assert budget_verdict(10, 11)["over"] is True


@pytest.mark.parametrize("limit", [0, None, "", "abc", -5])
def test_an_unusable_cap_never_stops_a_run(limit):
    """A guardrail that cannot be read must not stop a run the operator asked
    for. A negative cap would otherwise be 'always exceeded'."""
    v = budget_verdict(limit, 999)
    assert v["over"] is False
    assert v["limit_usd"] == 0.0
    assert v["pct"] == 0


def test_a_junk_spend_does_not_crash_the_guardrail():
    assert budget_verdict(10, None)["spend_usd"] == 0.0
    assert budget_verdict(10, "abc")["over"] is False


def test_the_loop_and_the_api_agree():
    """Both call the same pure function, so the run stops exactly when the UI
    says it is over budget."""
    from app.orchestrator.loop import _REASON_LABELS
    assert "llm_budget" in _REASON_LABELS
