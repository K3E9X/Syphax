"""Two things from the OWASP Phase 2 noise finding.

The report gives defenders a signature for an autonomous attacker:
"high-frequency, low-diversity tool invocation against a single target with no
advance in target state". syphax is an authorised tool - it sends an
attribution header on purpose and has no business hiding - so neither of these
is about evasion.

1. The DUPLICATION that produced that signature for free. On a parameterised
   endpoint eight nuclei items all apply, and seven are strict subsets of
   EXP-DAST's untagged run, so the same payloads went out up to eight times
   for the coverage of one. That is wasted run time on a small host first and
   a detection signature second.

2. The MEASUREMENT a client is entitled to: what footprint did this test
   leave, and should their monitoring have seen it?
"""
from __future__ import annotations

import pytest

from app.methodology import CATALOG, CATALOG_BY_ID
from app.methodology.catalog import dast_exclusions
from app.orchestrator.state import Asset
from app.reporting.footprint import collect, summarise


# ---- 1. the catch-all stops re-sending what its siblings send ---------

def _dast_siblings():
    return [i for i in CATALOG
            if "-dast" in i.default_options and i.id != "EXP-DAST"]


def test_the_overlap_was_real():
    """Guards the premise: if the catalog stops having focused -dast items
    that duplicate the catch-all, this whole fix is dead weight."""
    siblings = _dast_siblings()
    assert len(siblings) >= 6, (
        f"only {len(siblings)} focused -dast items; the duplication this "
        "fixes may no longer exist")
    assert CATALOG_BY_ID["EXP-DAST"].default_options == ["-dast"], (
        "the catch-all is no longer untagged, so it may no longer be a "
        "superset of its siblings")


def test_every_excluded_tag_is_covered_by_a_sibling():
    """THE safety property. Excluding a tag nothing else sends would silently
    delete coverage, which is far worse than sending it twice."""
    excluded = set(dast_exclusions())
    assert excluded, "nothing is excluded, so nothing was de-duplicated"
    covered = set()
    for item in _dast_siblings():
        opts = item.default_options
        if "-tags" in opts:
            covered |= {t.strip() for t in opts[opts.index("-tags") + 1].split(",")}
    missing = excluded - covered
    assert not missing, f"excluded but sent by nobody: {sorted(missing)}"


def test_only_siblings_that_always_apply_are_excluded():
    """A sibling gated on a technology or on being the base URL does not run
    everywhere the exclusion does, so excluding its tags would lose coverage
    on every target where that gate is false."""
    excluded = set(dast_exclusions())
    for item in _dast_siblings():
        gate = item.applies_when or {}
        if gate.get("requires_params") or gate.get("always"):
            continue
        opts = item.default_options
        if "-tags" not in opts:
            continue
        theirs = {t.strip() for t in opts[opts.index("-tags") + 1].split(",")}
        assert not (theirs & excluded), (
            f"{item.id} is gated on {gate} but its tags are excluded anyway")


def test_an_endpoint_without_parameters_still_gets_everything():
    """The focused items require parameters; the catch-all does not. Excluding
    unconditionally would leave a plain endpoint with no DAST coverage at
    all."""
    plain = Asset(kind="endpoint", value="https://t/page", is_https=True)
    assert CATALOG_BY_ID["EXP-DAST"].options_for(plain) == ["-dast"]


def test_a_parameterised_endpoint_skips_what_the_siblings_send():
    withparams = Asset(kind="endpoint", value="https://t/p?id=1",
                       is_https=True, has_params=True)
    opts = CATALOG_BY_ID["EXP-DAST"].options_for(withparams)
    assert "-exclude-tags" in opts
    sent = opts[opts.index("-exclude-tags") + 1].split(",")
    assert "ssrf" in sent and "lfi" in sent and "rce" in sent


def test_the_exclusion_is_derived_not_written_out():
    """Written out by hand it would go stale the first time a sibling was
    retagged, and a stale list either restores the overlap or deletes
    coverage."""
    import inspect

    from app.methodology import catalog
    src = inspect.getsource(catalog.dast_exclusions)
    assert "for item in CATALOG" in src
    assert "options_with_params=[]" in inspect.getsource(catalog), (
        "the exclusion should be filled in from the catalog, not inline")


def test_items_without_an_asset_rule_are_untouched():
    """options_for must behave exactly as the old flat copy for everything
    that does not use it."""
    asset = Asset(kind="endpoint", value="https://t/p?id=1", is_https=True,
                  has_params=True)
    for item in CATALOG:
        if item.id == "EXP-DAST":
            continue
        assert item.options_for(asset) == list(item.default_options)


def test_the_planner_asks_per_asset():
    import inspect

    from app.orchestrator import planner
    src = inspect.getsource(planner.Planner._candidate_tasks)
    assert "options_for(asset)" in src
    assert "list(item.default_options)" not in src


# ---- the job id that made the duplication worse -----------------------

def test_two_jobs_in_the_same_millisecond_do_not_collide():
    """The orchestrator launches a whole batch in a tight loop. A bare
    millisecond timestamp is not unique there, and the second insert raised on
    the primary key - losing a task silently."""
    from app.scans.storage import new_job_id
    ids = [new_job_id() for _ in range(5000)]
    assert len(set(ids)) == len(ids)


def test_job_ids_still_sort_by_creation_time():
    import time

    from app.scans.storage import new_job_id
    first = new_job_id()
    time.sleep(0.002)
    assert first < new_job_id()


# ---- 2. the footprint is measured, not invented -----------------------

def test_nothing_is_reported_when_nothing_ran():
    assert summarise({}) == []


def test_it_never_claims_a_request_count_it_cannot_know():
    """Jobs do not record a request count and the wrappers do not report one,
    so any total here would be invented. Only the crawl and probe tools are
    proxied, so the captured figure is a floor and has to say so."""
    import inspect

    from app.reporting import footprint
    src = inspect.getsource(footprint)
    assert "floor" in src
    lines = summarise({
        "jobs": 4, "targets": 2, "jobs_per_target": 2.0,
        "busiest_target": {"target": "https://t/a", "jobs": 3, "tools": ["nuclei"]},
        "concentrated_on": [], "captured_requests": 120,
        "learned": {"assets": 1, "findings": 2, "leads": 0, "total": 3},
        "jobs_per_fact": 1.3})
    assert any("floor, not a total" in ln for ln in lines)


def test_a_hammered_target_is_called_out():
    lines = summarise({
        "jobs": 17, "targets": 7, "jobs_per_target": 2.4,
        "busiest_target": {"target": "https://t/a", "jobs": 11, "tools": ["nuclei"]},
        "concentrated_on": [{"target": "https://t/a", "jobs": 11,
                             "tools": ["nuclei", "sqlmap"]}],
        "captured_requests": 0,
        "learned": {"assets": 0, "findings": 7, "leads": 0, "total": 7},
        "jobs_per_fact": 2.4})
    hit = [ln for ln in lines if "https://t/a" in ln]
    assert hit
    assert "11 invocation(s)" in hit[0]
    assert "defenders are told to look for" in hit[0]


def test_a_spread_out_run_is_not_called_out():
    lines = summarise({
        "jobs": 12, "targets": 12, "jobs_per_target": 1.0,
        "busiest_target": {"target": "https://t/a", "jobs": 1, "tools": ["nuclei"]},
        "concentrated_on": [], "captured_requests": 0,
        "learned": {"assets": 9, "findings": 3, "leads": 1, "total": 13},
        "jobs_per_fact": 0.9})
    assert not any("defenders" in ln for ln in lines)


def test_the_threshold_is_a_named_number():
    from app.reporting.footprint import BUSY_TARGET_JOBS
    assert BUSY_TARGET_JOBS >= 4


def test_the_report_carries_the_section():
    import inspect

    from app.reporting import report
    src = inspect.getsource(report._markdown)
    assert "Test Footprint" in src
    # and the appendix renumbers rather than colliding on "7."
    assert '"## 8. Appendix"' in src
    assert '"## 7. Appendix"' in src


def test_the_report_still_renders_without_a_footprint():
    from app.reporting.report import _markdown

    class _E:
        id = "e"
        target_url = "https://t"
        target_host = "t"
        scope_hosts = ["t"]
        allow_active_exploit = False
        authorized_by = "op"
        created_at = 0
        status = type("S", (), {"value": "authorized"})()

    md = _markdown(_E(), [], [], ["nuclei"], [], [], {}, {}, "low", (), None)
    assert "## 7. Appendix" in md
    assert "Test Footprint" not in md


@pytest.mark.asyncio
async def test_collect_returns_empty_rather_than_raising(monkeypatch):
    """A footprint is never worth failing a report over."""
    from app import db

    def _boom():
        raise RuntimeError("no database")

    monkeypatch.setattr(db, "acquire", _boom)
    assert await collect("nope") == {}


def test_the_diagnosis_shows_the_same_numbers():
    """The operator and the client read one set of figures, from one
    function - two measurements of the same run that disagree are worse than
    one."""
    import inspect

    from app import diagnose_run
    from app.reporting import report
    assert "footprint" in inspect.getsource(diagnose_run._agentic_section)
    assert "footprint" in inspect.getsource(report.build_report)
