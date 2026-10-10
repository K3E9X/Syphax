"""No tool may drown the run in its own inventory.

gau turned a domain's archive into 2175 findings and 2162 assets. The Findings
page became 2175 rows of archived stylesheets, and since the planner builds one
task per (catalog item x asset), the run spent its entire TIME budget on them
and tested nothing - `time budget reached iteration 8 - 62 jobs`.

Fixing gau's parser fixed gau. katana, ffuf, httpx, subfinder, dnsx and
kiterunner all report one finding per thing they find, with no cap at all, so
the next big target would have reproduced it with a different tool. These pin
the limit where every wrapper's output passes through it.
"""
from __future__ import annotations

import inspect as _inspect
import pathlib

from app.scans.models import Finding
from app.scans.wrappers import _WRAPPERS
from app.scans.wrappers.base import (DEFAULT_FINDING_CAP, FINDING_CAP,
                                     cap_findings)


def _f(severity: str, i: int) -> Finding:
    return Finding(severity=severity, title=f"{severity} finding {i}",
                   description="d", target="https://t.example/", evidence="e",
                   metadata={})


# ---- the rule ------------------------------------------------------------

def test_a_discovery_flood_is_bounded():
    out = cap_findings([_f("info", i) for i in range(3000)],
                       tool="katana", category="recon")
    assert len(out) == FINDING_CAP["recon"] + 1, len(out)


def test_nothing_is_lost_quietly():
    """The count has to survive, or the operator cannot tell a capped job from
    a quiet one."""
    out = cap_findings([_f("info", i) for i in range(3000)],
                       tool="katana", category="recon")
    summary = [f for f in out if (f.metadata or {}).get("capped")]
    assert len(summary) == 1
    assert summary[0].metadata["total"] == 3000
    assert summary[0].metadata["dropped"] == 3000 - FINDING_CAP["recon"]
    assert summary[0].metadata["dropped_by_severity"] == {
        "info": 3000 - FINDING_CAP["recon"]}


def test_a_critical_is_never_dropped():
    """A flood of criticals is a signal, not noise. Losing one to a display
    limit would be far worse than the flood this guards against."""
    flood = ([_f("critical", i) for i in range(500)]
             + [_f("high", i) for i in range(200)]
             + [_f("info", i) for i in range(2000)])
    out = cap_findings(flood, tool="nuclei", category="vuln")
    assert sum(1 for f in out if f.severity == "critical") == 500
    assert sum(1 for f in out if f.severity == "high") == 200


def test_the_most_severe_of_the_rest_are_the_ones_kept():
    flood = ([_f("info", i) for i in range(500)]
             + [_f("medium", i) for i in range(10)]
             + [_f("low", i) for i in range(10)])
    out = cap_findings(flood, tool="x", category="recon", limit=20)
    kept = [f.severity for f in out if not (f.metadata or {}).get("capped")]
    assert kept.count("medium") == 10, kept.count("medium")
    assert kept.count("low") == 10, kept.count("low")


def test_a_job_under_the_cap_is_untouched():
    findings = [_f("info", i) for i in range(5)]
    assert cap_findings(findings, tool="x", category="recon") == findings


def test_an_empty_result_stays_empty():
    assert cap_findings([], tool="x", category="recon") == []


# ---- it is applied where nothing can bypass it ---------------------------

def test_there_is_exactly_one_place_a_wrapper_is_parsed():
    """The cap is only universal because this is. A second call site would be
    a second way to flood the run."""
    root = pathlib.Path(_inspect.getfile(cap_findings)).resolve().parents[3]
    sites = []
    for path in (root / "app").rglob("*.py"):
        if "wrappers" in path.parts:
            continue
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if "wrapper.parse(" in line or ".parse(bytes(" in line:
                sites.append(f"{path.name}:{n}")
    assert len(sites) == 1, f"wrapper.parse is called from several places: {sites}"


def test_the_ingest_caps_what_it_parsed():
    from app import workers

    src = _inspect.getsource(workers)
    assert "cap_findings(" in src, "the one ingest point does not cap"
    assert src.index("wrapper.parse(") < src.index("cap_findings("), \
        "the cap must be applied to what was parsed"


def test_every_wrapper_category_resolves_to_a_cap():
    """An unlisted category silently takes the generous default, which for a
    discovery tool is the flood this file exists to prevent."""
    categories = {w.category for w in _WRAPPERS.values()}
    assert categories, "no wrappers found"
    for category in sorted(categories):
        cap = FINDING_CAP.get(category, DEFAULT_FINDING_CAP)
        assert cap > 0
    # The discovery categories must be the tight ones.
    for category in ("recon", "fingerprint", "content_discovery"):
        assert FINDING_CAP[category] < DEFAULT_FINDING_CAP, category


def test_the_discovery_tools_are_in_a_capped_category():
    """These are the ones with the gau shape: one finding per item found."""
    for name in ("gau", "katana", "ffuf", "httpx", "subfinder", "dnsx",
                 "kiterunner"):
        wrapper = _WRAPPERS[name]
        cap = FINDING_CAP.get(wrapper.category, DEFAULT_FINDING_CAP)
        assert cap <= FINDING_CAP["content_discovery"], (
            f"{name} is category '{wrapper.category}', which takes a cap of "
            f"{cap} - too generous for a tool that reports one finding per "
            f"item it finds")


# ---- and the asset side, which is what actually starved the run ----------

def test_the_asset_ceiling_is_a_safety_valve_not_a_policy():
    """It must sit far above any real application.

    An earlier version capped it at 300, which was wrong: pointing the tool at
    a URL and asking it to find the endpoints and APIs behind it is the job,
    and a site with 2000 endpoints is a site with 2000 endpoints. What decides
    which of them get TESTED is planner.asset_interest and the per-phase budget
    share - not a ceiling on what gets recorded.
    """
    from app.orchestrator.state import MAX_ENDPOINT_ASSETS, EngagementState

    assert MAX_ENDPOINT_ASSETS >= 2000, (
        f"{MAX_ENDPOINT_ASSETS} would trim the surface of a large application")
    src = _inspect.getsource(EngagementState.add_asset)
    assert "MAX_ENDPOINT_ASSETS" in src
    # A parameterised endpoint is an injection point: never capped at all.
    assert "not has_params" in src, \
        "the valve must not apply to endpoints that carry parameters"


def test_the_budget_can_actually_test_a_discovered_surface():
    """200 jobs and 2 hours was enough to map a small site and nothing else -
    a run on a real target ended with `time budget reached` during mapping,
    having proven nothing."""
    from app.orchestrator.loop import (DEFAULT_MAX_JOBS, DEFAULT_MAX_SECONDS,
                                       MAX_ITERATIONS, BATCH_SIZE,
                                       PHASE_BUDGET_SHARE, phase_allowance)

    assert DEFAULT_MAX_JOBS >= 500
    assert DEFAULT_MAX_SECONDS >= 4 * 60 * 60
    # The iteration count must never be the thing that stops a run.
    assert MAX_ITERATIONS * BATCH_SIZE > DEFAULT_MAX_JOBS
    # And exploitation must get a real share of it.
    assert phase_allowance(DEFAULT_MAX_JOBS, "exploitation") >= 100, \
        PHASE_BUDGET_SHARE
