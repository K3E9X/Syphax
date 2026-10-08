"""The path from "a PoC worked" to "the finding says confirmed".

An independent review traced run_engagement_loop end to end and found the chain
itself sound - and then found that in a normal install nothing could satisfy
all of its gates at once. These are the regression tests for each link it
broke on. They are grouped here because the defect they share is a class, not a
bug: every one of them made a run do nothing and say nothing about it.
"""
from __future__ import annotations

import inspect as _inspect
from types import SimpleNamespace

import pytest


# ---- #4: the banner the operator actually reads ----------------------------

def test_the_validation_banner_is_emitted_from_live_counts():
    """`stats` is captured before run_campaign, the cloud-credential probe, the
    judge and the payload prober - and all four move verdicts. Emitting that
    dict meant the one line the operator reads said "0 confirmed" on a run that
    had just confirmed several, while the dashboard (which queries live)
    disagreed with it."""
    from app.orchestrator import loop

    src = _inspect.getsource(loop)
    captured = src.index("stats = await validate_engagement(engagement.id)")
    campaign = src.index("await run_campaign(engagement.id)")
    emitted = src.index("f\"Validated: {final_stats.get('confirmed',0)} confirmed")
    assert captured < campaign < emitted, "ordering changed; re-check this test"
    # The emitted numbers must be re-read AFTER the phases that change them.
    reread = src.index("final_stats = await _VFRepo().summary(engagement.id)")
    assert campaign < reread < emitted, \
        "the banner must count what the exploitation phase left behind"


# ---- #5: a finding keeps its id across re-validation -----------------------

def test_a_findings_id_survives_revalidation():
    """replace_for_engagement is DELETE + INSERT. With a time-and-random id
    every re-validation renamed every row, so staged_pocs.finding_id dangled:
    a PoC that then ran clean wrote its proof against a row that no longer
    existed - exit 0, nothing confirmed, no event, no log."""
    from app.validation.storage import stable_vf_id

    first = stable_vf_id("eng_1", "nuclei", "CVE-2021-41773 path traversal",
                         "https://app.example.com")
    again = stable_vf_id("eng_1", "nuclei", "CVE-2021-41773 path traversal",
                         "https://app.example.com")
    assert first == again, "the id must not change between runs"
    assert first.startswith("vf_")


def test_two_engagements_against_one_host_do_not_collide():
    """id is a PRIMARY KEY across the whole table."""
    from app.validation.storage import stable_vf_id

    a = stable_vf_id("eng_a", "nuclei", "same title", "https://app.example.com")
    b = stable_vf_id("eng_b", "nuclei", "same title", "https://app.example.com")
    assert a != b


def test_validation_uses_the_stable_id():
    from app.validation import run as vrun

    src = _inspect.getsource(vrun.validate_engagement)
    assert "stable_vf_id(" in src
    assert "new_vf_id()" not in src, \
        "a fresh random id here orphans every staged PoC pointing at the row"


def test_staged_pocs_follow_a_finding_that_was_renamed_anyway():
    """A title a tool rewords between runs legitimately changes the id."""
    from app.sandbox.staging import StagedPoCRepository
    from app.validation import run as vrun

    assert hasattr(StagedPoCRepository, "repoint_findings")
    src = _inspect.getsource(vrun.validate_engagement)
    assert src.index("_repoint_staged_pocs(") < src.index(
        "vf_repo.replace_for_engagement("), \
        "PoCs must be repointed while the old rows are still readable"


# ---- #3: a PoC the model proved in the sandbox confirms its finding --------

@pytest.mark.asyncio
async def test_a_rehearsed_poc_that_worked_marks_the_finding_proven(monkeypatch):
    """refine already ran the final code against the live target and judged the
    output. _demonstrated read only outcome["auto_run"], so when the confirming
    re-run did not happen the proof was discarded - and the event said
    "demonstrated" and "not run" in the same sentence while the finding stayed
    at "likely"."""
    from app.exploit import campaign

    marked = {}

    async def _author(engagement, finding):
        return {"authored": True, "poc_id": "poc_r", "language": "python",
                "demonstrated": True, "iterations": 2,
                "rehearsal_output": "uid=0(root) gid=0(root)"}

    async def _auto_run(engagement, poc_id):
        return {"ran": False, "reason": "inspection found a critical signal"}

    class _Repo:
        async def get(self, _id):
            return SimpleNamespace(id="poc_r", finding_id="vf_1", repo="authored",
                                   path="rce.py", language="python", code="x")

    async def _mark(engagement_id, poc, result, decided_by):
        marked["finding_id"] = poc.finding_id
        marked["stdout"] = result.stdout
        marked["decided_by"] = decided_by

    monkeypatch.setattr(campaign, "_author", _author)
    monkeypatch.setattr(campaign, "_auto_run_staged", _auto_run)
    monkeypatch.setattr(campaign, "StagedPoCRepository", lambda: _Repo())
    monkeypatch.setattr("app.exploit.poc_run._mark_finding_proven", _mark)

    eng = SimpleNamespace(id="eng_1", scope_hosts=["app.example.com"],
                          allow_active_exploit=True)
    attempt = await campaign._try_authored(eng, {"id": "vf_1"})

    assert campaign._demonstrated(attempt), \
        "a rehearsal that demonstrated the issue is a clean sandbox run"
    assert marked["finding_id"] == "vf_1", "the finding was never marked proven"
    assert "uid=0" in marked["stdout"], "the rehearsal output is the evidence"


@pytest.mark.asyncio
async def test_a_rehearsal_that_failed_proves_nothing(monkeypatch):
    from app.exploit import campaign

    async def _author(engagement, finding):
        return {"authored": True, "poc_id": "poc_r", "demonstrated": False,
                "iterations": 2, "rehearsal_output": ""}

    async def _auto_run(engagement, poc_id):
        return {"ran": False, "reason": "vetting refused it"}

    monkeypatch.setattr(campaign, "_author", _author)
    monkeypatch.setattr(campaign, "_auto_run_staged", _auto_run)
    eng = SimpleNamespace(id="eng_1", scope_hosts=["h"], allow_active_exploit=True)
    attempt = await campaign._try_authored(eng, {"id": "vf_1"})
    assert not campaign._demonstrated(attempt)


# ---- #6: a run that failed on the environment can be retried ---------------

def test_a_poc_that_died_on_the_environment_is_not_terminal():
    from app.sandbox.staging import (STATUS_APPROVED, STATUS_EXECUTED,
                                     can_transition)

    assert can_transition(STATUS_EXECUTED, STATUS_APPROVED), \
        "a PoC that failed on a missing library could never be re-run"


# ---- #7: a finding with no route is named, not dropped ---------------------

def test_the_classes_the_default_tools_report_all_have_a_route():
    """Ten tool integrations produced findings nothing could ever exploit: no
    nuclei template, no TOOL_ROUTES entry, not authorable. run_campaign then
    dropped the plan without appending it, so plan.skipped_because - which
    strategy had already computed - was discarded, and the only trace was
    "N of M findings had a route"."""
    from app.exploit.strategy import AUTHORABLE_CLASSES, SURFACE_CLASSES, TOOL_ROUTES
    from app.validation.classes import TOOL_VULN_CLASS

    routed = AUTHORABLE_CLASSES | set(TOOL_ROUTES) | SURFACE_CLASSES
    orphans = sorted({c for c in TOOL_VULN_CLASS.values() if c not in routed})
    assert not orphans, f"no exploit route can ever exist for: {orphans}"


def test_the_two_definitions_of_surface_agree():
    """`vulnerable_component` was surface to the campaign and a real finding to
    the validator, so every retire.js CVE was scored likely/medium and then
    refused as "not a vulnerability"."""
    from app.exploit.strategy import SURFACE_CLASSES as campaign_side
    from app.validation.classes import SURFACE_CLASSES as validator_side

    assert set(campaign_side) == set(validator_side)


def test_a_routeless_finding_is_reported(monkeypatch):
    from app.exploit import campaign

    src = _inspect.getsource(campaign.run_campaign)
    assert "_report_skip(" in src, "the reason must reach the live view"
    assert "skipped.append(" in src, "the plan must ride back with the result"


# ---- #8: the public-PoC route is not GitHub-only ---------------------------

@pytest.mark.asyncio
async def test_an_exploitdb_entry_can_be_staged_from_its_local_copy(tmp_path):
    """exploit_sources emits Exploit-DB entries; parse_repo_url accepts
    github.com only, so _stage_public returned None for every one of them and
    the caller reported "could not fetch a runnable file"."""
    from app.exploit import campaign

    script = tmp_path / "50383.py"
    script.write_text("import requests\nprint('pwned')\n")
    route = SimpleNamespace(
        poc_url="https://www.exploit-db.com/exploits/50383",
        poc_source="exploit-db", poc_path=str(script))

    out = await campaign._fetch_exploitdb(route)
    assert out is not None
    assert out["language"] == "python"
    assert "pwned" in out["code"]


@pytest.mark.asyncio
async def test_a_github_url_is_not_mistaken_for_an_exploitdb_entry():
    from app.exploit import campaign

    route = SimpleNamespace(poc_url="https://github.com/x/CVE-2021-41773",
                            poc_source="github", poc_path="")
    assert await campaign._fetch_exploitdb(route) is None


def test_the_three_staging_failures_are_distinguishable():
    """Not a supported source / the listing came back empty / the download
    failed were collapsed into one message with three different fixes."""
    src = _inspect.getsource(
        __import__("app.exploit.campaign", fromlist=["x"])._stage_public)
    assert "is not a PoC source" in src
    assert "no candidate file" in src
    assert "could not download" in src


def test_the_github_search_says_why_it_came_back_empty():
    """403 for want of a token, a network failure and "no PoC exists" all
    returned [] and said so only in a debug log - and `aggregate` then produced
    no public_poc route at all."""
    from app.exploit_sources import github_poc_search_detailed

    src = _inspect.getsource(github_poc_search_detailed)
    assert "rate-limited" in src and "no GitHub token is set" in src
    assert "no published PoC repository matched" in src


def test_nuclei_is_not_claimed_for_every_cve():
    """nuclei_fired=True was passed unconditionally, so ROUTE_BUNDLED ranked
    first on every CVE and the summary attributed all the work to "bundled" -
    which is why a run that proved nothing still looked like it had tried."""
    from app.analysis import public_exploits

    # Code only: the comment explaining the defect names the old call.
    src = "\n".join(
        line for line in _inspect.getsource(public_exploits).splitlines()
        if not line.lstrip().startswith("#"))
    assert "nuclei_fired=True" not in src
    assert "nuclei_fired=cve in nuclei_cves" in src


# ---- #11: the panel can name the reasons that actually bite ----------------

def test_the_limits_panel_names_an_unusable_sandbox():
    from app.validation.limits import limits_for

    limits = limits_for(
        allow_active_exploit=True, unverified_classes=["cve", "rce"],
        sandbox_error="the sandbox runner is not reachable at http://x:8090")
    keys = {limit.key for limit in limits}
    assert "sandbox_unusable" in keys


def test_the_limits_panel_names_a_missing_model_key():
    from app.validation.limits import limits_for

    limits = limits_for(allow_active_exploit=True, unverified_classes=["idor", "rce"],
                        llm_configured=False)
    assert "no_llm_key" in {limit.key for limit in limits}


def test_the_limits_panel_names_a_poc_held_back_by_inspection():
    from app.validation.limits import limits_for

    limits = limits_for(allow_active_exploit=True, inspection_refusals=3)
    found = [limit for limit in limits if limit.key == "inspection_refused"]
    assert found and "3 PoC(s)" in found[0].what


def test_the_limits_panel_names_findings_with_no_route():
    from app.validation.limits import limits_for

    limits = limits_for(allow_active_exploit=True, routeless_findings=6,
                        routeless_reasons={"no route available": 5,
                                           "surface information": 1})
    found = [limit for limit in limits if limit.key == "no_exploit_route"]
    assert found and "no route available (x5)" in found[0].why


def test_a_healthy_run_still_reports_nothing():
    """Noise here trains the operator to skip the whole panel."""
    from app.validation.limits import limits_for

    assert limits_for(allow_active_exploit=True, unverified_classes=[]) == []


def test_the_loop_passes_those_facts_in():
    """limits_for grew the parameters; the caller has to fill them or the panel
    stays as blind as before."""
    from app.orchestrator import loop

    src = _inspect.getsource(loop._report_verification_limits)
    for arg in ("sandbox_error=", "llm_configured=", "auto_run_poc=",
                "inspection_refusals=", "routeless_findings="):
        assert arg in src, f"{arg} is never supplied"


# ---- #10: a probe-verified cloud credential lands somewhere -----------------

def test_a_live_cloud_key_confirms_the_finding_it_came_from():
    """probe_leaked_cloud_creds runs after validate_engagement, so the job
    finding it writes is never validated in that run - it reached neither the
    Findings page nor the report. A live, probe-verified AWS key surfaced
    nowhere at all."""
    from app.intel import cloud_creds

    src = _inspect.getsource(cloud_creds.probe_leaked_cloud_creds)
    assert "update_verdict(" in src and "set_metadata(" in src


def test_the_analysis_tools_verdicts_are_trusted():
    from app.validation.validator import _ANALYSIS_TOOLS

    for tool in ("cloud_creds", "api_exposure", "auth_posture", "dom_sinks",
                 "error_disclosure", "http_posture"):
        assert tool in _ANALYSIS_TOOLS, \
            f"{tool} precomputes its verdict and it is being discarded"


# ---- #9: every pass that decides something says so -------------------------
#
# These four ran, decided, logged to the backend log and returned a dict nobody
# rendered. From the operator's seat that is indistinguishable from not having
# run - and run_cve_checks is the ONLY mechanical path to a confirmed CVE, so
# its silence was the most expensive of them.

@pytest.mark.parametrize("module,function", [
    ("app.exploit.cve_checks", "run_cve_checks"),
    ("app.exploit.payload_gen", "run_payload_validation"),
    ("app.exploit.proof", "prove_impact"),
])
def test_each_deciding_pass_reports_to_the_live_view(module, function):
    mod = __import__(module, fromlist=["x"])
    src = _inspect.getsource(getattr(mod, function))
    assert "_say(" in src, f"{function} decides things and emits nothing"


def test_the_curated_cve_checks_say_when_they_did_not_cover_the_stack():
    """"The curated list did not match this fingerprint" and "this CVE is not
    real" look identical when neither is said."""
    from app.exploit import cve_checks

    src = _inspect.getsource(cve_checks.run_cve_checks)
    assert "was not covered here" in src or "did not match" in src


def test_an_absent_searchsploit_is_not_silence():
    """No log at all meant an image without searchsploit looked exactly like a
    CVE with no Exploit-DB entry."""
    from app import exploit_sources

    src = _inspect.getsource(exploit_sources.local_exploitdb)
    assert "searchsploit is not installed" in src
