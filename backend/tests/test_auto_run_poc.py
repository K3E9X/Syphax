"""Auto-run of vetted public PoCs: the gate must match the manual path.

execute_poc is the single gated run path. These cover the pre-vet gates that
return before any sandbox/DB access, the config default, and the campaign
policy condition (only run when BOTH readings are clean).
"""
from types import SimpleNamespace

import pytest

from app.config import settings
from app.exploit.poc_run import PoCRunRefused, execute_poc


def _eng(**kw):
    base = dict(id="eng_1", allow_active_exploit=True, scope_hosts=["t.example"])
    base.update(kw)
    return SimpleNamespace(**base)


def _poc():
    return SimpleNamespace(id="poc_1", code="print(1)", language="python",
                           repo="o/r", path="poc.py")


@pytest.mark.asyncio
async def test_refused_when_active_exploit_off():
    with pytest.raises(PoCRunRefused) as e:
        await execute_poc(_eng(allow_active_exploit=False), _poc(),
                          timeout=10, decided_by="auto:policy")
    assert "allow_active_exploit" in str(e.value)


@pytest.mark.asyncio
async def test_refused_when_no_scope():
    with pytest.raises(PoCRunRefused):
        await execute_poc(_eng(scope_hosts=[]), _poc(),
                          timeout=10, decided_by="auto:policy")


def test_auto_run_on_by_default():
    assert settings.auto_run_public_poc is True


def test_auto_run_policy_requires_both_readings_clean():
    # Mirror the condition in campaign.run_campaign: run only when the target
    # vet passed AND the operator-safety inspection found nothing.
    def should_run(outcome):
        return bool(outcome and settings.auto_run_public_poc
                    and outcome.get("allowed")
                    and outcome.get("inspection_verdict") == "review")

    assert should_run({"allowed": True, "inspection_verdict": "review"})
    assert not should_run({"allowed": False, "inspection_verdict": "review"})
    assert not should_run({"allowed": True, "inspection_verdict": "suspicious"})
    assert not should_run({"allowed": True, "inspection_verdict": "hostile"})
    assert not should_run(None)


# ---- every origin is actually run, not just the published ones -------------

def test_both_routes_run_their_poc():
    """A PoC the model wrote used to be staged and never fired, which left the
    whole LLM exploitation path decorative: it proved nothing."""
    import inspect as _inspect

    from app.exploit import campaign

    for fn in (campaign._try_public, campaign._try_authored):
        assert "_auto_run_staged" in _inspect.getsource(fn), fn.__name__


def test_the_campaign_walks_every_route_until_one_proves_it():
    """Taking only plan.best was the bug the operator hit for a week.

    ROUTE_BUNDLED ranks first, so for ANY CVE with a nuclei template the single
    route chosen was "bundled", whose branch merely records "ran earlier in this
    phase". The published PoC and the model were never reached, and the finding
    stayed LIKELY / UNVERIFIED forever.
    """
    import inspect as _inspect

    from app.exploit import campaign

    src = _inspect.getsource(campaign.run_campaign)
    assert "for route in plan.routes:" in src, "still picking a single route"
    # Ignore comments: the fix is explained in one, and the explanation names
    # the thing it replaced.
    code = "\n".join(l for l in src.split("\n")
                     if not l.lstrip().startswith("#"))
    assert "plan.best" not in code, "plan.best short-circuits the cascade"
    # Both real routes are reachable from the loop, and the loop stops on proof.
    assert "_try_public" in src and "_try_authored" in src
    assert "_demonstrated(attempt)" in src


def test_an_already_confirmed_finding_stops_the_cascade():
    """If run_known_exploits/prove_impact already settled it there is nothing
    left to prove - do not re-exploit a confirmed finding."""
    from app.exploit.campaign import _already_proven
    assert _already_proven({"status": "confirmed"})
    assert _already_proven({"metadata": {"proven": True}})
    assert not _already_proven({"status": "likely"})
    assert not _already_proven({})


def test_active_exploit_off_is_announced():
    """With it off every PoC is refused at the run gate and everything stays
    'likely'. An engagement created before it became the default still has it
    off, which is invisible unless we say so."""
    import inspect as _inspect

    from app.exploit import campaign

    src = _inspect.getsource(campaign.run_campaign)
    assert "allow_active_exploit" in src
    assert "no proof can be" in src


@pytest.mark.parametrize("outcome,proved", [
    ({"auto_run": {"ran": True, "exit_code": 0}}, True),
    ({"auto_run": {"ran": True, "exit_code": 2}}, False),   # usage error / checker
    ({"auto_run": {"ran": False, "reason": "vetting refused it"}}, False),
    ({"poc_id": "p1"}, False),                              # staged only
    ({}, False),
])
def test_only_a_clean_sandbox_run_counts_as_demonstrated(outcome, proved):
    from app.exploit.campaign import _demonstrated
    assert _demonstrated(outcome) is proved


def test_auto_run_reads_the_gate_from_the_poc_itself():
    """The policy must not be passed in by the caller: every origin gets the
    same two clean readings (target vet + operator-safety inspection)."""
    import inspect as _inspect

    from app.exploit import campaign

    src = _inspect.getsource(campaign._auto_run_staged)
    assert "vetting" in src and "allowed" in src
    assert '"review"' in src
    assert "execute_poc" in src


@pytest.mark.asyncio
async def test_rehearsal_is_on_by_default():
    """0 meant the model never watched its own exploit run. The value now comes
    from the saved settings (no DB here -> the env default answers)."""
    from app.exploit.settings_live import refine_iterations
    assert await refine_iterations() >= 1


@pytest.mark.asyncio
async def test_auto_run_defaults_on():
    from app.exploit.settings_live import auto_run_poc
    assert await auto_run_poc() is True


# ---- the operator can see what happened ------------------------------------

def test_every_attempt_is_reported_to_the_live_view():
    """run_campaign returned the attempt detail and the caller dropped it, so
    the operator saw a one-line plan summary and never learned which route was
    tried or what the sandbox returned."""
    import inspect as _inspect

    from app.exploit import campaign

    assert "_report_attempts" in _inspect.getsource(campaign.run_campaign)
    report = _inspect.getsource(campaign._report_attempts)
    for phrase in ("PROVEN", "proves nothing", "staged for review",
                   "model wrote one", "rehearsed"):
        assert phrase in report, phrase


def test_summary_counts_what_happened_not_just_what_was_planned():
    import inspect as _inspect

    from app.exploit import campaign

    src = _inspect.getsource(campaign.run_campaign)
    assert '"proven"' in src and '"escalated_to_model"' in src


# ---- the Sandbox page is optional ------------------------------------------

def test_the_automatic_path_does_not_wait_for_a_human_approval():
    """Nothing in the run requires opening the Sandbox page. The approval gate
    belongs to the MANUAL endpoint only; the campaign calls execute_poc directly."""
    import inspect as _inspect

    from app.api import poc as poc_api
    from app.exploit import campaign, poc_run

    # The shared runner has no approval check...
    assert "STATUS_APPROVED" not in _inspect.getsource(poc_run.execute_poc)
    # ...the manual endpoint does...
    assert "STATUS_APPROVED" in _inspect.getsource(poc_api.run)
    # ...and the automatic path goes straight to the runner.
    assert "execute_poc" in _inspect.getsource(campaign._auto_run_staged)


def test_only_a_poc_that_looks_hostile_to_the_operator_waits():
    """The single remaining human gate: static analysis says the PoC attacks
    YOU (a stealer in a fake exploit repo), not the target."""
    import inspect as _inspect

    from app.exploit import campaign

    src = _inspect.getsource(campaign._auto_run_staged)
    assert '"review"' in src and "needs a human" in src


# ---- ordering: the campaign must see the findings it works on --------------

def test_the_campaign_runs_after_validation_creates_its_input():
    """run_campaign reads VALIDATED findings. It used to run nine lines before
    validate_engagement, which is what writes them: on a run it found an empty
    table, returned through a silent early exit, and produced no plan, no PoC
    and no event - every finding stayed "likely" with nothing explaining it."""
    import inspect as _inspect

    from app.orchestrator import loop

    src = _inspect.getsource(loop)
    assert src.index("await validate_engagement(engagement.id)") < \
        src.index("await run_campaign(engagement.id)"), \
        "the campaign reads validated findings before validation writes them"


def test_an_empty_campaign_says_so():
    """The silent return is what hid the ordering bug."""
    import inspect as _inspect

    from app.exploit import campaign

    src = _inspect.getsource(campaign.run_campaign)
    assert "no validated finding to work on" in src
