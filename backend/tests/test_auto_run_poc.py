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


def test_a_public_poc_that_proves_nothing_escalates_to_the_model():
    """Published exploits are often only a checker - they print VULNERABLE and
    exit. That is not proof, so the model must then write a real one."""
    import inspect as _inspect

    from app.exploit import campaign

    src = _inspect.getsource(campaign.run_campaign)
    assert "_demonstrated(outcome)" in src
    assert "_try_authored" in src[src.index("ROUTE_PUBLIC_POC"):]


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
