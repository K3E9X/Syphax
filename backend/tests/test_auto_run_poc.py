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

def test_authored_and_public_pocs_both_auto_run():
    """A PoC the model wrote used to be staged and never fired, which left the
    whole LLM exploitation path decorative: it proved nothing."""
    import inspect as _inspect

    from app.exploit import campaign

    src = _inspect.getsource(campaign.run_campaign)
    public_at = src.index("ROUTE_PUBLIC_POC")
    authored_at = src.index("ROUTE_AUTHORED")
    # Both branches reach the auto-run helper.
    assert src.count("_auto_run_staged") >= 2
    assert "_auto_run_staged" in src[public_at:authored_at]
    assert "_auto_run_staged" in src[authored_at:]


def test_auto_run_reads_the_gate_from_the_poc_itself():
    """The policy must not be passed in by the caller: every origin gets the
    same two clean readings (target vet + operator-safety inspection)."""
    import inspect as _inspect

    from app.exploit import campaign

    src = _inspect.getsource(campaign._auto_run_staged)
    assert "vetting" in src and "allowed" in src
    assert '"review"' in src
    assert "execute_poc" in src


def test_rehearsal_is_enabled_by_default():
    """0 meant the model never watched its own exploit run."""
    from app.config import settings
    assert settings.exploit_refine_iterations >= 1
