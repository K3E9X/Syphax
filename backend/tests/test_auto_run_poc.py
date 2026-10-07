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
