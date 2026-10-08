"""Proof obtained by RUNNING something must survive re-validation.

validate_engagement rebuilds every validated finding with a DELETE + INSERT,
re-deriving each row from the raw job findings - which know nothing about a PoC
executed afterwards. So a finding proven by a sandbox run lost both its
"confirmed" verdict and the PoC output the moment anyone pressed "Re-validate"
or "Retest", silently reverting to likely/unverified. The UI has both buttons.
"""
from types import SimpleNamespace

import pytest

from app.validation.run import _carry_over_proof


def _vf(vuln_class, target, status="likely", confidence=0.6, metadata=None,
        method="heuristic"):
    return SimpleNamespace(vuln_class=vuln_class, target=target, status=status,
                           confidence=confidence, method=method,
                           metadata=dict(metadata or {}))


class _Repo:
    def __init__(self, previous):
        self._previous = previous

    async def list(self, _engagement_id):
        return self._previous


PROOF = {"exploitation": {"repo": "o/r", "exit_code": 0, "stdout": "uid=33"},
         "proven": True}


@pytest.mark.asyncio
async def test_a_proven_finding_comes_back_proven():
    old = _vf("rce", "https://t/x", status="confirmed", confidence=0.95,
              method="public-poc-exploit", metadata=PROOF)
    fresh = _vf("rce", "https://t/x")                   # re-derived, no proof
    carried = await _carry_over_proof(_Repo([old]), "eng", [fresh])
    assert carried == 1
    assert fresh.status == "confirmed"
    assert fresh.confidence == 0.95
    assert fresh.method == "public-poc-exploit"
    assert fresh.metadata["exploitation"]["stdout"] == "uid=33"


@pytest.mark.asyncio
async def test_a_different_finding_is_untouched():
    old = _vf("rce", "https://t/x", status="confirmed", metadata=PROOF)
    other = _vf("xss", "https://t/y")
    await _carry_over_proof(_Repo([old]), "eng", [other])
    assert other.status == "likely"
    assert "exploitation" not in other.metadata


@pytest.mark.asyncio
async def test_findings_without_proof_are_not_carried():
    old = _vf("xss", "https://t/y", status="confirmed")   # confirmed, no proof
    fresh = _vf("xss", "https://t/y")
    assert await _carry_over_proof(_Repo([old]), "eng", [fresh]) == 0
    assert fresh.status == "likely"


@pytest.mark.asyncio
async def test_a_fresh_verdict_is_never_demoted():
    """Carrying over only ever upgrades."""
    old = _vf("rce", "https://t/x", status="likely", confidence=0.6,
              metadata={"repro": {"command": "commix -u ..."}})
    fresh = _vf("rce", "https://t/x", status="confirmed", confidence=0.95)
    await _carry_over_proof(_Repo([old]), "eng", [fresh])
    assert fresh.status == "confirmed"          # not dragged back to likely
    assert fresh.confidence == 0.95
    assert fresh.metadata["repro"]["command"].startswith("commix")


@pytest.mark.asyncio
async def test_a_first_run_has_nothing_to_carry():
    fresh = _vf("rce", "https://t/x")
    assert await _carry_over_proof(_Repo([]), "eng", [fresh]) == 0


@pytest.mark.asyncio
async def test_a_dead_repository_does_not_break_validation():
    class _Dead:
        async def list(self, _):
            raise RuntimeError("no db")
    assert await _carry_over_proof(_Dead(), "eng", [_vf("rce", "t")]) == 0
