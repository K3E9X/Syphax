"""Scoring, and the scope the sandbox is actually given.

Two things the operator named: the validation/scoring of a vulnerability, and
exploitation EXECUTION. Both had a defect that is invisible from the outside.
"""
from __future__ import annotations

import asyncio
import inspect as _inspect
from types import SimpleNamespace as N

import pytest

from app.findings_util import score_for


def _f(severity="high", status="likely", **meta):
    return N(severity=severity, status=status, metadata=meta)


# ---- scoring -------------------------------------------------------------

def test_a_published_cvss_is_used_when_there_is_one():
    """nuclei carries the real score in its template classification and the
    wrapper already stored it in metadata["cvss"]. It was thrown away, and a
    severity-to-constant lookup was displayed in its place - LABELLED CVSS,
    which is a false claim in a document a client reads."""
    out = score_for(_f(severity="high", cvss=9.8))
    assert out["value"] == 9.8
    assert out["basis"] == "cvss"


def test_a_derived_score_says_it_is_derived():
    out = score_for(_f(severity="high", status="likely"))
    assert out["basis"] == "risk"
    assert "high impact" in out["explain"] and "likely" in out["explain"]


def test_proof_outranks_a_guess():
    """The only thing this number is used for is deciding what to look at
    first, and a medium somebody demonstrated is a better use of the next hour
    than a critical a scanner guessed at."""
    proven_medium = score_for(_f(severity="medium", status="confirmed",
                                 proven=True))
    guessed_critical = score_for(_f(severity="critical", status="unconfirmed"))
    assert proven_medium["value"] > guessed_critical["value"], (
        proven_medium, guessed_critical)


def test_certainty_moves_the_score_within_a_severity():
    band = [score_for(_f(severity="critical", status=s))["value"]
            for s in ("confirmed", "likely", "unconfirmed", "false_positive")]
    assert band == sorted(band, reverse=True), band
    assert band[-1] == 0.0


def test_a_false_positive_scores_nothing():
    assert score_for(_f(severity="critical", status="false_positive"))["value"] == 0.0


@pytest.mark.parametrize("bad", [None, "", "n/a", -1, 11, "high"])
def test_an_unusable_published_score_falls_back_to_the_derived_one(bad):
    out = score_for(_f(severity="high", status="likely", cvss=bad))
    assert out["basis"] == "risk", out


def test_the_api_serves_the_basis_so_the_ui_can_stop_saying_cvss():
    from app.api import findings as findings_api

    src = _inspect.getsource(findings_api)
    assert "score_basis" in src and "score_explain" in src
    assert "_CVSS.get(" not in src, \
        "a severity lookup is still being served as the score"


# ---- the scope the sandbox is given --------------------------------------

def _eng(scope, extra_in_scope=()):
    allowed = {h.lower() for h in list(scope) + list(extra_in_scope)}
    return N(id="eng_1", scope_hosts=list(scope), allow_active_exploit=True,
             host_in_scope=lambda h: h.lower() in allowed)


def _poc(finding_id=None):
    return N(id="poc_1", finding_id=finding_id, code="print(1)",
             language="python", repo="o/r", path="p.py")


def test_the_targets_host_is_added_when_the_engagement_authorises_it(monkeypatch):
    """The sandbox pins egress to the hosts it is given, and it was given the
    DECLARED scope only. A finding's target is frequently not in that list
    though it IS in scope - an IP the DNS seeding admitted, a subdomain the
    same-server rule accepted. The PoC was handed that target and could not
    reach it: it failed on the firewall, recorded as a failed exploit."""
    from app.exploit import poc_run

    class _Repo:
        async def get(self, _id):
            return N(target="http://51.159.110.74:80/x")

    monkeypatch.setattr("app.validation.storage.ValidatedFindingRepository",
                        _Repo, raising=False)
    eng = _eng(["prospex.datax.iliad.fr"], extra_in_scope=["51.159.110.74"])
    scope = asyncio.run(poc_run._scope_for(eng, _poc("vf_1"), []))

    assert "prospex.datax.iliad.fr" in scope
    assert "51.159.110.74" in scope, scope


def test_a_host_the_engagement_refuses_is_never_added(monkeypatch):
    """host_in_scope IS the authorization. It is never widened here."""
    from app.exploit import poc_run

    class _Repo:
        async def get(self, _id):
            return N(target="https://someone-elses.example/x")

    monkeypatch.setattr("app.validation.storage.ValidatedFindingRepository",
                        _Repo, raising=False)
    eng = _eng(["t.example"])
    scope = asyncio.run(poc_run._scope_for(eng, _poc("vf_1"), []))
    assert scope == ["t.example"], scope


def test_an_argv_target_is_admitted_on_the_same_terms(monkeypatch):
    from app.exploit import poc_run

    class _Repo:
        async def get(self, _id):
            return None

    monkeypatch.setattr("app.validation.storage.ValidatedFindingRepository",
                        _Repo, raising=False)
    eng = _eng(["t.example"], extra_in_scope=["api.t.example"])
    scope = asyncio.run(poc_run._scope_for(
        eng, _poc("vf_1"), ["-u", "https://api.t.example/v1"]))
    assert "api.t.example" in scope


def test_execute_poc_uses_the_widened_scope():
    """A guard: computing it and then passing the old list would be worse than
    not computing it, because the audit record would claim otherwise."""
    from app.exploit import poc_run

    src = _inspect.getsource(poc_run.execute_poc)
    assert "scope = await _scope_for(" in src
    assert "scope_hosts=eng.scope_hosts" not in src.split("_scope_for(")[1], \
        "the declared list is still what reaches the sandbox"
    assert "scope=scope" in src, "the audit record must say what was in force"
