"""The reward for a PoC comes from outside the agent that wrote it.

refine.py used to ask one question of a sandbox run: did it exit 0 and print
something? The model writes the script that chooses the exit code, so this was
enough to earn a proof and promote a finding:

    print("Vulnerability confirmed: admin access obtained")
    sys.exit(0)

These tests pin the fix. A clean run is now the PoC's own account of itself;
only an independent request syphax makes ITSELF can promote it.
"""
from __future__ import annotations

import pytest

from app.exploit import oracle, refine


# ---- the hole itself ---------------------------------------------------

def test_a_poc_cannot_grade_itself_by_exiting_zero():
    status, _ = refine.classify_run(0, False, "Vulnerability confirmed!", "")
    assert status == refine.SELF_REPORTED
    assert status != refine.DEMONSTRATED


def test_no_claim_means_no_corroboration():
    got = pytest.importorskip("asyncio").run(oracle.corroborate(None))
    assert got["outcome"] == oracle.NO_CLAIM


# ---- parsing the claim -------------------------------------------------

def test_a_well_formed_claim_is_read():
    claim = oracle.parse_claim(
        'looking...\n'
        'SYPHAX-CLAIM: {"url": "https://t/api/u/2", '
        '"expect": "other.user@example.com", "note": "another user"}')
    assert claim == {"url": "https://t/api/u/2",
                     "expect": "other.user@example.com",
                     "note": "another user"}


def test_the_last_claim_wins():
    """A PoC that explores before it concludes stands behind its final answer."""
    claim = oracle.parse_claim(
        'SYPHAX-CLAIM: {"url": "https://t/a", "expect": "firstvalue"}\n'
        'SYPHAX-CLAIM: {"url": "https://t/b", "expect": "secondvalue"}')
    assert claim["url"] == "https://t/b"


@pytest.mark.parametrize("stdout", [
    "",
    "no claim here at all",
    "SYPHAX-CLAIM: not json",
    'SYPHAX-CLAIM: {"url": "https://t/a"}',              # no expect
    'SYPHAX-CLAIM: {"expect": "something long"}',        # no url
    'SYPHAX-CLAIM: ["https://t/a", "x"]',                # not an object
])
def test_an_unusable_claim_is_no_claim(stdout):
    assert oracle.parse_claim(stdout) is None


@pytest.mark.parametrize("expect", [
    "true", "confirmed", "vulnerable", "200", "ok", "admin", "error", "root",
    "yes", "x",
])
def test_a_claim_that_would_match_anything_is_refused(expect):
    """An expectation nothing could distinguish is worse than no claim: it
    corroborates against almost any response and hands out a proof for free."""
    stdout = 'SYPHAX-CLAIM: {"url": "https://t/a", "expect": "%s"}' % expect
    assert oracle.parse_claim(stdout) is None


def test_a_specific_expectation_is_accepted():
    claim = oracle.parse_claim(
        'SYPHAX-CLAIM: {"url": "https://t/a", "expect": "/home/deploy/.ssh"}')
    assert claim is not None


# ---- the prompt and the parser cannot drift apart ---------------------

def test_the_prompt_asks_for_exactly_what_the_parser_reads():
    text = oracle.claim_instruction()
    assert oracle.CLAIM_PREFIX in text
    # and a line built the way the prompt describes it actually parses
    example = ('SYPHAX-CLAIM: {"url": "https://t/api/invoices/2", '
               '"expect": "other.user@example.com", "note": "cross-user read"}')
    assert oracle.parse_claim(example) is not None


def test_the_authoring_prompt_carries_the_claim_rule():
    """If it did not, no PoC would ever emit a claim, nothing would ever be
    corroborated, and every authored proof would silently become
    self-reported."""
    from app.exploit.authoring import system_prompt
    assert oracle.CLAIM_PREFIX in system_prompt([])
    assert oracle.CLAIM_PREFIX in system_prompt(["destructive"])


# ---- the oracle's request is in scope, read-only ----------------------

def test_the_scope_predicate_refuses_an_empty_scope():
    """An oracle must never be the thing that widens scope."""
    pred = oracle._scope_predicate([])
    assert pred("anything.example") is False


def test_the_scope_predicate_matches_the_engagement_rule():
    pred = oracle._scope_predicate(["t.example", ".iliad.fr"])
    assert pred("t.example")
    assert pred("a.iliad.fr")
    assert pred("iliad.fr")          # the apex, as Engagement.host_in_scope does
    assert not pred("evil.example")
    assert not pred("iliad.fr.evil.example")
    assert not pred("")


def test_the_oracle_delegates_to_the_shared_replay():
    """It reuses validation/proof_replay: GET/HEAD only, in-scope, capped. A
    second, looser HTTP path would be a second policy to keep right."""
    import inspect
    src = inspect.getsource(oracle.corroborate)
    assert "replay_proof" in src


def test_a_replay_that_blows_up_is_inconclusive_not_a_proof(monkeypatch):
    import asyncio

    import app.validation.proof_replay as pr

    async def boom(proof, in_scope):
        raise RuntimeError("target unreachable")

    monkeypatch.setattr(pr, "replay_proof", boom)
    got = asyncio.run(oracle.corroborate(
        {"url": "https://t/a", "expect": "something specific"},
        scope_hosts=["t"]))
    assert got["outcome"] == oracle.INCONCLUSIVE


def test_an_unknown_replay_outcome_is_not_treated_as_held(monkeypatch):
    """Fail closed: anything the oracle does not recognise is not a proof."""
    import asyncio

    import app.validation.proof_replay as pr

    async def odd(proof, in_scope):
        return {"outcome": "probably_fine"}

    monkeypatch.setattr(pr, "replay_proof", odd)
    got = asyncio.run(oracle.corroborate(
        {"url": "https://t/a", "expect": "something specific"},
        scope_hosts=["t"]))
    assert got["outcome"] == oracle.INCONCLUSIVE


# ---- nothing downstream promotes on the model's word -----------------

def test_an_authored_poc_needs_the_oracle_to_count_as_proof():
    from app.exploit import strategy
    from app.exploit.campaign import _demonstrated
    clean_run = {"auto_run": {"ran": True, "exit_code": 0},
                 "route": strategy.ROUTE_AUTHORED}
    assert _demonstrated(clean_run) is False
    assert _demonstrated({**clean_run, "demonstrated": True}) is True


def test_a_tool_or_published_route_keeps_the_plain_rule():
    """commix's own output and a published PoC are not code written by an agent
    being rewarded for this run succeeding - and both are staged for a human."""
    from app.exploit import strategy
    from app.exploit.campaign import _demonstrated
    for route in (strategy.ROUTE_PUBLIC_POC, strategy.ROUTE_TOOL,
                  strategy.ROUTE_BUNDLED):
        assert _demonstrated({"auto_run": {"ran": True, "exit_code": 0},
                              "route": route}) is True


def test_a_run_that_did_not_run_is_never_proof():
    from app.exploit.campaign import _demonstrated
    assert _demonstrated({"auto_run": {"ran": False, "exit_code": 0}}) is False
    assert _demonstrated({"auto_run": {"ran": True, "exit_code": 1}}) is False
    assert _demonstrated({}) is False


# ---- the oracle sits at the promotion site, not only in the loop ------

class _Poc:
    def __init__(self, origin="authored", refine=None):
        self.id = "poc_1"
        self.finding_id = "vf_1"
        self.inspection = {"origin": origin}
        if refine is not None:
            self.inspection["refine"] = refine


def test_an_auto_run_authored_poc_needs_corroboration():
    from app.exploit.poc_run import needs_corroboration
    assert needs_corroboration(_Poc(), "auto:policy") is True


def test_an_operator_run_never_needs_it():
    """The person approved this PoC and reads its output: they are the oracle,
    and nothing about their workflow changes."""
    from app.exploit.poc_run import needs_corroboration
    assert needs_corroboration(_Poc(), "operator:alice") is False
    assert needs_corroboration(_Poc(), "") is False


def test_a_third_party_exploit_never_needs_it():
    from app.exploit.poc_run import needs_corroboration
    assert needs_corroboration(_Poc(origin="public_poc"), "auto:policy") is False
    assert needs_corroboration(_Poc(origin=""), "auto:policy") is False


def test_a_refine_corroborated_poc_is_not_asked_twice():
    from app.exploit.poc_run import already_corroborated
    assert already_corroborated(_Poc(refine={"corroborated": True})) is True
    assert already_corroborated(_Poc(refine={"corroborated": False})) is False
    assert already_corroborated(_Poc(refine={"demonstrated": True})) is False
    assert already_corroborated(_Poc()) is False


def test_the_oracle_still_runs_when_the_refine_loop_is_off():
    """Turning rehearsal off, or losing the sandbox, must not quietly restore
    promotion-on-exit-code for single-shot authored PoCs - which is why the
    oracle lives at the promotion site and not only inside refine."""
    import inspect

    from app.exploit import poc_run
    src = inspect.getsource(poc_run._promotable)
    assert "corroborate" in src
    assert "parse_claim" in src
