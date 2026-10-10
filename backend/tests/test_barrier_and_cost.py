"""Two questions the operator asked, answered in code.

  "la recon consomme des tokens ?"  - it did, on every planning round.
  "pour les vuln non verified, si c'est un scan sur la barriere, on la
   qualifie autrement" - it was not qualified at all.
"""
from __future__ import annotations

import inspect as _inspect

import pytest

from app.validation.barrier import describe, detect
from app.validation.models import ValidationResult, ValidationStatus


# ---- a barrier is not an answer about the target -------------------------

@pytest.mark.parametrize("code,body,headers,expected", [
    (403, "Attention Required! | Cloudflare", {"cf-ray": "x"}, "cloudflare"),
    (503, "Access denied - Sucuri Website Firewall", {}, "sucuri"),
    (403, "The requested URL was rejected.", {}, "f5 big-ip asm"),
    (429, "Too Many Requests", {}, "a WAF or rate limiter"),
    (406, "Not Acceptable! mod_security", {}, "mod_security"),
])
def test_a_block_page_is_recognised(code, body, headers, expected):
    assert detect(code, body, headers) == expected


@pytest.mark.parametrize("code,body", [
    (403, '{"error":"you must be logged in"}'),
    (403, "Forbidden: this account cannot read that invoice"),
    (401, '{"detail":"authentication required"}'),
    (404, "Not Found"),
    (200, "<html>hello</html>"),
    (500, "Internal Server Error"),
])
def test_an_application_answering_is_not_a_barrier(code, body):
    """This matters more than the detections. A false "blocked" claim would
    excuse a finding the target genuinely disproved, and a 403 is also how an
    application says "you are not logged in" - which IS an answer."""
    assert detect(code, body, {}) == "", (code, body)


def test_the_reason_says_what_it_does_not_say():
    text = describe("cloudflare", 403)
    assert "not tested" in text.lower()
    assert "says nothing about whether the issue is real" in text


# ---- the verdict keeps the two apart -------------------------------------

def test_blocked_is_not_scored_like_a_failed_reproduction():
    """We learned nothing, so there are no grounds to think less of the
    finding than before the attempt."""
    blocked = ValidationResult.blocked("re-request", barrier="cloudflare")
    looked = ValidationResult.unconfirmed("re-request")
    assert blocked.status is ValidationStatus.UNCONFIRMED
    assert blocked.was_blocked and not looked.was_blocked
    assert blocked.confidence > looked.confidence


def test_the_validator_asks_before_reading_a_status_code():
    """Otherwise a WAF's 403 decides whether a finding is real."""
    from app.validation import validator

    src = _inspect.getsource(validator.FindingValidator._check_against_baseline)
    assert "detect_barrier(" in src
    assert src.index("detect_barrier(") < src.index("(404, 410)"), \
        "the 404 rule runs before anyone asks who answered"


def test_the_finding_carries_it_to_the_ui():
    from app.validation import run as vrun

    assert "blocked_by" in _inspect.getsource(vrun.validate_engagement)


def test_the_score_does_not_bury_what_was_never_tested():
    from types import SimpleNamespace as N

    from app.findings_util import score_for

    tested = score_for(N(severity="high", status="unconfirmed", metadata={}))
    untested = score_for(N(severity="high", status="unconfirmed",
                           metadata={"blocked_by": "cloudflare"}))
    likely = score_for(N(severity="high", status="likely", metadata={}))

    assert tested["value"] < untested["value"] < likely["value"], (
        tested, untested, likely)
    assert "NOT TESTED" in untested["explain"]


# ---- what recon was costing ----------------------------------------------

def test_the_model_is_not_asked_to_order_recon():
    """It was asked on every planning round in every phase, at roughly 5k
    tokens a round. With MAX_ITERATIONS at 150 that is most of a million tokens
    per run, much of it spent deciding whether to resolve DNS before probing a
    port - which the deterministic order already settles."""
    from app.orchestrator import planner

    src = _inspect.getsource(planner.Planner._llm_reorder)
    assert "PHASE_RECON" in src and "PHASE_MAPPING" in src
    assert src.index("PHASE_RECON") < src.index("get_router()"), \
        "the client is built before the phase is checked, which is the cost"


def test_there_is_a_ceiling_on_model_assisted_ordering():
    from app.orchestrator.planner import MAX_LLM_REORDERS
    from app.orchestrator.loop import MAX_ITERATIONS

    assert 0 < MAX_LLM_REORDERS < MAX_ITERATIONS, (
        "a long run must not turn into an open tab")


def test_hitting_the_ceiling_is_announced_not_silent():
    from app.orchestrator import planner

    src = _inspect.getsource(planner.Planner._llm_reorder)
    assert "_report_degraded(" in src
    assert "_reorder_cap_reported" in src, "it must be said once, not per round"
