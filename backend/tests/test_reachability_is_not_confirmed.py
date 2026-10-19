"""Confirming that an endpoint answers is not confirming a vulnerability.

A run's only 'confirmed' findings were "Archived endpoint is still answering"
(shadow_api) - reachability, not proven weaknesses - which read as if the tool
had confirmed vulns on a target it had barely tested. Reachability-only classes
now cap at 'likely' through the analysis path; a real weakness on the same
target (the version that lost its auth -> broken_access_control) stays
confirmed.
"""
from __future__ import annotations

import asyncio

from app.scans.models import Finding
from app.validation.models import ValidationStatus
from app.validation.safe_poc import SafePoC
from app.validation.validator import FindingValidator


def _validate(finding, tool, vuln_class):
    v = FindingValidator(SafePoC(in_scope=lambda h: True))
    return asyncio.run(v.validate(finding, tool, vuln_class))


def _finding(vuln_class, status="confirmed", confidence=0.85):
    return Finding(
        severity="low", title="t", description="d",
        target="https://t.example/api/v1/x", evidence="GET ... -> 200",
        metadata={"tool": "api_inventory", "vuln_class": vuln_class,
                  "status": status, "confidence": confidence})


def test_a_confirmed_shadow_api_is_capped_to_likely():
    r = _validate(_finding("shadow_api"), "api_inventory", "shadow_api")
    assert r.status == ValidationStatus.LIKELY
    assert r.confidence <= 0.5
    assert "reachability" in r.detail.lower()


def test_the_access_control_regression_stays_confirmed():
    """The forgotten version that answers WITHOUT the auth the current one
    enforces is a real weakness - broken_access_control, not a reachability
    class - and must keep its confirmed verdict."""
    r = _validate(_finding("broken_access_control"),
                  "api_inventory", "broken_access_control")
    assert r.status == ValidationStatus.CONFIRMED


def test_other_analysers_confirmed_verdicts_are_untouched():
    """The cap is narrow: a mass-assignment echo or an SQLi stays confirmed."""
    for vclass in ("mass_assignment", "idor", "sql_injection"):
        r = _validate(_finding(vclass), "mass_assignment", vclass)
        assert r.status == ValidationStatus.CONFIRMED, vclass


def test_a_non_confirmed_reachability_finding_is_left_as_is():
    """The cap only lowers CONFIRMED; a shadow_api already 'likely' is
    unchanged."""
    r = _validate(_finding("shadow_api", status="likely", confidence=0.4),
                  "api_inventory", "shadow_api")
    assert r.status == ValidationStatus.LIKELY
