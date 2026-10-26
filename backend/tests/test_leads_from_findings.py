"""Every finding the run produces is offered to the blackboard, once.

save_analysis_job covers every analyser and Executor.ingest covers every tool,
so the mapping lives in one place. The rule that matters most: this mechanical
mapping may NEVER post an identity it cannot prove - a false credential lead
makes the strategist announce an account the run does not have, and the
grey-box scanners believe it.
"""
from __future__ import annotations

import inspect

import pytest

from app.orchestrator import blackboard as bb
from app.orchestrator.blackboard import lead_for_finding
from app.scans.models import Finding


def _f(cls, *, target="https://t/x", status="confirmed", conf=0.9, **meta):
    return Finding(severity="high", title=f"{cls} on {target}",
                   description="", target=target, evidence="",
                   metadata={"vuln_class": cls, "status": status,
                             "confidence": conf, **meta})


# ---- what chains --------------------------------------------------------

@pytest.mark.parametrize("cls", ["sql_injection", "xss", "command_injection",
                                 "nosql_injection", "ssti", "lfi", "xxe",
                                 "ssrf", "crlf_injection", "open_redirect"])
def test_a_confirmed_injection_becomes_an_injectable_lead(cls):
    kind, value, data = lead_for_finding(_f(cls, target="https://t/p?id=1"))
    assert kind == bb.INJECTABLE
    assert value == "https://t/p?id=1"
    assert data["vuln_class"] == cls


@pytest.mark.parametrize("cls", ["exposed_resource", "exposed_bucket", "auth"])
def test_a_reachable_exposure_becomes_an_unauth_endpoint(cls):
    kind, value, _ = lead_for_finding(_f(cls))
    assert kind == bb.UNAUTH_ENDPOINT
    assert value == "https://t/x"


def test_a_cve_lead_is_keyed_on_the_cve_not_the_url():
    """One CVE on forty endpoints is one fact, not forty."""
    kind, value, data = lead_for_finding(
        _f("cve", cve="CVE-2021-44228", target="https://t/a"))
    assert kind == bb.CVE
    assert value == "CVE-2021-44228"
    assert data["target"] == "https://t/a"


def test_a_cve_falls_back_to_the_template_then_the_title():
    _, value, _ = lead_for_finding(_f("cve", template_id="log4j-rce"))
    assert value == "log4j-rce"
    _, value, _ = lead_for_finding(_f("cms_vulnerability"))
    assert value.startswith("cms_vulnerability on")


# ---- what does NOT chain ------------------------------------------------

def test_a_guess_does_not_steer_the_plan():
    """Below the confidence floor and not confirmed: the strategist would
    spend the exploitation budget chasing noise."""
    assert lead_for_finding(_f("sql_injection", status="likely", conf=0.3)) is None


def test_a_confirmed_finding_passes_whatever_its_stated_confidence():
    assert lead_for_finding(
        _f("sql_injection", status="confirmed", conf=0.0)) is not None


def test_a_class_that_chains_to_nothing_posts_nothing():
    assert lead_for_finding(_f("weak_tls")) is None
    assert lead_for_finding(_f("misconfiguration")) is None
    assert lead_for_finding(_f("recon")) is None


def test_a_finding_with_no_metadata_is_ignored_not_crashed_on():
    f = Finding(severity="info", title="t", description="", target="https://t",
                evidence="")
    assert lead_for_finding(f) is None


def test_an_injection_with_no_target_posts_nothing():
    """The whole value of an injectable lead is the URL to inject into."""
    assert lead_for_finding(_f("sql_injection", target="")) is None


# ---- the rule that protects the grey-box bridge ------------------------

def test_the_mechanical_mapping_never_posts_a_credential_or_a_session():
    """A credential/session/privilege lead asserts the run can act AS someone.
    The strategist says so on the console and adopt_identity acts on it, so it
    is only ever posted where the code holds the material - never derived from
    a vuln_class string."""
    classes = (list(bb.__dict__.get("_INJECTION_CLASSES", []))
               + list(bb.__dict__.get("_UNAUTH_CLASSES", []))
               + list(bb.__dict__.get("_CVE_CLASSES", []))
               + ["secret_exposure", "auth", "rce", "weak_tls"])
    for cls in classes:
        for verified in (True, False):
            got = lead_for_finding(_f(cls, verified=verified))
            if got is None:
                continue
            kind = got[0]
            assert kind not in (bb.CREDENTIAL, bb.SESSION, bb.PRIVILEGE), (
                f"{cls!r} was mapped to {kind!r} - a mechanical mapping must "
                "not claim the run holds an identity")


def test_a_verified_secret_is_a_lead_but_is_marked_unusable():
    """trufflehog proves a live key exists; it keeps no copy of it. Saying
    otherwise would make adopt_identity send an empty header and silently
    un-authenticate the run."""
    kind, value, data = lead_for_finding(
        _f("secret_exposure", verified=True, detector="AWS",
           location="https://t/app.js"))
    assert kind == bb.SECRET
    assert "AWS" in value
    assert data["usable"] is False
    assert data["verified"] is True


def test_an_unverified_secret_is_not_a_lead_at_all():
    """js_recon's candidates are already reported as findings; a guessed key
    must not reorder the exploitation phase."""
    assert lead_for_finding(_f("secret_exposure", verified=False)) is None


# ---- both ingest paths are wired ---------------------------------------

def test_the_analyser_store_offers_every_finding_to_the_board():
    from app.analysis import _store
    src = inspect.getsource(_store.save_analysis_job)
    assert "post_from_finding" in src
    # and it cannot fail the analyser that called it
    assert "except Exception" in src[src.index("post_from_finding"):]


def test_the_executor_offers_every_tool_finding_to_the_board():
    from app.orchestrator.executor import Executor
    src = inspect.getsource(Executor.ingest)
    assert "post_from_finding" in src
    assert "except Exception" in src[src.index("post_from_finding"):]
