"""A 404 that leads nowhere is not a finding.

The operator kept seeing them on the Findings page and was right to. A whole
class of path-existence claims was never re-checked:

    exposed_resource on https://t/admin/backup/  ->  likely,
                                                     "scanner-match (nuclei)"

...for a path that answers 404. is_noise only ever drops `info` findings of
inventory classes, deliberately - a weakness must never be silenced for its
status code - and the validator's re-request check only covered
DISCOVERY_CLASSES, which did not include `exposed_resource`. That is what
nuclei's exposure templates report (VULN-EXPOSURES) and it ships at MEDIUM, so
nothing at all was looking at it.

The URLs here matter. A path like /.env carries its own safe-PoC content
signature and is refuted by that branch whatever its class, which masks the
gap entirely - these use paths with no signature, where the re-request check
is the only thing standing between a dead end and the report.
"""
from __future__ import annotations

import asyncio

import pytest

from app.scans.models import Finding
from app.validation.baseline import NO_BASELINE
from app.validation.classes import DISCOVERY_CLASSES
from app.validation.models import ValidationStatus
from app.validation.validator import FindingValidator

# No safe-PoC signature attaches to these, so the verdict comes from the
# re-request check or not at all.
DEAD_END = "https://t.example/admin/backup/"
SHADOW = "https://t.example/api/v1/users"


class _Resp:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text
        self.headers = {}


class _Safe:
    """Answers one way for everything, and records what was asked."""

    def __init__(self, answer=(404, "Not Found")):
        self.answer = answer
        self.fetched = []

    async def fetch(self, url, method="GET"):
        self.fetched.append(url)
        return None if self.answer is None else _Resp(*self.answer)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _f(url, cls, sev="medium"):
    return Finding(severity=sev, title=f"{cls} at {url}", description="",
                   target=url, evidence="", metadata={"vuln_class": cls})


def _verdict(cls, url=DEAD_END, *, answer=(404, "Not Found"), sev="medium"):
    safe = _Safe(answer)
    v = FindingValidator(safe, baseline=NO_BASELINE)
    return _run(v.validate(_f(url, cls, sev), "nuclei", cls)), safe


# ---- the regression ----------------------------------------------------

def test_an_exposed_resource_on_a_missing_path_is_a_false_positive():
    """THE bug, in the shape it shipped: medium severity, 'likely', pointing
    at a path that is not there."""
    res, safe = _verdict("exposed_resource")
    assert res.status is ValidationStatus.FALSE_POSITIVE
    assert res.method == "re-request"
    assert "does not exist" in (res.detail or "")
    # and it was decided by asking the server, not by guessing
    assert safe.fetched == [DEAD_END]


def test_a_shadow_api_on_a_missing_path_is_a_false_positive():
    """"This forgotten version still answers" is a path claim too, and a 404
    is the server saying it does not."""
    res, _ = _verdict("shadow_api", SHADOW)
    assert res.status is ValidationStatus.FALSE_POSITIVE
    assert res.method == "re-request"


@pytest.mark.parametrize("cls", ["exposed_resource", "exposed_bucket",
                                 "shadow_api", "content_discovery",
                                 "source_code_disclosure",
                                 "information_disclosure"])
def test_every_path_claim_class_is_re_checked(cls):
    assert cls in DISCOVERY_CLASSES, (
        f"{cls} claims a path exists but is not re-checked, so a 404 on it "
        "ships as a finding")
    res, _ = _verdict(cls)
    assert res.status is ValidationStatus.FALSE_POSITIVE


@pytest.mark.parametrize("status", [404, 410])
def test_both_missing_statuses_count(status):
    res, _ = _verdict("exposed_resource", answer=(status, "gone"))
    assert res.status is ValidationStatus.FALSE_POSITIVE


def test_an_exposure_that_really_answers_survives():
    """The fix must not silence a real exposure - that would be worse than
    the bug."""
    res, _ = _verdict("exposed_resource",
                      answer=(200, "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7"))
    assert res.status is not ValidationStatus.FALSE_POSITIVE


# ---- what must NOT be silenced ----------------------------------------

@pytest.mark.parametrize("cls", ["sql_injection", "xss", "command_injection",
                                 "weak_tls", "misconfiguration", "jwt",
                                 "cors", "rate_limit"])
def test_a_weakness_is_never_refuted_by_the_path_check(cls):
    """On an injection or a TLS finding the response shape means nothing: a
    404 on the URL says nothing about whether the parameter is injectable.
    Other branches may still have an opinion - what must never happen is the
    PATH check deciding a weakness is not real."""
    assert cls not in DISCOVERY_CLASSES
    res, _ = _verdict(cls, "https://t.example/search?q=1")
    assert res.method != "re-request"
    assert "does not exist" not in (res.detail or "")


def test_the_home_page_is_not_a_path_existence_claim():
    res, _ = _verdict("exposed_resource", "https://t.example/")
    assert res.method != "re-request"


def test_a_target_that_does_not_answer_is_not_a_refutation():
    """No response is inconclusive - the target may have been down or
    rate-limited. Treating silence as proof of absence drops real findings."""
    res, _ = _verdict("exposed_resource", answer=None)
    assert res.method != "re-request"


@pytest.mark.parametrize("status", [401, 403])
def test_a_guarded_path_is_not_called_missing(status):
    """"This exists and is guarded" is one of the more interesting things a
    scan can find. Whatever else happens to it, the path check must not say
    the path is absent."""
    res, _ = _verdict("exposed_resource", answer=(status, "Forbidden"))
    assert "does not exist" not in (res.detail or "")


# ---- the info-noise half, which was already right ---------------------

def test_inventory_that_answered_404_is_still_dropped():
    from app.validation.noise import is_noise
    drop, why = is_noise("info", "content_discovery", {"status_code": 404})
    assert drop and "not there" in why


def test_an_info_lead_survives_its_404():
    """A dead page that carries parameters is still an injection point."""
    from app.validation.noise import is_noise
    drop, _ = is_noise("info", "content_discovery",
                       {"status_code": 404, "params": ["id"]})
    assert not drop


def test_a_weakness_is_not_noise_whatever_it_answered():
    from app.validation.noise import is_noise
    drop, _ = is_noise("medium", "exposed_resource", {"status_code": 404})
    assert not drop, ("is_noise must not silence a weakness - that is the "
                      "re-request check's job, and it says why in the detail")
