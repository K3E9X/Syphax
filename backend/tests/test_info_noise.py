"""Which `info` findings earn a row.

"Pour les pages qui renvoient 404 ou erreur, pas besoin de les remonter, sauf
les pertinents qui meritent d'etre remontes."

A run on a real target produces hundreds of info rows - every archived URL,
every crawled page, every probed host. Most are inventory: they tell the
pipeline where to aim and the operator nothing. A few are leads and must
survive, and getting THAT wrong is the expensive mistake.
"""
from __future__ import annotations

import inspect as _inspect

import pytest

from app.validation.noise import is_noise


# ---- dead pages go ------------------------------------------------------

@pytest.mark.parametrize("status", [404, 410, 500, 502, 503, 504])
def test_inventory_pointing_at_a_dead_page_is_dropped(status):
    drop, why = is_noise("info", "recon", {"status_code": status})
    assert drop
    assert str(status) in why


def test_the_status_key_each_tool_happens_to_use_is_read():
    """katana writes status_code, ffuf writes status. Reading only one of them
    would silently keep half the dead pages."""
    for key in ("status_code", "status", "http_status"):
        drop, _ = is_noise("info", "content_discovery", {key: 404})
        assert drop, key


def test_nothing_is_re_requested_to_decide_this():
    """The answer is already on the finding. Re-asking would cost a thousand
    requests to learn what the discovering tool wrote down."""
    # Asserted on the function, not on its text. Two earlier versions of this
    # matched a comment and then a dict lookup (`meta.get(key)`), which is the
    # hazard of grepping source for intent. Every network call in this codebase
    # is awaited, so "not a coroutine" IS "makes no request".
    assert not _inspect.iscoroutinefunction(is_noise)
    src = _inspect.getsource(is_noise)
    assert "await" not in src, "a sync function cannot await, so this is dead"
    for forbidden in ("httpx", "aiohttp", "requests.", "SafePoC", "urlopen"):
        assert forbidden not in src, forbidden


# ---- leads stay ---------------------------------------------------------

def test_a_guarded_page_is_not_noise():
    """401/403 is "this exists and is guarded", which is one of the more
    interesting things a scan can report."""
    for status in (401, 403):
        drop, _ = is_noise("info", "content_discovery", {"status": status})
        assert not drop, status


@pytest.mark.parametrize("lead", [
    {"has_params": True}, {"params": ["id"]}, {"param": "debug"},
    {"cname": ["x.cloudfront.net"]}, {"server": "Apache/2.4.49"},
    {"tech": ["php"]}, {"cve_id": "CVE-2021-41773"}, {"secret": "shape"},
])
def test_a_lead_survives_even_on_a_dead_page(lead):
    """A 404 with parameters is still an injection point; a dead host with a
    CNAME is the shape of a subdomain takeover."""
    drop, _ = is_noise("info", "recon", {"status_code": 404, **lead})
    assert not drop, lead


def test_a_weakness_is_never_silenced_by_a_status_code():
    """An injection finding's status code says nothing about the injection."""
    for severity in ("critical", "high", "medium", "low"):
        drop, _ = is_noise(severity, "xss", {"status_code": 404})
        assert not drop, severity
    drop, _ = is_noise("info", "sql_injection", {"status_code": 404})
    assert not drop


def test_an_unfetched_url_is_kept():
    """Nobody recorded an answer, so nobody can say it is dead. An archived
    URL nothing has fetched sits here."""
    drop, _ = is_noise("info", "recon", {})
    assert not drop


def test_a_live_page_is_kept():
    for status in (200, 204, 301, 302):
        drop, _ = is_noise("info", "recon", {"status_code": status})
        assert not drop, status


# ---- it is applied in both places, from one rule ------------------------

def test_the_validator_drops_them_before_re_requesting():
    from app.validation import validator

    src = _inspect.getsource(validator.FindingValidator.validate)
    assert "is_noise(" in src
    assert src.index("is_noise(") < src.index("_check_against_baseline("), \
        "a dead page is re-requested before anyone checks the answer we have"


def test_a_dead_page_is_not_made_a_scan_target():
    """Pointing a scanner at a 404 spends budget to learn nothing - and with
    the asset ceiling raised so the whole live surface is kept, that is the
    difference between a large surface and a wasteful one."""
    from app.orchestrator import executor

    src = _inspect.getsource(executor)
    assert "_dead_page(meta)" in src
    assert "from app.validation.noise import is_noise" in src, \
        "the planner and the report must share one rule, or they drift"


def test_the_drop_is_announced():
    """An unexplained fall in the findings count is as unhelpful as the noise
    it replaced."""
    from app.validation import run as vrun

    src = _inspect.getsource(vrun.validate_engagement)
    assert "inventory finding(s) dropped" in src
    assert "dropped_dead_inventory" in src
