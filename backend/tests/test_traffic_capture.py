"""The traffic-driven checks had no traffic.

"IDOR, controle d'acces casse, JWT, secrets dans les bundles - met ca dans
run." They WERE in the run: run_analysis is called in finalisation. They had
no input.

analysis/logic.py (IDOR, BFLA, CSRF), access_control.py, jwt.py, js_recon and
everything that reads captured JavaScript all read FlowRepository - and
NOTHING routed tool traffic through the capture proxy. On an automated run the
flows table was empty, so every one of them ran against nothing. That is why
those classes only ever appeared after someone browsed the target by hand.
"""
from __future__ import annotations

import inspect as _inspect

import pytest

from app.scans.identity import CAPTURE_WORTH_IT, proxy_args, should_capture


# ---- what is captured, and what deliberately is not ---------------------

@pytest.mark.parametrize("tool", ["katana", "httpx"])
def test_the_tools_that_fetch_the_application_are_captured(tool):
    """katana fetches the pages AND the JavaScript - which is what js_recon,
    jsluice, retire.js and trufflehog need. httpx fetches each discovered
    endpoint with its headers and body, which is what the access-control and
    posture checks compare."""
    assert should_capture(tool)
    assert proxy_args(tool, "http://backend:8080"), \
        f"{tool} is on the capture list but has no proxy flag"


@pytest.mark.parametrize("tool", ["ffuf", "nuclei", "sqlmap", "commix", "gau"])
def test_the_payload_floods_are_not(tool):
    """Each makes thousands of requests that are payloads rather than
    application behaviour. Capturing them would fill the flow store - 2 MiB per
    body, no cap - and teach the analysers nothing."""
    assert not should_capture(tool)


def test_the_capture_list_is_small_on_purpose():
    assert len(CAPTURE_WORTH_IT) <= 3, sorted(CAPTURE_WORTH_IT)


# ---- it fails safe ------------------------------------------------------

def test_an_unreachable_proxy_yields_no_flag(monkeypatch):
    """Adding a proxy flag for a port nothing listens on would make every
    crawl fail - which is the exact failure mode this session has been
    chasing, so it is checked rather than assumed."""
    from app.proxy import capture

    monkeypatch.setenv("CAPTURE_PROXY_URL", "http://127.0.0.1:1/")
    assert capture.capture_proxy_url() == ""


def test_it_can_be_switched_off(monkeypatch):
    from app.proxy import capture

    monkeypatch.setenv("CAPTURE_PROXY", "off")
    assert capture.capture_proxy_url() == ""


def test_the_default_address_matches_how_the_proxy_is_deployed(monkeypatch):
    """The proxy container runs with `network_mode: service:backend`, so it
    shares the backend's network namespace and answers at the BACKEND's
    address - not at a hostname of its own. Getting that wrong routes the
    crawl into a black hole."""
    import pathlib

    from app.proxy import capture

    monkeypatch.delenv("CAPTURE_PROXY_URL", raising=False)
    monkeypatch.delenv("CAPTURE_PROXY", raising=False)
    monkeypatch.setattr(capture, "_reachable", lambda url, timeout=1.5: True)
    assert capture.capture_proxy_url() == "http://backend:8080"

    compose = (pathlib.Path(__file__).resolve().parents[2]
               / "docker-compose.yml").read_text()
    assert 'network_mode: "service:backend"' in compose, \
        "the proxy no longer shares the backend's namespace; the default is stale"


# ---- anonymity still wins ------------------------------------------------

def test_an_anonymity_proxy_takes_precedence():
    """A tool takes one proxy flag, and leaking the real IP is worse than
    missing some captured traffic."""
    from app.scans import runner

    src = _inspect.getsource(runner)
    anonymity = src.index("proxy = await netmgr.proxy_for_tools_shared()")
    capture = src.index("capture_proxy_url() if should_capture(tool)")
    assert anonymity < capture
    branch = src[anonymity:capture]
    assert "if proxy:" in branch and "else:" in branch, \
        "capture must be the else of the anonymity proxy, not an addition"


# ---- and the operator is told which of the two they got -----------------

def test_the_run_says_whether_it_is_capturing():
    """The difference between a run that can find an IDOR and one that cannot
    is worth one line at the start."""
    from app.orchestrator import loop

    src = _inspect.getsource(loop.run_engagement_loop)
    assert "_report_capture(engagement, run)" in src

    # These messages are split across adjacent string literals, so the text
    # the operator reads is not contiguous in the source. Join the whitespace
    # AND close the literal boundaries, or a phrase that straddles one matches
    # nothing and the assertion passes on air.
    report = " ".join(_inspect.getsource(loop._report_capture).split())
    report = report.replace('" "', "")
    assert "anonymity proxy is configured" in report, "the anonymity case"
    assert "capture proxy is not reachable" in report, "the unreachable case"
    assert "traffic is being captured" in report, "the working case"
