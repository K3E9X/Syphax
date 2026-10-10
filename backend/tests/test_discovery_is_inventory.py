"""A discovery tool reports surface, and surface is assets - not findings.

gau turned a domain's archive into 2175 findings and 2162 assets, and the run
spent its whole time budget on them. Capping the volume stopped the bleeding;
this is the actual model the project already had and the wrappers ignored:
`SURFACE_CLASSES` in validation, and a separate `assets` table.

Six wrappers had the same shape - katana, ffuf, httpx, subfinder, dnsx and
kiterunner - each emitting one finding per item it found, with no cap at all.
These drive every one of them with a flood in its own output format.
"""
from __future__ import annotations

import json

import pytest

from app.scans.wrappers import _WRAPPERS

TARGET = "https://t.example/"
N = 800


def _jsonl(objs) -> bytes:
    return "\n".join(json.dumps(o) for o in objs).encode()


# Each entry: the wrapper, a flood in its real output format, and how many of
# those items deserve a row of their own.
FLOODS = {
    "katana": _jsonl(
        [{"request": {"endpoint": f"{TARGET}page{i}.jsp", "method": "GET"},
          "response": {"status_code": 200}} for i in range(N)]
        + [{"request": {"endpoint": f"{TARGET}search.jsp?q={i}", "method": "GET"},
            "response": {"status_code": 200}} for i in range(5)]),
    "httpx": _jsonl(
        [{"url": f"{TARGET}p{i}", "status_code": 200} for i in range(N)]
        + [{"url": f"{TARGET}guarded", "status_code": 403}]),
    "subfinder": _jsonl(
        [{"host": f"h{i}.t.example", "source": "crtsh"} for i in range(N)]),
    "dnsx": _jsonl(
        [{"host": f"h{i}.t.example", "a": ["1.2.3.4"]} for i in range(N)]
        + [{"host": "cdn.t.example", "cname": ["x.cloudfront.net"]}]),
    "kiterunner": _jsonl(
        [{"url": f"{TARGET}api/v1/r{i}", "status": 200} for i in range(N)]),
    "ffuf": json.dumps({"results": [
        {"url": f"{TARGET}p{i}", "status": 200, "length": 10, "words": 2,
         "input": {"FUZZ": f"p{i}"}} for i in range(N)
    ] + [
        {"url": f"{TARGET}admin", "status": 403, "length": 10, "words": 2,
         "input": {"FUZZ": "admin"}}
    ]}).encode(),
}


def _parse(name: str):
    wrapper = _WRAPPERS[name]
    return wrapper.parse(FLOODS[name], b"", 0, TARGET).findings


@pytest.mark.parametrize("name", sorted(FLOODS))
def test_a_flood_does_not_become_a_finding_each(name):
    findings = _parse(name)
    assert len(findings) < N / 2, (
        f"{name} produced {len(findings)} findings from {N} discovered items")


@pytest.mark.parametrize("name", sorted(FLOODS))
def test_the_real_total_is_still_reported(name):
    """Bounding the output must not hide how much surface there is."""
    findings = _parse(name)
    summary = [f for f in findings if (f.metadata or {}).get("inventory")]
    assert len(summary) == 1, [f.title for f in findings[:5]]
    assert summary[0].metadata["total"] >= N


@pytest.mark.parametrize("name", sorted(FLOODS))
def test_what_is_kept_is_declared_as_a_scan_target(name):
    """The point of keeping any of it: the planner aims tools at assets."""
    findings = _parse(name)
    assets = [f for f in findings if (f.metadata or {}).get("asset")]
    assert assets, f"{name} kept nothing the planner can use"
    for f in assets:
        assert f.metadata["asset_kind"] in ("endpoint", "host")


# ---- and the few that are leads keep their row --------------------------

def test_katana_keeps_the_parameterised_urls():
    """A URL with a query string is an injection point, and the seven
    param-gated catalog items need one to exist."""
    kept = [f for f in _parse("katana")
            if (f.metadata or {}).get("has_params")]
    assert len(kept) == 5, len(kept)


def test_httpx_keeps_what_did_not_answer_a_plain_200():
    kept = [f for f in _parse("httpx")
            if (f.metadata or {}).get("status_code") == 403]
    assert len(kept) == 1


def test_ffuf_keeps_a_guarded_path():
    """A 401/403 says something is there and guarded - that is the lead."""
    kept = [f for f in _parse("ffuf") if (f.metadata or {}).get("status") == 403]
    assert len(kept) == 1


def test_dnsx_keeps_a_cname():
    """The one DNS record that is a lead: it points somewhere else, which is
    where a subdomain takeover lives."""
    kept = [f for f in _parse("dnsx") if (f.metadata or {}).get("cname")]
    assert len(kept) == 1


def test_kiterunner_keeps_more_than_a_crawl_does():
    """An undocumented API route IS the surface for the auth, BOLA and
    injection tests, so its cap is deliberately higher than a crawl's."""
    routes = [f for f in _parse("kiterunner")
              if (f.metadata or {}).get("vuln_class") == "api_route"]
    crawled = [f for f in _parse("katana") if (f.metadata or {}).get("asset")]
    assert len(routes) > 60, len(routes)
    assert len(routes) >= len(crawled) - 60


# ---- a short run is untouched ------------------------------------------

@pytest.mark.parametrize("name", sorted(FLOODS))
def test_a_handful_of_results_passes_through_unchanged(name):
    """The splitting must not add a summary to a job that found three things."""
    wrapper = _WRAPPERS[name]
    if name == "ffuf":
        small = json.dumps({"results": [
            {"url": f"{TARGET}a", "status": 200, "length": 1, "words": 1,
             "input": {"FUZZ": "a"}}]}).encode()
    elif name == "katana":
        small = _jsonl([{"request": {"endpoint": f"{TARGET}a", "method": "GET"}}])
    elif name == "httpx":
        small = _jsonl([{"url": f"{TARGET}a", "status_code": 200}])
    elif name == "subfinder":
        small = _jsonl([{"host": "a.t.example", "source": "x"}])
    elif name == "dnsx":
        small = _jsonl([{"host": "a.t.example", "a": ["1.2.3.4"]}])
    else:
        small = _jsonl([{"url": f"{TARGET}api/a", "status": 200}])

    findings = wrapper.parse(small, b"", 0, TARGET).findings
    assert len(findings) == 1, [f.title for f in findings]
    assert not (findings[0].metadata or {}).get("inventory")
