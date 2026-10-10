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

from app.scans.wrappers import _WRAPPERS  # noqa: F401

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
def test_every_discovered_endpoint_becomes_a_scan_target(name):
    """THE requirement. Point the tool at a URL and the job is to find the
    endpoints and APIs behind it AND TEST THEM.

    An earlier version of this file asserted the opposite - that a flood is
    trimmed - and that was wrong: trimming live discovery throws away exactly
    the surface the operator asked to have found. What bounds the work is the
    planner's ranking and the per-phase budget, not a ceiling on what gets
    recorded.
    """
    findings = _parse(name)
    assets = [f for f in findings if (f.metadata or {}).get("asset")]
    assert len(assets) >= N, (
        f"{name} discovered {N} items and kept only {len(assets)} as scan "
        f"targets")
    for f in assets:
        assert f.metadata["asset_kind"] in ("endpoint", "host")


@pytest.mark.parametrize("name", sorted(FLOODS))
def test_nothing_is_summarised_away_when_nothing_is_hidden(name):
    """The summary row exists to report what was NOT listed. With live
    discovery keeping everything, there is nothing to report - and a summary
    claiming otherwise would be noise."""
    findings = _parse(name)
    summary = [f for f in findings if (f.metadata or {}).get("inventory")]
    assert summary == [], [f.title for f in summary]


def test_archive_material_is_the_one_thing_still_bounded():
    """gau returns a domain's HISTORICAL URLs, most of them long dead. That is
    the material worth trimming - and a parameterised archived URL is still an
    injection point, so it is the generous half of the two limits."""
    from app.scans.wrappers.gau import MAX_PARAM_FINDINGS, MAX_PLAIN_ASSETS

    lines = [f"{TARGET}archive/p{i}.jsp" for i in range(2500)]
    lines += [f"{TARGET}old.jsp?id={i}" for i in range(500)]
    out = _WRAPPERS["gau"].parse("\n".join(lines).encode(), b"", 0, TARGET)

    assets = [f for f in out.findings if (f.metadata or {}).get("asset")]
    assert len(assets) <= MAX_PARAM_FINDINGS + MAX_PLAIN_ASSETS
    params = [f for f in assets if (f.metadata or {}).get("has_params")]
    assert len(params) == MAX_PARAM_FINDINGS, len(params)

    summary = [f for f in out.findings if "archived URL(s)" in f.title]
    assert len(summary) == 1
    assert summary[0].metadata["archived_total"] >= 2000


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


def test_every_api_route_is_kept():
    """An undocumented API route IS the surface for the auth, BOLA and
    injection tests. Capping these was the worst of the trimming."""
    routes = [f for f in _parse("kiterunner")
              if (f.metadata or {}).get("vuln_class") == "api_route"]
    assert len(routes) == N, len(routes)


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


@pytest.mark.parametrize("name", sorted(FLOODS))
def test_the_ingest_cap_never_drops_a_scan_target(name):
    """The per-job cap is about how much one job may add to the REPORT. A row
    that declares an asset is a target, and the planner decides what to do with
    it - so the cap must not be the thing that unfinds an endpoint."""
    from app.scans.wrappers.base import cap_findings

    wrapper = _WRAPPERS[name]
    findings = _parse(name)
    before = [f for f in findings if (f.metadata or {}).get("asset")]
    after = [f for f in cap_findings(findings, tool=name,
                                     category=wrapper.category)
             if (f.metadata or {}).get("asset")]
    assert len(after) == len(before), (
        f"the ingest cap dropped {len(before) - len(after)} scan targets")


def test_gau_terminates_when_there_are_fewer_urls_than_the_allowance():
    """A round-robin whose exit condition is "every list is empty" never ends,
    because the lists are never drained - it hung the whole test suite. The
    exit has to be "a full pass added nothing"."""
    out = _WRAPPERS["gau"].parse(
        (f"{TARGET}a.jsp?id=1\n{TARGET}b.jsp?id=2\n{TARGET}plain.jsp\n").encode(),
        b"", 0, TARGET)
    params = [f for f in out.findings if (f.metadata or {}).get("has_params")]
    assert len(params) == 2


def test_gau_spreads_its_allowance_across_distinct_paths():
    """One endpoint archived under five hundred timestamps must not use the
    whole allowance and hide the other endpoints behind it."""
    lines = [f"{TARGET}hot.jsp?t={i}" for i in range(500)]
    lines += [f"{TARGET}other{i}.jsp?id=1" for i in range(20)]
    out = _WRAPPERS["gau"].parse("\n".join(lines).encode(), b"", 0, TARGET)
    kept = [f.target for f in out.findings
            if (f.metadata or {}).get("has_params")]
    distinct = {u.split("?")[0] for u in kept}
    assert len(distinct) == 21, len(distinct)


def test_gau_reads_past_the_first_few_thousand_lines():
    """An archive commonly returns thousands of plain paths before the first
    parameterised one. Stopping at 2000 input lines meant the injection points
    - the whole reason to look at an archive - were never seen."""
    lines = [f"{TARGET}archive/p{i}.jsp" for i in range(5000)]
    lines += [f"{TARGET}late.jsp?id=1"]
    out = _WRAPPERS["gau"].parse("\n".join(lines).encode(), b"", 0, TARGET)
    assert any((f.metadata or {}).get("has_params") for f in out.findings), \
        "the parameterised URL after 5000 plain ones was never reached"
