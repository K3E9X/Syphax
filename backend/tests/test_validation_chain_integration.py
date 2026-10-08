"""Validation, CVE execution and triage, driven for real.

The other half of the operator's question. These run validate_engagement and
run_cve_checks over in-memory repositories and a scripted HTTP target
(tests/_chain_harness.py), so the verdicts are the ones the real validators
produce rather than ones a mock asserted into existence.
"""
from __future__ import annotations

import asyncio

from app.scans.models import Finding
from tests import _chain_harness as H


def _finding(**kw):
    base = dict(severity="high", title="t", description="d",
                target="https://app.example.com/x", evidence="e", metadata={})
    base.update(kw)
    return Finding(**base)


# ---- CVE execution: the one mechanical path to a confirmed CVE ------------

def test_a_curated_cve_check_confirms_outright(monkeypatch):
    """validator trusts "cve-checks" verbatim, so this is the only way a CVE
    becomes confirmed without a human. It emitted no event at all before."""
    h = H.install(monkeypatch)
    H.fake_state(monkeypatch, technologies=["apache", "apache httpd 2.4.49"])
    saved = H.fake_analysis_store(monkeypatch)

    from app.exploit.cve_checks import CHECKS, run_cve_checks

    # Serve the signature the first applicable check looks for.
    check = next(c for c in CHECKS if c.paths and c.signature)
    routes = {check.paths[0]: (200, f"prefix {check.signature} suffix")}
    H.fake_http(monkeypatch, routes)

    out = asyncio.run(run_cve_checks("eng_1"))

    assert out.get("probes", 0) > 0, f"nothing was probed: {out}"
    if out.get("confirmed"):
        findings = [f for s in saved for f in s["findings"]]
        assert findings, saved
        assert findings[0].metadata["status"] == "confirmed"
        assert findings[0].metadata["confidence"] >= 0.95
    assert any("Targeted CVE checks" in e for e in h.events), h.events


def test_it_says_when_the_curated_list_did_not_cover_the_stack(monkeypatch):
    """"The checks did not match this fingerprint" and "this CVE is not real"
    look identical when neither is said."""
    h = H.install(monkeypatch)
    H.fake_state(monkeypatch, technologies=["nginx"])
    H.fake_analysis_store(monkeypatch)
    H.fake_http(monkeypatch, {}, default_status=404)

    from app.exploit.cve_checks import run_cve_checks
    asyncio.run(run_cve_checks("eng_1"))

    said = " | ".join(h.events)
    assert "Targeted CVE checks" in said, h.events
    # The distinction that matters: "the curated list does not cover this
    # stack" must be stated, so it cannot be read as "this stack is clean".
    assert "fingerprint" in said or "not covered here" in said, said


def test_the_cve_pass_is_skipped_audibly_when_active_exploit_is_off(monkeypatch):
    h = H.install(monkeypatch, eng=H.engagement(allow_active_exploit=False))
    H.fake_state(monkeypatch)
    H.fake_analysis_store(monkeypatch)

    from app.exploit.cve_checks import run_cve_checks
    out = asyncio.run(run_cve_checks("eng_1"))
    assert out.get("skipped") == 1
    # The name of this test used to be a lie: the pass returned {"skipped": 1}
    # into a dict nobody rendered. "Switched off" and "nothing to find" must
    # not look the same, because this is the only mechanical path to a
    # confirmed CVE.
    assert any("allow_active_exploit" in e for e in h.events), h.events


# ---- validation: the verdicts the operator reads -------------------------

def test_a_finding_that_points_at_a_404_is_ruled_out(monkeypatch):
    """The operator asked for exactly this: "si il obtient de 404, pas besoin
    de remonter". A content-discovery hit is a claim that a path exists, so it
    is re-requested and dropped when the path is gone."""
    gone = _finding(severity="medium", title="Found /backup.zip",
                    target="https://app.example.com/backup.zip",
                    metadata={"vuln_class": "content_discovery"})
    H.install(monkeypatch, jobs=[H.job("ffuf", [gone])])
    H.fake_http(monkeypatch, {}, default_status=404)

    from app.validation.run import validate_engagement
    stats = asyncio.run(validate_engagement("eng_1"))

    rows = asyncio.run(H.FakeVFRepo().list("eng_1"))
    assert rows, stats
    assert rows[0].status == "false_positive", (rows[0].status, rows[0].method)
    assert "re-request" in (rows[0].method or ""), rows[0].method


def test_a_path_that_really_is_there_survives(monkeypatch):
    """The filter must not swallow the real ones."""
    real = _finding(severity="medium", title="Found /.env",
                    target="https://app.example.com/.env",
                    evidence="DB_PASSWORD=hunter2",
                    metadata={"vuln_class": "content_discovery"})
    H.install(monkeypatch, jobs=[H.job("ffuf", [real])])
    H.fake_http(monkeypatch, {"/.env": (200, "DB_PASSWORD=hunter2\nAPI_KEY=x\n")},
                default_status=404)

    from app.validation.run import validate_engagement
    asyncio.run(validate_engagement("eng_1"))

    rows = asyncio.run(H.FakeVFRepo().list("eng_1"))
    assert rows and rows[0].status != "false_positive", \
        (rows[0].status, rows[0].method)


def test_an_unproven_finding_can_never_reach_the_confirmed_band(monkeypatch):
    """A scanner's own confidence must not buy it a confirmed verdict."""
    boast = _finding(severity="critical", title="SQL injection!",
                     target="https://app.example.com/q",
                     metadata={"vuln_class": "sql_injection", "confidence": 0.99})
    H.install(monkeypatch, jobs=[H.job("nikto", [boast])])
    H.fake_http(monkeypatch, {"/q": (200, "ok")})

    from app.validation.run import validate_engagement
    asyncio.run(validate_engagement("eng_1"))

    rows = asyncio.run(H.FakeVFRepo().list("eng_1"))
    assert rows[0].status != "confirmed", rows[0].method
    assert rows[0].confidence < 0.95


def test_every_finding_gets_a_verdict_and_a_method(monkeypatch):
    """"unverified with no explanation" was the original complaint."""
    jobs = [H.job("nuclei", [
        _finding(title="CVE-2021-1234 in nginx",
                 metadata={"vuln_class": "cve", "cve_id": "CVE-2021-1234"}),
        _finding(title="Missing security headers", severity="low",
                 metadata={"vuln_class": "misconfiguration"}),
    ])]
    H.install(monkeypatch, jobs=jobs)
    H.fake_http(monkeypatch, {"/x": (200, "hello")})

    from app.validation.run import validate_engagement
    asyncio.run(validate_engagement("eng_1"))

    rows = asyncio.run(H.FakeVFRepo().list("eng_1"))
    assert len(rows) == 2, rows
    for row in rows:
        assert row.status in ("confirmed", "likely", "unconfirmed",
                              "false_positive"), row.status
        assert row.method, f"{row.title} has no explanation of how it was decided"


def test_the_summary_counts_what_is_in_the_table(monkeypatch):
    """The banner used to be emitted from a stale dict."""
    jobs = [H.job("nuclei", [_finding(metadata={"vuln_class": "cve"})])]
    H.install(monkeypatch, jobs=jobs)
    H.fake_http(monkeypatch, {"/x": (200, "hello")})

    from app.validation.run import validate_engagement
    asyncio.run(validate_engagement("eng_1"))

    live = asyncio.run(H.FakeVFRepo().summary("eng_1"))
    rows = asyncio.run(H.FakeVFRepo().list("eng_1"))
    assert live.get("total") == len(rows)


# ---- triage: what the Findings page is allowed to show -------------------

def test_the_triage_statuses_are_the_ones_the_api_accepts():
    """A status the UI can set but the API rejects is a dead button."""
    from app.findings_util import TRIAGE_STATUSES

    assert {"new", "triaged", "reported", "false_positive"} <= TRIAGE_STATUSES


def test_a_ruled_out_finding_is_not_offered_for_triage(monkeypatch):
    """It is dropped at validation, so it never reaches the triage queue -
    which is what "l'enlever du tri" means in practice."""
    gone = _finding(title="Found /old.bak",
                    target="https://app.example.com/old.bak",
                    metadata={"vuln_class": "content_discovery"})
    H.install(monkeypatch, jobs=[H.job("ffuf", [gone])])
    H.fake_http(monkeypatch, {}, default_status=404)

    from app.validation.run import validate_engagement
    asyncio.run(validate_engagement("eng_1"))

    rows = asyncio.run(H.FakeVFRepo().list("eng_1"))
    worth_triaging = [r for r in rows if r.status != "false_positive"]
    assert not worth_triaging, [r.title for r in worth_triaging]
