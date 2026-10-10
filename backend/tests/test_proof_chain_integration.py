"""The proof chain, driven end to end with the real modules.

The operator's question, after four rounds of fixes that each turned out to be
downstream of the next: does exploitation actually work - the LLM writing a
payload, a public PoC, a CVE check, validation, triage?

It could not be answered from this suite, because every test in it was a unit
test that never touched the database (conftest.py says so). That is how the
planner could spend a run's entire budget before reaching the exploitation
phase with two thousand tests green. These drive validate_engagement,
run_campaign, strategy, authoring, refine, poc_run and cve_checks for real,
over in-memory repositories (tests/_chain_harness.py).
"""
from __future__ import annotations

import asyncio
import time

from app.validation.models import ValidatedFinding
from tests import _chain_harness as H

# What the model is actually told to produce.
#
# authoring.py's prompt says "use only the standard library plus `requests`"
# and "POST, PUT and DELETE against the target are expected". A GET-only PoC
# would sail through the operator-safety inspection whatever its rules said, so
# a test built on one proves nothing about the gate: `requests.post(` and
# `os.environ` are what made every real exploit "suspicious", which the
# auto-run gate then refused. This shape exercises that.
WORKING_POC = """```python
import os
import sys
import requests

target = sys.argv[1] if len(sys.argv) > 1 else "https://app.example.com/"
session = requests.Session()
session.headers["User-Agent"] = os.environ.get("UA", "syphax")
r = session.post(target, data={"id": 2}, timeout=10)
print("retrieved another user's invoice:", r.text[:120])
sys.exit(0)
```"""

FAILING_POC = """```python
import sys
print("could not reach the parameter")
sys.exit(1)
```"""


# What sandbox-runner/Dockerfile actually installs, read from the Dockerfile so
# the two cannot drift apart silently.
def _sandbox_python_packages():
    import pathlib as _p
    import re as _re
    text = (_p.Path(__file__).resolve().parents[2]
            / "sandbox-runner" / "Dockerfile").read_text()
    return set(_re.findall(r"([a-zA-Z0-9_.\-]+)==", text))


_SANDBOX_PYTHON_PACKAGES = _sandbox_python_packages()


def _vf(**kw):
    base = dict(
        id="vf_1", engagement_id="eng_1", source_job_id="job_x", tool="logic",
        vuln_class="idor", severity="high", title="IDOR on /invoice",
        target="https://app.example.com/invoice", status="likely",
        confidence=0.6, method="traffic analysis", poc="", evidence="id=1 -> id=2",
        created_at=time.time(), metadata={"vuln_class": "idor"},
    )
    base.update(kw)
    return ValidatedFinding(**base)


def _sandbox_ok(code, language, argv):
    # The image must actually have the client the code imports - that is the
    # defect this stands in for: the sandbox shipped without `requests` while
    # the authoring prompt promised it, so every PoC died on ImportError.
    if language == "python" and "requests" in code:
        assert "requests" in _SANDBOX_PYTHON_PACKAGES
    return {"exit_code": 0, "stdout": "retrieved another user's invoice: {...}"}


def _sandbox_fail(code, language, argv):
    return {"exit_code": 1, "stdout": "", "stderr": "connection refused"}


# ---- the question: does the model write an exploit, run it, and prove it? --

def test_the_model_writes_an_exploit_runs_it_and_the_finding_becomes_confirmed(
        monkeypatch):
    h = H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=WORKING_POC)
    H.FakeVFRepo.store["vf_1"] = _vf()

    from app.exploit.campaign import run_campaign
    summary = asyncio.run(run_campaign("eng_1"))

    vf = H.FakeVFRepo.store["vf_1"]
    assert vf.status == "confirmed", (
        f"the chain ran and proved nothing: {summary} / events={h.events}")
    assert vf.confidence >= 0.95
    assert vf.metadata.get("proven") is True
    assert summary.get("proven", 0) >= 1, summary


def test_the_exploitation_is_recorded_as_evidence(monkeypatch):
    """"It says confirmed" is not enough - the report needs what it returned."""
    H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=WORKING_POC)
    H.FakeVFRepo.store["vf_1"] = _vf()

    from app.exploit.campaign import run_campaign
    asyncio.run(run_campaign("eng_1"))

    exploitation = H.FakeVFRepo.store["vf_1"].metadata.get("exploitation") or {}
    assert exploitation, "no exploitation record was attached"
    assert "invoice" in str(exploitation).lower() or exploitation.get("stdout")


def test_a_staged_poc_exists_for_the_operator_to_read(monkeypatch):
    H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=WORKING_POC)
    H.FakeVFRepo.store["vf_1"] = _vf()

    from app.exploit.campaign import run_campaign
    asyncio.run(run_campaign("eng_1"))

    pocs = asyncio.run(H.FakeStagedRepo().list("eng_1"))
    assert pocs, "nothing was staged, so the PoC view would be empty"
    assert pocs[0].finding_id == "vf_1"
    assert "requests" in pocs[0].code


def test_an_exploit_that_does_not_work_leaves_the_finding_alone(monkeypatch):
    """The operator asked for exactly this: if it works, say exploited; if not,
    do not claim it."""
    H.install(monkeypatch, sandbox=_sandbox_fail, llm_reply=FAILING_POC)
    H.FakeVFRepo.store["vf_1"] = _vf()

    from app.exploit.campaign import run_campaign
    summary = asyncio.run(run_campaign("eng_1"))

    vf = H.FakeVFRepo.store["vf_1"]
    assert vf.status == "likely", "a failed exploit must not confirm anything"
    assert vf.metadata.get("proven") is not True
    assert summary.get("proven", 0) == 0


def test_the_operator_is_told_what_happened(monkeypatch):
    H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=WORKING_POC)
    H.FakeVFRepo.store["vf_1"] = _vf()

    from app.exploit.campaign import run_campaign
    h_events = []
    H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=WORKING_POC,
              events_sink=h_events)
    H.FakeVFRepo.store["vf_1"] = _vf()
    asyncio.run(run_campaign("eng_1"))

    joined = " | ".join(h_events)
    assert "Exploit" in joined, joined
    assert "PROVEN" in joined.upper(), joined


# ---- no model configured: the deterministic half must still work ----------

def test_without_a_model_the_run_says_so_instead_of_going_quiet(monkeypatch):
    h = H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=None)
    H.FakeVFRepo.store["vf_1"] = _vf()

    from app.exploit.campaign import run_campaign
    summary = asyncio.run(run_campaign("eng_1"))

    assert H.FakeVFRepo.store["vf_1"].status == "likely"
    joined = " | ".join(h.events)
    assert "Exploit" in joined, f"silent: {summary} {h.events}"


# ---- no sandbox: must refuse audibly, not report a failed exploit ---------

def test_without_a_sandbox_nothing_claims_to_have_run(monkeypatch):
    h = H.install(monkeypatch, sandbox=None, llm_reply=WORKING_POC)
    H.FakeVFRepo.store["vf_1"] = _vf()

    from app.exploit.campaign import run_campaign
    asyncio.run(run_campaign("eng_1"))

    assert H.FakeVFRepo.store["vf_1"].status == "likely"
    # Only the per-finding attempt lines, not the summary - which legitimately
    # contains the phrase "0 proven by a clean sandbox run".
    attempts = [e for e in h.events if e.startswith("Exploit [")]
    assert attempts, h.events
    assert not any("PROVEN" in a.upper() for a in attempts), \
        f"a run with no sandbox claimed proof: {attempts}"
    # And it must say the PoC was written but not run, rather than go quiet.
    assert any("staged" in a or "not run" in a for a in attempts), attempts


# ---- a finding with no route is reported, not dropped --------------------

def test_a_class_with_no_route_is_named(monkeypatch):
    h = H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=WORKING_POC)
    H.FakeVFRepo.store["vf_s"] = _vf(
        id="vf_s", vuln_class="fingerprint", severity="info",
        title="Server banner", tool="httpx")

    from app.exploit.campaign import run_campaign
    summary = asyncio.run(run_campaign("eng_1"))

    assert summary.get("skipped", 0) >= 1, summary
    joined = " | ".join(h.events)
    assert "Exploit [none]" in joined, joined


# ---- re-validation must not destroy what was proven ----------------------

def test_proof_survives_a_second_validation(monkeypatch):
    """The whole point of the stable finding id. A re-validation rebuilds every
    row from the raw job findings, which know nothing about a PoC that ran
    afterwards."""
    H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=WORKING_POC)
    H.FakeVFRepo.store["vf_1"] = _vf()

    from app.exploit.campaign import run_campaign
    asyncio.run(run_campaign("eng_1"))
    assert H.FakeVFRepo.store["vf_1"].status == "confirmed"

    # Now re-validate: same finding identity, fresh row.
    from app.validation.run import _carry_over_proof
    rebuilt = [_vf(id="vf_rebuilt", status="likely", confidence=0.6, metadata={})]
    carried = asyncio.run(_carry_over_proof(H.FakeVFRepo(), "eng_1", rebuilt))

    assert carried == 1, "the proof was not carried across"
    assert rebuilt[0].status == "confirmed"
    assert rebuilt[0].metadata.get("exploitation")


def test_a_staged_poc_follows_its_finding_to_the_new_id(monkeypatch):
    H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=WORKING_POC)
    H.FakeVFRepo.store["vf_1"] = _vf()

    from app.exploit.campaign import run_campaign
    asyncio.run(run_campaign("eng_1"))

    from app.validation.run import _repoint_staged_pocs
    rebuilt = [_vf(id="vf_new_id", status="likely", metadata={})]
    moved = asyncio.run(_repoint_staged_pocs(H.FakeVFRepo(), "eng_1", rebuilt))

    assert moved >= 1, "the PoC was left pointing at a row about to be deleted"
    pocs = asyncio.run(H.FakeStagedRepo().list("eng_1"))
    assert all(p.finding_id == "vf_new_id" for p in pocs)


# ---- the public-PoC route ------------------------------------------------

def test_a_published_exploit_is_fetched_staged_and_run(monkeypatch):
    """ROUTE_PUBLIC_POC, with the GitHub fetch faked at the staging edge."""
    H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=None)
    H.FakeVFRepo.store["vf_cve"] = _vf(
        id="vf_cve", vuln_class="cve", tool="nuclei", severity="critical",
        title="CVE-2021-41773 path traversal",
        metadata={"vuln_class": "cve", "cve_id": "CVE-2021-41773"})

    from app.exploit import campaign

    async def _files(owner, name, *, token=None):
        return [{"path": "exploit.py", "language": "python", "size": 400}]

    async def _file(owner, name, path, *, token=None):
        return ("import sys, requests\n"
                "print(requests.get(sys.argv[1]).text[:80])\nsys.exit(0)\n")

    async def _pocs_by_cve(_eid):
        return {"CVE-2021-41773": [
            {"source": "github", "ref": "https://github.com/x/CVE-2021-41773",
             "runnable": "sandbox", "title": "poc"}]}

    monkeypatch.setattr(campaign, "fetch_repo_files", _files)
    monkeypatch.setattr(campaign, "fetch_file", _file)
    monkeypatch.setattr(campaign, "_public_exploits_by_cve", _pocs_by_cve)

    summary = asyncio.run(campaign.run_campaign("eng_1"))

    pocs = asyncio.run(H.FakeStagedRepo().list("eng_1"))
    assert pocs, f"no published PoC was staged: {summary}"
    assert pocs[0].repo == "x/CVE-2021-41773"
    assert H.FakeVFRepo.store["vf_cve"].status == "confirmed", summary


# ---- the two ways an authored PoC can be proven ---------------------------
#
# With the refine loop on (the default, EXPLOIT_REFINE_ITERATIONS=2) the model
# rehearses its PoC in the sandbox and the rehearsal verdict IS the proof. With
# it off, the PoC is written blind and the auto-run gate decides whether it runs
# at all. Both paths have to work, and they fail for different reasons - so a
# test that only exercises one leaves the other free to break.

def test_with_the_refine_loop_off_the_gate_still_lets_it_run(monkeypatch):
    """This is the path the auto-run gate governs.

    The gate used to demand inspection verdict == "review" - "no rule matched
    at all" - and a realistic exploit reads an environment variable, which is
    filed as credential_access at SEV_HIGH and makes the verdict "suspicious".
    So every PoC written without a rehearsal was staged and never fired.
    """
    h = H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=WORKING_POC)

    async def _no_refine():
        return 0

    monkeypatch.setattr("app.exploit.settings_live.refine_iterations", _no_refine)
    H.FakeVFRepo.store["vf_1"] = _vf()

    from app.exploit.campaign import run_campaign
    summary = asyncio.run(run_campaign("eng_1"))

    vf = H.FakeVFRepo.store["vf_1"]
    assert vf.status == "confirmed", (
        f"single-shot authoring proved nothing: {summary} / {h.events}")
    assert vf.metadata.get("proven") is True


def test_the_poc_the_model_writes_is_the_shape_the_gate_has_to_accept():
    """Guards the test above against becoming vacuous.

    If WORKING_POC stops tripping any inspection rule it lands on "review",
    both the old and the new gate accept it, and the test proves nothing. The
    prompt demands a POST and real exploits read their configuration, so
    "suspicious" is what the gate must tolerate.
    """
    from app.exploit.authoring import extract_code
    from app.sandbox.inspect import inspect_code

    code, _language = extract_code(WORKING_POC)
    report = inspect_code(code, filename="poc.py",
                          scope_hosts=["app.example.com"])
    assert report.verdict == "suspicious", (
        f"this PoC no longer exercises the gate ({report.verdict}): "
        f"{report.summary}")
    assert report.verdict != "hostile", "and it must not be refused outright"


def test_the_same_published_exploit_is_staged_once(monkeypatch):
    """Two findings sharing a CVE each staged their own copy, so the queue
    filled with identical rows - four of RoflSecurity/nodeloris/nodeloris.js in
    one engagement - and a reviewer had to read the same script four times."""
    H.install(monkeypatch, sandbox=_sandbox_ok, llm_reply=None)
    for i in (1, 2):
        H.FakeVFRepo.store[f"vf_cve{i}"] = _vf(
            id=f"vf_cve{i}", vuln_class="cve", tool="nuclei", severity="critical",
            title=f"CVE-2021-41773 on host {i}",
            target=f"https://app.example.com/{i}",
            metadata={"vuln_class": "cve", "cve_id": "CVE-2021-41773"})

    from app.exploit import campaign

    async def _files(owner, name, *, token=None):
        return [{"path": "exploit.py", "language": "python", "size": 400}]

    async def _file(owner, name, path, *, token=None):
        return "import sys, requests\nprint(requests.get(sys.argv[1]).text)\n"

    async def _pocs_by_cve(_eid):
        return {"CVE-2021-41773": [
            {"source": "github", "ref": "https://github.com/x/CVE-2021-41773",
             "runnable": "sandbox", "title": "poc"}]}

    monkeypatch.setattr(campaign, "fetch_repo_files", _files)
    monkeypatch.setattr(campaign, "fetch_file", _file)
    monkeypatch.setattr(campaign, "_public_exploits_by_cve", _pocs_by_cve)

    asyncio.run(campaign.run_campaign("eng_1"))

    pocs = asyncio.run(H.FakeStagedRepo().list("eng_1"))
    same = [p for p in pocs if p.repo == "x/CVE-2021-41773"]
    assert len(same) == 1, f"{len(same)} copies of the same published exploit"
