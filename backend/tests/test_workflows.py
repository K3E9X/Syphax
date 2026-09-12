"""CI workflow invariants.

The nightly answers "does what we ship still build?". Dispatching it against
another branch answers that question with someone else's code while labelling
the run with that branch - which is how a build of a 45-commit-old `preprod`
was read as a verdict on main, and how a naabu/arm64 gap that predated the
current tools looked like a regression from them.

These assertions are cheap and they pin the shape of the guard, not its
wording.
"""
from pathlib import Path

import pytest
import yaml   # declared in requirements-test.txt; a hard import so this test
               # fails loudly rather than vanishing if that pin is dropped

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
NIGHTLY = WORKFLOWS / "nightly.yml"
CI = WORKFLOWS / "ci.yml"


@pytest.fixture(scope="module")
def nightly():
    return yaml.safe_load(NIGHTLY.read_text(encoding="utf-8"))


def test_the_workflows_exist():
    assert NIGHTLY.is_file()
    assert CI.is_file()


def test_nightly_has_a_branch_guard(nightly):
    assert "guard" in nightly["jobs"], "the main-only guard job is gone"


def test_every_nightly_job_waits_on_the_guard(nightly):
    """A job without `needs: guard` runs on any dispatched branch, which is
    exactly the failure mode the guard exists to prevent."""
    unguarded = [
        name for name, job in nightly["jobs"].items()
        if name != "guard" and "guard" not in (
            [job.get("needs")] if isinstance(job.get("needs"), str)
            else (job.get("needs") or []))
    ]
    assert unguarded == [], f"jobs that would run off main: {unguarded}"


def test_the_guard_fails_rather_than_skips(nightly):
    """A green run that tested nothing is worse than a red one: it reads as a
    pass. So the guard exits non-zero instead of using an `if:` condition."""
    guard = nightly["jobs"]["guard"]
    assert "if" not in guard, "an if: makes the run green without testing"
    script = " ".join(str(s.get("run", "")) for s in guard["steps"])
    assert "exit 1" in script
    assert "main" in script


def test_the_guard_reads_the_branch_not_the_event(nightly):
    script = " ".join(str(s.get("run", "")) for s in nightly["jobs"]["guard"]["steps"])
    assert "github.ref_name" in script


def test_nightly_still_runs_on_a_schedule(nightly):
    """GitHub restricts `schedule` to the default branch, so the guard costs
    the scheduled run nothing - but the schedule has to still be there."""
    on = nightly.get("on") or nightly.get(True)   # PyYAML reads bare `on:` as True
    assert "schedule" in on
    assert "workflow_dispatch" in on


def test_the_download_check_runs_before_the_slow_build(nightly):
    """Three seconds of URL checks before twenty minutes of QEMU, or the next
    yanked asset is again found four minutes into an emulated build."""
    steps = nightly["jobs"]["docker"]["steps"]
    names = [s.get("name", "") for s in steps]
    checks = [i for i, n in enumerate(names) if "Pinned downloads" in n]
    builds = [i for i, n in enumerate(names) if "Build" in n]
    assert checks, "the pinned-download pre-check is gone"
    assert builds, "the image build is gone"
    assert min(checks) < min(builds)
