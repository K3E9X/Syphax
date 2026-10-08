"""Staging third-party PoCs for review.

The state machine is the safety feature: `staged` is a dead end until a person
moves it. Not default-allow with a cancel button, not a timeout that proceeds.
These tests pin that down, along with the fetch restrictions that decide what a
reviewer is even shown.
"""
from __future__ import annotations

import pytest

from app.sandbox.staging import (MAX_FILE_BYTES, STATUS_APPROVED,
                                 STATUS_EXECUTED, STATUS_REJECTED,
                                 STATUS_STAGED, can_transition, language_for,
                                 parse_repo_url, rank_candidates)


# ---- Only fetch from where the operator was shown ----

def test_github_repo_url_is_parsed():
    assert parse_repo_url("https://github.com/owner/CVE-2024-1234") == ("owner", "CVE-2024-1234")


def test_trailing_git_and_extra_path_are_handled():
    assert parse_repo_url("https://github.com/o/n.git") == ("o", "n")
    assert parse_repo_url("https://github.com/o/n/tree/main/src") == ("o", "n")


@pytest.mark.parametrize("url", [
    "https://gitlab.com/o/n",
    "https://raw.githubusercontent.com/o/n/main/x.py",
    "https://evil.example/o/n",
    "https://github.com/onlyowner",
    "file:///etc/passwd",
    "not a url",
    "",
])
def test_anything_but_a_github_repo_is_refused(url):
    """Staging must fetch from the same place the operator reviewed, or the
    review was of something else."""
    assert parse_repo_url(url) is None


# ---- What a reviewer is shown ----

@pytest.mark.parametrize("path,lang", [
    ("exploit.py", "python"), ("run.sh", "bash"), ("poc.js", "javascript"),
])
def test_runnable_extensions_are_recognised(path, lang):
    assert language_for(path) == lang


@pytest.mark.parametrize("path", ["README.md", "poc.bin", "notebook.ipynb", "a.exe"])
def test_unreadable_artifacts_are_not_staged(path):
    """A compiled binary is not something a human can read line by line, which
    is the only reason staging exists."""
    assert language_for(path) is None


def test_the_exploit_ranks_above_its_helpers():
    ranked = rank_candidates([
        {"type": "file", "path": "utils/helpers.py", "size": 100},
        {"type": "file", "path": "exploit.py", "size": 100},
    ])
    assert ranked[0]["path"] == "exploit.py"


def test_top_level_files_rank_above_buried_ones():
    ranked = rank_candidates([
        {"type": "file", "path": "tests/deep/nested/a.py", "size": 10},
        {"type": "file", "path": "a.py", "size": 10},
    ])
    assert ranked[0]["path"] == "a.py"


def test_oversized_files_are_dropped():
    assert rank_candidates(
        [{"type": "file", "path": "poc.py", "size": MAX_FILE_BYTES + 1}]) == []


def test_directories_and_junk_are_ignored():
    assert rank_candidates([
        {"type": "dir", "path": "src"},
        {"type": "file", "path": "README.md", "size": 10},
        None, "nope", {},
    ]) == []


def test_candidate_count_is_capped():
    entries = [{"type": "file", "path": f"poc{i}.py", "size": 10} for i in range(30)]
    assert len(rank_candidates(entries)) == 5


# ---- The state machine ----

def test_a_staged_poc_can_only_be_approved_or_rejected():
    assert can_transition(STATUS_STAGED, STATUS_APPROVED)
    assert can_transition(STATUS_STAGED, STATUS_REJECTED)


def test_staged_code_can_never_jump_straight_to_executed():
    """The human gate is the point: no path from staged to executed."""
    assert not can_transition(STATUS_STAGED, STATUS_EXECUTED)


def test_only_approved_code_can_execute():
    assert can_transition(STATUS_APPROVED, STATUS_EXECUTED)
    assert not can_transition(STATUS_REJECTED, STATUS_EXECUTED)


def test_rejection_is_final():
    for target in (STATUS_APPROVED, STATUS_EXECUTED, STATUS_REJECTED, STATUS_STAGED):
        assert not can_transition(STATUS_REJECTED, target)


def test_an_executed_poc_can_only_go_back_for_a_fresh_approval():
    """Not fully terminal any more, and on purpose.

    poc_run used to set "executed" whatever the exit code was, so a PoC that
    died on an environment problem - no HTTP client in the sandbox image,
    egress denied, a timeout - was stuck: the API only runs an APPROVED PoC and
    nothing could leave "executed". The operator had a dead row and no retry.

    poc_run only marks a clean run "executed" now, and re-approval is the one
    way out, so re-running still costs a deliberate human decision.
    """
    assert can_transition(STATUS_EXECUTED, STATUS_APPROVED)
    assert not can_transition(STATUS_EXECUTED, STATUS_EXECUTED)
    assert not can_transition(STATUS_EXECUTED, STATUS_STAGED)
    assert not can_transition(STATUS_EXECUTED, STATUS_REJECTED)


def test_a_failed_run_does_not_become_terminal():
    """The status only advances on a clean run, so a failure is retryable."""
    import inspect as _inspect

    from app.exploit import poc_run

    src = _inspect.getsource(poc_run.execute_poc)
    assert "if clean:" in src and "set_status" in src
    assert src.index("clean = result.exit_code == 0") < src.index(
        "await repo.set_status"), "the status must depend on the exit code"


def test_approval_cannot_be_reused_after_running():
    """One approval, one execution. Re-running needs a fresh decision."""
    assert not can_transition(STATUS_EXECUTED, STATUS_EXECUTED)


def test_an_approved_poc_can_still_be_rejected():
    """Second thoughts before the run must be possible."""
    assert can_transition(STATUS_APPROVED, STATUS_REJECTED)


def test_unknown_states_transition_nowhere():
    assert not can_transition("banana", STATUS_EXECUTED)
