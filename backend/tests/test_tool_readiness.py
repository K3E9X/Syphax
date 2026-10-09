"""A tool can be installed and still find nothing.

Five rounds of fixes in, a run on two deliberately vulnerable lab sites still
reported only "info" findings. `is_available()` answers "is the binary on
PATH", and for three tools that is not the same question:

  * nuclei with an empty template directory scans for nothing. It exits 0 and
    prints nothing, so a target full of known CVEs comes back clean. The image
    downloads its templates with `nuclei -update-templates -silent || true`, so
    a throttled or offline build ships a working binary with no templates - and
    the build succeeds. Five catalog items and every -dast injection family run
    nuclei, so that one `|| true` can account for a whole run finding nothing.
  * ffuf without its wordlist fuzzes an empty list.
  * kiterunner without its .kite route database replays no routes.

All three are indistinguishable from a clean target, which is the failure mode
this suite exists to make impossible to hide.
"""
from __future__ import annotations

import inspect as _inspect

import pytest

from app.scans.wrappers import _WRAPPERS, not_ready, preflight
from app.scans.wrappers.base import BaseWrapper, _missing_data


# ---- the distinction itself ----------------------------------------------

def test_a_missing_data_file_is_not_the_same_as_a_missing_binary(tmp_path,
                                                                monkeypatch):
    class _Tool(BaseWrapper):
        name = "fake"
        binary = "sh"            # certainly installed
        required_data = ((str(tmp_path / "wordlist.txt"), "the wordlist"),)

    tool = _Tool()
    assert tool.is_available() is True, "sh should be on PATH"
    state = tool.readiness()
    assert state.installed is True
    assert state.ready is False, "a missing wordlist must not read as ready"
    assert "the wordlist" in state.reason
    assert "find nothing" in state.reason


def test_an_empty_directory_counts_as_missing(tmp_path):
    """The nuclei failure mode exactly: the directory exists, and is empty."""
    empty = tmp_path / "nuclei-templates"
    empty.mkdir()
    assert _missing_data(str(empty)) == "empty"

    (empty / "nested").mkdir()
    assert _missing_data(str(empty)) == "empty", "still empty: only dirs"

    (empty / "nested" / "cve.yaml").write_text("id: x\n")
    assert _missing_data(str(empty)) == "", "one template is enough"


def test_an_empty_file_counts_as_missing(tmp_path):
    f = tmp_path / "common.txt"
    f.write_text("")
    assert _missing_data(str(f)) == "empty"
    f.write_text("admin\n")
    assert _missing_data(str(f)) == ""


def test_a_tool_with_no_data_dependency_is_ready_when_installed():
    class _Tool(BaseWrapper):
        name = "fake"
        binary = "sh"

    assert _Tool().readiness().ready is True


# ---- the three tools that actually have one ------------------------------

@pytest.mark.parametrize("tool_name", ["nuclei", "ffuf", "kiterunner"])
def test_the_data_dependent_tools_declare_their_data(tool_name):
    wrapper = _WRAPPERS[tool_name]
    required = list(getattr(wrapper, "required_data", ()) or ())
    assert required, (
        f"{tool_name} runs and reports nothing without its data, and nothing "
        f"declares that data - so the gap is invisible")
    for path, what in required:
        assert path and what


def test_nuclei_finds_its_templates_wherever_they_are(tmp_path, monkeypatch):
    """v3 keeps them in ~/.local/nuclei-templates, v2 in ~/nuclei-templates,
    and NUCLEI_TEMPLATES overrides both. Checking only one would report a
    working install as broken."""
    from app.scans.wrappers import nuclei as nuclei_mod

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("NUCLEI_TEMPLATES", raising=False)

    v2 = tmp_path / "nuclei-templates"
    v2.mkdir()
    (v2 / "cve.yaml").write_text("id: x\n")
    assert nuclei_mod._template_dir() == str(v2)

    v3 = tmp_path / ".local" / "nuclei-templates"
    v3.mkdir(parents=True)
    (v3 / "cve.yaml").write_text("id: x\n")
    assert nuclei_mod._template_dir() == str(v3), "v3 location wins"

    monkeypatch.setenv("NUCLEI_TEMPLATES", "/custom/templates")
    assert nuclei_mod._template_dir() == "/custom/templates"


# ---- it reaches the operator --------------------------------------------

def test_preflight_reports_every_tool():
    entries = preflight()
    assert len(entries) == len(_WRAPPERS)
    for entry in entries:
        assert set(entry) >= {"tool", "installed", "ready", "reason"}
        if not entry["ready"]:
            assert entry["reason"], f"{entry['tool']} is not ready and says why not"


def test_not_ready_is_the_subset_that_cannot_work():
    assert all(not e["ready"] for e in not_ready())


def test_the_limits_panel_puts_a_crippled_tool_first():
    """An installed-but-useless tool outranks every other explanation: it means
    the scan it belongs to reported nothing while looking like it worked."""
    from app.validation.limits import limits_for

    limits = limits_for(
        allow_active_exploit=True,
        tools_not_ready=[
            {"tool": "wpscan", "installed": False, "ready": False,
             "reason": "wpscan is not installed in this image"},
            {"tool": "nuclei", "installed": True, "ready": False,
             "reason": "the nuclei template set is empty (/root/.local/"
                       "nuclei-templates), so nuclei would run and find nothing"},
        ])
    assert limits, "a crippled nuclei must be reported"
    assert limits[0].key == "tool_has_no_data:nuclei", [limit.key for limit in limits]
    assert "comes back clean" in limits[0].fix
    # And the absent one is still listed, further down.
    assert any(limit.key == "tool_missing:wpscan" for limit in limits)


def test_the_run_says_it_up_front():
    """By the end of a run the operator has already concluded the target is
    clean, so this belongs at the start."""
    from app.orchestrator import loop

    src = _inspect.getsource(loop.run_engagement_loop)
    assert "_report_tool_readiness(engagement, run)" in src
    assert src.index("_report_tool_readiness") < src.index("planner.plan("), \
        "the preflight must run before the first task is planned"


def test_the_run_repairs_the_templates_rather_than_only_complaining():
    """Telling the operator to rebuild is a poor answer when the fix is one
    command the worker can run itself."""
    from app.orchestrator import loop

    src = _inspect.getsource(loop._report_tool_readiness)
    assert "_repair_nuclei_templates" in src
    repair = _inspect.getsource(loop._repair_nuclei_templates)
    assert "-update-templates" in repair
    assert "wait_for" in repair, "an unbounded download would hang the run"
    # And it must re-check rather than assume the download worked.
    assert "readiness()" in repair


def test_the_build_no_longer_hides_a_failed_template_download():
    """`|| true` is right - a throttled build must still produce an image - but
    it was silent, and silence is what made this invisible."""
    import pathlib

    dockerfile = (pathlib.Path(__file__).resolve().parents[1]
                  / "Dockerfile").read_text()
    assert "-update-templates" in dockerfile
    assert "WARNING: nuclei templates are MISSING" in dockerfile, \
        "a build that ships without templates must say so"


def test_the_tools_endpoint_exposes_readiness():
    """The Scans page shows it, so it has to be served."""
    from app.scans.wrappers import available_wrappers

    entry = available_wrappers()[0]
    assert "ready" in entry and "not_ready_because" in entry


# ---- the self-test: one command that says what works ----------------------
#
# It exists because five rounds of "read the code, infer a cause, fix, rebuild,
# no difference" is a failure of method. Each capability is exercised rather
# than inferred: a model role is "ok" when a live call returned text, not when
# a key is non-empty.

def test_the_selftest_covers_every_capability_the_operator_asked_about():
    import inspect as _i

    from app import selftest

    src = _i.getsource(selftest)
    for capability in ("check_tools", "check_llm", "check_exploit_authoring",
                       "check_poc_search", "check_sandbox"):
        assert f"def {capability}" in src, capability
    # And all of them have to be in the run, not merely defined.
    run = _i.getsource(selftest.run)
    for capability in ("check_tools", "check_llm", "check_exploit_authoring",
                       "check_poc_search", "check_sandbox"):
        assert capability in run, f"{capability} is never called"


def test_the_selftest_hydrates_the_router_before_judging_the_keys():
    """The LLM keys live in the database and the router is hydrated from them
    at worker startup. Without that, a self-test on a correctly configured
    installation would report "no API key" for every role."""
    import inspect as _i

    from app import selftest

    for fn in (selftest.run, selftest.as_json):
        src = _i.getsource(fn)
        assert "apply_saved_on_startup" in src, fn.__name__
        assert src.index("apply_saved_on_startup") < src.index("check_llm"), \
            f"{fn.__name__} judges the keys before loading them"


def test_a_live_call_is_what_makes_a_role_ok():
    """A non-empty key is not evidence the model answers."""
    import inspect as _i

    from app import selftest

    src = _i.getsource(selftest.check_llm)
    assert "client.chat(" in src, "the role check never calls the model"
    assert "max_tokens=8" in src, "the check must stay cheap"


def test_the_authoring_check_goes_all_the_way_to_a_vetted_script():
    """"The key works" and "the model can produce a runnable exploit" are
    different claims, and the operator asked about the second."""
    import inspect as _i

    from app import selftest

    src = _i.getsource(selftest.check_exploit_authoring)
    assert "authoring.author(" in src
    assert "inspect_code(" in src, "it must also report what the gate would say"
    assert "result.usable" in src, "and what the target-safety vet decided"


def test_the_poc_search_check_reports_the_reason_it_found_nothing():
    import inspect as _i

    from app import selftest

    src = _i.getsource(selftest.check_poc_search)
    assert "github_poc_search_detailed" in src, \
        "the plain search swallows the reason"
    assert "searchsploit" in src


def test_absent_and_broken_are_not_the_same_thing():
    """A tool nobody installed is a choice. A tool that looks present and does
    not work is the thing that cost five rebuilds."""
    from app import selftest

    assert selftest.ABSENT != selftest.BROKEN
    line = selftest._line(selftest.BROKEN, "nuclei", "templates are empty")
    assert "FAIL" in line and "nuclei" in line


def test_the_ui_and_the_cli_cannot_disagree():
    """as_json parses the same lines the CLI prints, from the same checks."""
    import inspect as _i

    from app import selftest

    src = _i.getsource(selftest.as_json)
    for capability in ("check_tools", "check_llm", "check_exploit_authoring",
                       "check_poc_search", "check_sandbox"):
        assert capability in src, f"{capability} is missing from the API view"


def test_the_endpoint_is_a_post_because_it_is_not_free():
    import inspect as _i

    from app.api import scans

    src = _i.getsource(scans)
    assert '@router.post("/selftest")' in src, \
        "a GET would be retried by caches and crawlers, and it spends tokens"
