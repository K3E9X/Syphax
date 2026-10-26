"""One setting decides how thorough a run is.

Every analyser had its own hardcoded ceiling - auth-brute sprayed 3 login
endpoints, rate_limit checked 2, mass_assignment probed 4 operations,
cve_checks took 6 targets. Each was reasonable alone, nobody chose the total,
and on a large application the run tested a sliver of the surface. The
operator asked for no limitation on the tests; SYPHAX_TEST_DEPTH is where that
is decided.
"""
from __future__ import annotations

import importlib

import pytest

from app import limits
from app.limits import DEEP, EXHAUSTIVE, STANDARD, UNLIMITED, cap, depth
from tests._limits import at_depth


def test_deep_is_the_default():
    """The old numbers were not a considered trade-off, they were defaults
    nobody revisited - so the default is deeper than they were."""
    with at_depth(""):
        import os
        os.environ.pop("SYPHAX_TEST_DEPTH", None)
        assert depth() == DEEP
        assert cap(3) == 12


def test_standard_keeps_the_documented_number():
    with at_depth(STANDARD):
        assert cap(3) == 3
        assert cap(60) == 60


def test_exhaustive_removes_the_cap():
    with at_depth(EXHAUSTIVE):
        assert cap(3) == UNLIMITED
        assert cap(60) == UNLIMITED
        assert limits.unlimited() is True


def test_a_floor_lifts_a_cap_too_small_to_scale():
    """2 x 4 is 8, which is still only 8 endpoints on a large API."""
    with at_depth(DEEP):
        assert cap(2) == 8
        assert cap(2, floor=20) == 20
    # but the floor must not inflate the standard depth, which is the
    # documented trade-off
    with at_depth(STANDARD):
        assert cap(2, floor=20) == 2


def test_an_unknown_depth_falls_back_rather_than_crashing(caplog):
    with at_depth("maximum-overdrive"):
        assert depth() == DEEP
        assert cap(3) == 12


@pytest.mark.parametrize("bad", [0, -1, None, "x"])
def test_a_nonsense_default_is_treated_as_no_cap(bad):
    """A cap of 0 or a broken value must not silently become "test nothing"."""
    assert cap(bad) == UNLIMITED


def test_describe_tells_the_operator_which_it_is():
    with at_depth(EXHAUSTIVE):
        assert "no coverage cap" in limits.describe()
    with at_depth(STANDARD):
        text = limits.describe()
        assert "standard" in text and "exhaustive" in text


# ---- the caps actually move -------------------------------------------

CAPPED = [
    ("app.exploit.auth_brute", "MAX_ENDPOINTS"),
    ("app.analysis.rate_limit", "MAX_ENDPOINTS"),
    ("app.analysis.mass_assignment", "MAX_OPERATIONS"),
    ("app.analysis.mass_assignment", "MAX_PROBES"),
    ("app.analysis.api_sequences", "MAX_SEQUENCES"),
    ("app.analysis.api_inventory", "MAX_PROBES"),
    ("app.analysis.api_inventory", "MAX_ZOMBIE_PROBES"),
    ("app.analysis.auth_posture", "MAX_BYPASS_PROBES"),
    ("app.analysis.access_control", "MAX_ANON_REPLAY"),
    ("app.analysis.logic", "MAX_IDOR_CONFIRM"),
    ("app.analysis.cors", "MAX_ENDPOINTS"),
    ("app.analysis.graphql", "MAX_ENDPOINTS"),
    ("app.analysis.param_discovery", "MAX_ENDPOINTS"),
    ("app.analysis.public_exploits", "MAX_CVES"),
    ("app.exploit.cve_checks", "MAX_TARGETS"),
    ("app.exploit.known", "MAX_TARGETS"),
    ("app.exploit.campaign", "MAX_PLANS"),
    ("app.exploit.payload_gen", "MAX_FINDINGS"),
    ("app.exploit.chain_exploit", "MAX_CHAINS"),
]


@pytest.mark.parametrize("module_name,const", CAPPED)
def test_every_coverage_cap_grows_with_depth(module_name, const):
    mod = importlib.import_module(module_name)
    with at_depth(STANDARD):
        low = getattr(importlib.reload(mod), const)
    with at_depth(EXHAUSTIVE):
        high = getattr(importlib.reload(mod), const)
    importlib.reload(mod)  # leave it at the suite's depth
    assert high == UNLIMITED, f"{module_name}.{const} ignores the depth setting"
    assert low < high


# ---- what depth must NOT touch ----------------------------------------

MEMORY_CAPS = [
    ("app.analysis.logic", "MAX_FLOWS"),
    ("app.analysis.js_recon", "MAX_BODY"),
    ("app.analysis.jwt_analysis", "MAX_BODY"),
    ("app.analysis.dom_sinks", "MAX_BYTES"),
    ("app.analysis.schema_audit", "MAX_DOC_BYTES"),
    ("app.analysis.openapi_synth", "MAX_FLOWS"),
]


@pytest.mark.parametrize("module_name,const", MEMORY_CAPS)
def test_depth_never_lifts_a_memory_cap(module_name, const):
    """These are not testing limits, they are what keeps a 2 GB host alive
    while parsing a few thousand captured responses. Raising them does not
    test more; it gets the worker OOM-killed mid-run and loses everything it
    had found."""
    mod = importlib.import_module(module_name)
    with at_depth(EXHAUSTIVE):
        value = getattr(importlib.reload(mod), const)
    importlib.reload(mod)
    assert value < UNLIMITED, (
        f"{module_name}.{const} is a memory bound and must not follow "
        "SYPHAX_TEST_DEPTH")


def test_depth_does_not_relax_a_gate():
    """More probes is not more permission. An analyser that probes more
    endpoints still needs allow_active_exploit for its writes."""
    import inspect

    from app.analysis import mass_assignment, rate_limit
    for fn in (mass_assignment.analyze_mass_assignment,
               rate_limit.analyze_rate_limit):
        src = inspect.getsource(fn)
        assert "allow_active" in src
    # And limits.py CANNOT touch a gate: it imports nothing from the app, so
    # it has no access to capabilities, scope or the engagement. Asserting the
    # import graph rather than grepping for words - the module's own prose
    # mentions capabilities, and a test that reads its documentation instead
    # of its behaviour passes for the wrong reason.
    import ast

    tree = ast.parse(inspect.getsource(limits))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "app" not in imported, (
        f"limits.py reaches into the app ({sorted(imported)}); it must only "
        "read a setting")


# ---- the setting has to reach the containers --------------------------

def _repo_root():
    import pathlib
    return pathlib.Path(__file__).resolve().parents[2]


def test_the_knob_is_documented_where_operators_look():
    text = (_repo_root() / ".env.example").read_text()
    assert "SYPHAX_TEST_DEPTH" in text
    # and the three levels are named, so nobody has to read limits.py
    for level in ("standard", "deep", "exhaustive"):
        assert level in text


def test_the_worker_and_backend_both_read_the_env_file():
    """depth() reads os.environ, so the setting only works if .env reaches
    the containers that plan and run the tests."""
    import re
    text = (_repo_root() / "docker-compose.yml").read_text()
    for service in ("backend", "worker"):
        block = re.search(rf"^  {service}:\n(.*?)(?=^  \S)", text,
                          re.S | re.M)
        assert block, f"no {service} service in docker-compose.yml"
        assert "env_file" in block.group(1), (
            f"{service} does not read .env, so SYPHAX_TEST_DEPTH cannot reach it")


def test_the_run_says_how_thorough_it_was_told_to_be():
    """A run that tested a sliver used to look exactly like one that tested
    the whole surface."""
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    assert "describe_depth" in src
