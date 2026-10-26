"""Does the API work fit how syphax actually runs?

"Assure-toi a la fin que ca rentre en cohesion avec comment syphax fonctionne."

Six modules and one catalog item were added for API security - the synthesised
schema, the shadow/zombie hunt, the GraphQL suite, the contract audit, mass
assignment, rate limiting and the stateful sequence. Each of them is only real
if it joins the pipeline that already exists: a vuln_class the taxonomy knows,
a verdict validation keeps, findings that survive dedup and the noise filter,
a place in the run rather than a button, and an exploit route or a stated
reason there is none.

The first test here is the one that matters most, and it is not about the API
work at all: it derives EVERY vuln_class the codebase can emit, from the
source, and fails on any that the exploit strategy cannot answer for. That
check did not exist, which is why ten classes - nikto's whole signature table
among them - had been answering "no route available" for every finding.
"""
from __future__ import annotations

import inspect as _inspect
import pathlib
import re

import pytest

APP = pathlib.Path(__file__).resolve().parents[1] / "app"

# The two idioms the codebase uses to attach a class to a finding.
_DICT_FORM = re.compile(r'"vuln_class":\s*"([a-z_0-9]+)"')
# nikto, nuclei and schemathesis map a signature to (severity, class).
# The negative lookahead keeps `x.severity in ("critical", "high")` out: a
# severity pair is not a class, and without it the scan "finds" two.
_SEVERITIES = "critical|high|medium|low|info"
_TUPLE_FORM = re.compile(
    rf'\(\s*"(?:{_SEVERITIES})"\s*,\s*"(?!(?:{_SEVERITIES})")([a-z_0-9]+)"\s*\)')


def _emitted_classes() -> dict:
    """{class: where it is emitted}, read out of the source.

    Comment lines are stripped first: a class name discussed in a comment is
    not a class the code emits, and a test that matches its own prose proves
    nothing.
    """
    found: dict = {}
    for path in sorted(APP.rglob("*.py")):
        body = "\n".join(line for line in path.read_text().splitlines()
                         if not line.strip().startswith("#"))
        for pattern in (_DICT_FORM, _TUPLE_FORM):
            for name in pattern.findall(body):
                found.setdefault(name, str(path.relative_to(APP.parent)))

    from app.methodology.catalog import CATALOG
    for item in CATALOG:
        found.setdefault(item.vuln_class, f"catalog:{item.id}")
    from app.validation.classes import TOOL_VULN_CLASS
    for tool, name in TOOL_VULN_CLASS.items():
        found.setdefault(name, f"TOOL_VULN_CLASS:{tool}")
    return found


def test_the_check_itself_finds_something():
    """Guard the guard: a regex that matched nothing would make every
    assertion below vacuously true."""
    emitted = _emitted_classes()
    assert len(emitted) > 40, f"only found {len(emitted)} classes - the scan broke"
    for expected in ("sql_injection", "mass_assignment", "shadow_api",
                     "broken_access_control", "api_contract_violation"):
        assert expected in emitted


def test_every_class_the_codebase_emits_can_be_answered_for():
    """A class the strategy does not know produces "no route available: no
    template, no tool path, no published PoC, and the class is not one a
    written proof would settle" - which reads as a gap in the tool rather
    than as a decision about the finding. Either it has a route, or it is
    surface, or NO_EXPLOIT_NEEDED says why in words an operator can act on."""
    from app.exploit.strategy import (AUTHORABLE_CLASSES, NO_EXPLOIT_NEEDED,
                                      SURFACE_CLASSES, TOOL_ROUTES)
    answerable = (set(AUTHORABLE_CLASSES) | set(TOOL_ROUTES)
                  | set(SURFACE_CLASSES) | set(NO_EXPLOIT_NEEDED))
    emitted = _emitted_classes()
    orphans = {name: where for name, where in emitted.items()
               if name not in answerable}
    assert not orphans, (
        "these vuln classes are emitted but the strategy cannot answer for "
        f"them, so every such finding is discarded as 'no route available': "
        f"{orphans}")


def test_a_stated_reason_is_actually_a_reason():
    """NO_EXPLOIT_NEEDED exists so the report says something useful. A
    one-word entry would defeat the point."""
    from app.exploit.strategy import NO_EXPLOIT_NEEDED
    for name, reason in NO_EXPLOIT_NEEDED.items():
        assert len(reason) > 40, f"{name}: {reason!r}"
        assert "no route available" not in reason


def test_a_class_is_never_both_surface_and_authorable():
    """It was once: vulnerable_component was surface to the validator and a
    weakness to the campaign, so every retire.js CVE was scored as a real
    finding and then refused as "not a vulnerability"."""
    from app.exploit.strategy import (AUTHORABLE_CLASSES, NO_EXPLOIT_NEEDED,
                                      SURFACE_CLASSES)
    assert not (set(AUTHORABLE_CLASSES) & set(SURFACE_CLASSES))
    assert not (set(AUTHORABLE_CLASSES) & set(NO_EXPLOIT_NEEDED))
    assert not (set(SURFACE_CLASSES) & set(NO_EXPLOIT_NEEDED))


# ---- every new analyser joins the pipeline ---------------------------

API_ANALYSERS = ("api_inventory", "schema_audit", "mass_assignment",
                 "rate_limit", "api_sequences")


@pytest.mark.parametrize("tool", API_ANALYSERS)
def test_each_analyser_has_a_place_in_the_run(tool):
    """Not a button. The user's standing requirement: if it is worth doing it
    happens in the run."""
    from app.analysis import run_analysis
    assert f'("{tool}",' in _inspect.getsource(run_analysis)


@pytest.mark.parametrize("tool", API_ANALYSERS)
def test_each_analysers_verdict_survives_validation(tool):
    """These modules compute a careful status - "the server echoed what we
    injected" is not the same claim as "it answered 2xx". A tool missing from
    this set has its verdict thrown away and re-derived from the severity."""
    from app.validation.validator import _ANALYSIS_TOOLS
    assert tool in _ANALYSIS_TOOLS


@pytest.mark.parametrize("tool", API_ANALYSERS)
def test_each_analyser_stores_its_findings_as_a_synthetic_job(tool):
    """One tool, one job: that is what keeps them partitioned in the UI and
    makes a re-run replace its own findings instead of duplicating them."""
    import importlib
    module = importlib.import_module(
        {"api_inventory": "app.analysis.api_inventory",
         "schema_audit": "app.analysis.schema_audit",
         "mass_assignment": "app.analysis.mass_assignment",
         "rate_limit": "app.analysis.rate_limit",
         "api_sequences": "app.analysis.api_sequences"}[tool])
    source = _inspect.getsource(module)
    assert f'save_analysis_job(engagement_id, "{tool}"' in source


@pytest.mark.parametrize("tool", API_ANALYSERS)
def test_each_analyser_scopes_what_it_touches(tool):
    import importlib
    module = importlib.import_module(f"app.analysis.{tool}")
    source = _inspect.getsource(module)
    assert "host_in_scope" in source or "url_in_scope" in source, tool


@pytest.mark.parametrize("tool", ("mass_assignment", "rate_limit", "api_sequences"))
def test_every_analyser_that_writes_or_bursts_is_gated(tool):
    import importlib
    module = importlib.import_module(f"app.analysis.{tool}")
    source = _inspect.getsource(module)
    assert "allow_active_exploit" in source, tool
    assert "allow_active" in source, tool


@pytest.mark.parametrize("tool", ("api_inventory", "schema_audit"))
def test_the_read_only_analysers_need_no_gate(tool):
    """api_inventory sends in-scope GETs through the safe layer and
    schema_audit sends nothing at all, so gating them would only mean fewer
    findings on an engagement that asked for a passive run."""
    import importlib
    module = importlib.import_module(f"app.analysis.{tool}")
    source = _inspect.getsource(module)
    assert "ProbeClient" not in source, tool


# ---- the findings survive the filters that come after ----------------

def test_no_api_finding_is_silenced_by_the_noise_filter():
    """is_noise drops inventory rows pointing at dead pages. None of these
    classes is inventory, and a finding that said "the forgotten version
    answered 200" being dropped for its status code would be absurd."""
    from app.validation.noise import is_noise
    cases = [
        ("high", "broken_access_control", {"tool": "api_inventory"}),
        ("low", "shadow_api", {"tool": "api_inventory", "status_code": 200}),
        ("medium", "shadow_api", {"tool": "api_inventory", "source": "archive"}),
        ("high", "broken_authentication", {"tool": "schema_audit"}),
        ("medium", "mass_assignment", {"tool": "mass_assignment"}),
        ("low", "rate_limit", {"tool": "rate_limit"}),
        ("medium", "api_contract_violation", {"tool": "schemathesis"}),
        ("medium", "graphql_introspection", {"tool": "graphql"}),
        ("high", "idor", {"tool": "api_sequences"}),
    ]
    for severity, vuln_class, metadata in cases:
        drop, why = is_noise(severity, vuln_class, metadata)
        assert not drop, f"{vuln_class} silenced as noise: {why}"


def test_two_findings_about_the_same_forgotten_version_collapse():
    """The duplicate problem the user reported. The dedup key folds the
    scheme, case, default port and trailing slash of the target, so the same
    endpoint reported twice is one row."""
    from app.findings_util import dedup
    assert dedup("shadow_api", "https://t.example/api/v1/x") == \
        dedup("shadow_api", "https://T.Example:443/api/v1/x/")


def test_findings_about_different_versions_do_not_collapse():
    """v1 and v0 are two findings, and folding them would hide one."""
    from app.findings_util import dedup
    assert dedup("shadow_api", "https://t.example/api/v1/x") != \
        dedup("shadow_api", "https://t.example/api/v0/x")


def test_the_dedup_key_keeps_the_query_string():
    """A parameterised endpoint is an injection point, and two different
    parameters on one path are two different findings."""
    from app.findings_util import dedup
    assert dedup("mass_assignment", "https://t.example/api/u?id=1") != \
        dedup("mass_assignment", "https://t.example/api/u?name=1")


def test_every_api_finding_can_be_scored():
    """score_for drives the ordering in the UI and the report. A class it
    cannot score sorts as if it were nothing."""
    from app.findings_util import score_for
    for severity, vuln_class in (("high", "broken_access_control"),
                                 ("medium", "mass_assignment"),
                                 ("low", "shadow_api"),
                                 ("low", "rate_limit"),
                                 ("info", "graphql_introspection")):
        score = score_for({"severity": severity, "vuln_class": vuln_class,
                           "metadata": {}, "status": "confirmed"})
        assert score["value"] > 0, (severity, vuln_class)
        assert score["basis"] in ("cvss", "risk")
        assert score["explain"]


# ---- the catalog item is well formed --------------------------------

def test_the_new_catalog_item_names_a_registered_wrapper():
    """The planner builds a task per (item x asset) and the worker resolves
    the tool by name. An item naming a tool that does not exist is a job that
    fails for every asset."""
    from app.methodology.catalog import CATALOG, PHASE_ORDER
    from app.scans.wrappers import _WRAPPERS
    for item in CATALOG:
        assert item.tool in _WRAPPERS, f"{item.id} -> {item.tool}"
        assert item.phase in PHASE_ORDER, f"{item.id} -> {item.phase}"


def test_every_catalog_condition_is_one_the_engine_understands():
    """applies_when is deliberately a small structured dict. A key the engine
    does not read is a condition that silently always passes."""
    from app.methodology.catalog import CATALOG
    understood = {"always", "is_host", "is_endpoint", "is_base",
                  "requires_params", "tech_any", "path_any", "is_https"}
    for item in CATALOG:
        unknown = set(item.applies_when) - understood
        assert not unknown, f"{item.id}: {unknown}"


def test_no_new_binary_was_added_without_a_readiness_check():
    """Every tool in the catalog has to be answerable by the preflight, or a
    run reports "nothing found" when the real answer is "not installed"."""
    from app.methodology.catalog import CATALOG
    from app.scans.wrappers import _WRAPPERS, preflight
    ready = {row["tool"] for row in preflight()}
    for item in CATALOG:
        wrapper = _WRAPPERS[item.tool]
        assert getattr(wrapper, "binary", ""), item.tool
        assert item.tool in ready, (
            f"{item.tool} is in the catalog but the preflight does not report "
            f"on it, so a run would say 'nothing found' where the real answer "
            f"is 'not installed'")


# ---- the two schemas stay distinct ----------------------------------

def test_the_synthesised_schema_is_never_audited_as_a_contract():
    """It declares no security because we did not write one. Auditing it
    would manufacture a finding per operation out of our own omission."""
    from app.analysis.openapi_synth import build
    from app.analysis.schema_audit import audit, is_observed
    observed = build([{"method": "POST", "url": "https://t.example/api/users",
                       "status_code": 201,
                       "request_content_type": "application/json",
                       "response_content_type": "application/json"}],
                     base_url="https://t.example")
    assert is_observed(observed)
    assert audit(observed, schema_url="x") == []


def test_the_two_schemas_are_written_to_different_filenames():
    from app.analysis import openapi_synth, surface_seed
    assert '"observed.json"' in _inspect.getsource(openapi_synth)
    assert '"published.json"' in _inspect.getsource(surface_seed)


# ---- what runs before the vuln phase, and in what order -------------

def test_the_pre_vuln_hooks_run_in_the_order_their_outputs_need():
    """All four seed something the vuln phase then plans against: the JS
    cache, the parameterised endpoints, the API schema and the forgotten
    versions. Correlation is last because it reads what the others produced."""
    from app.orchestrator import loop
    src = _inspect.getsource(loop)
    order = ["_materialise_js(engagement, run)",
             "_discover_params(engagement, run)",
             "_synthesise_api_schema(engagement, run)",
             "_hunt_shadow_apis(engagement, run)",
             "_run_correlation(engagement, run, executor, runs)"]
    positions = [src.index(f"await {name}") for name in order]
    assert positions == sorted(positions), order


def test_every_pre_vuln_hook_is_isolated():
    """A seeding step that raised would end the run at the phase change, with
    everything already discovered thrown away."""
    from app.orchestrator import loop
    for name in ("_materialise_js", "_discover_params", "_synthesise_api_schema",
                 "_hunt_shadow_apis"):
        src = _inspect.getsource(getattr(loop, name))
        assert "except Exception" in src, name
        assert "logger.exception" in src, name


def test_the_five_ui_stages_are_still_four_planned_phases_plus_validation():
    """The operator sees five stages - recon, mapping, vuln analysis,
    exploitation, validation - and the planner walks four. Validation is not
    planned: it runs in _finalize_engagement after the loop. Nothing added
    here changes that."""
    from app.methodology.catalog import (PHASE_EXPLOIT, PHASE_MAPPING,
                                         PHASE_ORDER, PHASE_RECON, PHASE_VULN)
    assert PHASE_ORDER == [PHASE_RECON, PHASE_MAPPING, PHASE_VULN, PHASE_EXPLOIT]
    from app.orchestrator import loop
    assert "validation" not in [p for p in PHASE_ORDER]
    assert "_finalize_engagement" in _inspect.getsource(loop)


# ---- nothing here sends a mutation, a batch or an unbounded loop ----

def test_the_only_write_methods_in_the_api_suite_are_post():
    """PUT, PATCH and DELETE destroy data on a target the operator asked us
    to test. The probe client refuses them structurally; this checks no
    module tries."""
    from app.exploit.probe_client import ALLOWED_METHODS
    assert ALLOWED_METHODS == {"GET", "HEAD", "POST"}
    for name in ("api_inventory", "schema_audit", "mass_assignment",
                 "rate_limit", "api_sequences", "graphql", "graphql_probes",
                 "openapi_synth"):
        import importlib
        src = _inspect.getsource(importlib.import_module(f"app.analysis.{name}"))
        body = "\n".join(line for line in src.splitlines()
                         if not line.strip().startswith("#"))
        for method in ('method="PUT"', 'method="PATCH"', 'method="DELETE"'):
            assert method not in body, f"{name} sends {method}"


def test_every_probe_budget_in_the_api_suite_is_bounded():
    from app.analysis import api_inventory, api_sequences, graphql
    from app.analysis import mass_assignment, rate_limit
    from tests._limits import is_bounded, standard
    # Finite at the suite's depth: no probe budget is unbounded by accident.
    for value in (api_inventory.MAX_PROBES, graphql.MAX_ENDPOINTS,
                  mass_assignment.MAX_PROBES, api_sequences.MAX_SEQUENCES):
        assert is_bounded(value)
    # And the documented trade-off at the standard depth.
    assert standard(60) <= 100
    assert standard(6) <= 10
    assert standard(12) <= 20
    assert standard(3, floor=12) <= 5
    # A burst is NOT a coverage cap - it is how hard one endpoint is hit, and
    # it stays pinned whatever the depth.
    assert rate_limit.BURST_WITH_CAPABILITY <= 200


# ---- the diagnosis can see the traffic-driven half ------------------

def test_the_analyser_tool_names_are_exactly_what_the_source_saves():
    """The step key in run_analysis is an underscore name used for the summary
    dict ("js_recon") while the job's tool is the hyphenated one the UI and
    the validator know ("js-recon"). Conflating them is how a tool ends up
    missing from a set that gates its verdict, so this derives the list from
    the save calls themselves."""
    from app.analysis import ANALYSER_TOOLS
    saved = set()
    for path in APP.rglob("*.py"):
        saved |= set(re.findall(
            r'save_analysis_job\(\s*engagement_id,\s*"([a-z_0-9-]+)"',
            path.read_text()))
    assert saved, "no save_analysis_job calls found - the scan broke"
    assert set(ANALYSER_TOOLS) == saved, {
        "declared but never saved": sorted(set(ANALYSER_TOOLS) - saved),
        "saved but not declared": sorted(saved - set(ANALYSER_TOOLS))}


def test_every_analyser_tool_has_its_verdict_kept():
    """A tool that saves findings with its own status/confidence and is not in
    _ANALYSIS_TOOLS has that verdict discarded and re-derived from the
    severity. cloud_creds lost an authenticated AWS probe that way."""
    from app.analysis import ANALYSER_TOOLS
    from app.validation.validator import _ANALYSIS_TOOLS
    missing = sorted(set(ANALYSER_TOOLS) - set(_ANALYSIS_TOOLS))
    assert not missing, f"their verdicts are thrown away: {missing}"


def test_the_diagnosis_reports_on_the_analysers_not_only_the_catalog():
    """An analyser's job carries no catalog_item_id, so none of them appeared
    in the per-item section: nineteen analysers - every API check, the JWT
    pass, access control, the JavaScript mining - could each produce nothing
    and the diagnostic would not mention them. That is most of what a run
    does on an application."""
    from app import diagnose_run
    src = _inspect.getsource(diagnose_run.run)
    assert "ANALYSER_TOOLS" in src
    assert 'job["catalog_item_id"]' in src
    assert "never ran" in src


def test_the_diagnosis_surfaces_why_an_analyser_declined():
    """Each one emits a THOUGHT when it skips itself - "it needs active
    exploitation", "no captured traffic to build a schema from" - and that
    sentence is the answer to "why did this find nothing"."""
    from app import diagnose_run
    src = _inspect.getsource(diagnose_run.run)
    assert "agent_thought" in src
    assert "WHAT THE ANALYSERS SAID" in src


def test_the_diagnosis_stays_read_only():
    """It runs against a live engagement while a run may be in progress."""
    from app import diagnose_run
    src = _inspect.getsource(diagnose_run)
    for write in ("INSERT", "UPDATE ", "DELETE FROM", "TRUNCATE", "DROP "):
        assert write not in src.upper().replace("SELECT", ""), write


@pytest.mark.parametrize("tool", API_ANALYSERS)
def test_each_new_analyser_explains_itself_when_it_declines(tool):
    """A silent skip is indistinguishable from a clean pass that found
    nothing, and the operator cannot act on the difference."""
    import importlib
    module = importlib.import_module(f"app.analysis.{tool}")
    source = _inspect.getsource(module)
    if "_say(" not in source:
        pytest.skip(f"{tool} cannot decline: it reads what is already in hand")
    assert "async def _say" in source


# ---- the report says something specific about every class -----------

def test_every_class_the_codebase_emits_has_a_report_mapping():
    """Without an entry the report prints WSTG-INFO-00, CWE-0, category
    "other" and "review the finding and apply standard hardening". Fifteen
    classes were doing that, the whole API suite among them: a high-severity
    finding whose remediation line is "apply standard hardening" is not a
    report, it is a row."""
    from app.reporting.mappings import MAPPING, _FALLBACK
    unmapped = {name: where for name, where in _emitted_classes().items()
                if name not in MAPPING}
    assert not unmapped, (
        f"these fall back to {_FALLBACK['wstg']} / {_FALLBACK['cwe']} / "
        f"'{_FALLBACK['category']}': {unmapped}")


def test_every_class_the_strategy_accepts_has_one_too():
    """A class the campaign is willing to author a PoC for, whose finding the
    report then cannot categorise, is the same gap one step later."""
    from app.exploit.strategy import AUTHORABLE_CLASSES
    from app.reporting.mappings import MAPPING
    missing = sorted(set(AUTHORABLE_CLASSES) - set(MAPPING))
    assert not missing, missing


def test_every_mapping_is_complete_and_specific():
    from app.reporting.mappings import CATEGORY_ORDER, MAPPING
    for name, entry in MAPPING.items():
        assert entry["category"] in CATEGORY_ORDER, name
        assert entry["wstg"].startswith("WSTG-"), name
        assert entry["cwe"].startswith("CWE-") and entry["cwe"] != "CWE-0", name
        assert entry["attack"], name
        # A remediation that could be pasted onto any finding is not one.
        assert len(entry["remediation"]) > 60, name
        assert "standard hardening" not in entry["remediation"], name


@pytest.mark.parametrize("vuln_class,item", [
    ("broken_access_control", "API1:2023"),
    ("idor", "API1:2023"),
    ("broken_authentication", "API2:2023"),
    ("jwt", "API2:2023"),
    ("mass_assignment", "API3:2023"),
    ("rate_limit", "API4:2023"),
    ("privilege_escalation", "API5:2023"),
    ("ssrf", "API7:2023"),
    ("api_contract_violation", "API8:2023"),
    ("graphql_introspection", "API8:2023"),
    ("shadow_api", "API9:2023"),
    ("api_route", "API9:2023"),
])
def test_the_api_classes_carry_their_owasp_api_item(vuln_class, item):
    """It answers a different question from the WSTG id - which API control
    is missing, rather than which test this is - and it is the vocabulary an
    API owner reads the report in."""
    from app.reporting.mappings import owasp_api_for_class
    assert owasp_api_for_class(vuln_class) == item


@pytest.mark.parametrize("vuln_class", ["path_traversal", "vulnerable_component",
                                        "weak_tls", "xss", "sql_injection"])
def test_a_web_class_with_no_honest_api_item_carries_none(vuln_class):
    """Mapping these to the nearest item would send a reader to the wrong
    control. Empty is a real answer here, not a missing one."""
    from app.reporting.mappings import owasp_api_for_class
    assert owasp_api_for_class(vuln_class) == ""


def test_every_declared_api_item_is_a_real_one():
    from app.reporting.mappings import MAPPING
    valid = {f"API{n}:2023" for n in range(1, 11)}
    for name, entry in MAPPING.items():
        item = entry.get("owasp_api")
        if item:
            assert item in valid, f"{name}: {item}"


def test_the_item_reaches_the_report_and_both_exports():
    """A mapping nothing prints is a mapping nobody reads."""
    from app.reporting import export, report
    assert "OWASP API" in _inspect.getsource(report._render_findings)
    assert '"owasp_api"' in _inspect.getsource(export.findings_json)
    assert '"owasp_api"' in _inspect.getsource(export.sarif)


def test_a_finding_with_no_api_item_gets_no_empty_owasp_label():
    """An "OWASP API:" label with nothing after it is worse than no label.

    Rendered rather than grepped: the standards line is built for a finding
    whose class has no API item and one whose class has, and compared."""
    from app.reporting.report import _render_findings

    class _F:
        def __init__(self, vuln_class):
            self.vuln_class = vuln_class
            self.title = "t"
            self.severity = "high"
            self.status = "confirmed"
            self.confidence = 0.9
            self.target = "https://t.example/x"
            self.tool = "x"
            self.method = "m"
            self.metadata = {}
            self.evidence = ""
            self.poc = ""

    web: list = []
    _render_findings(web, [_F("path_traversal")])
    assert not any("OWASP API" in line for line in web)

    api: list = []
    _render_findings(api, [_F("shadow_api")])
    assert any("**OWASP API:** API9:2023" in line for line in api)
