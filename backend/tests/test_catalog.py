"""The methodology catalog stays coherent and the exploitation phase is rich."""
from app.methodology.catalog import (
    CATALOG,
    CATALOG_BY_ID,
    PHASE_EXPLOIT,
    items_for_phase,
)
from app.reporting.mappings import category_for_class

# Read from the real registry rather than restated here: a hardcoded copy
# drifts, and the property that matters is "every catalog item names a
# wrapper that exists", not "names one of these seventeen".
from app.scans.wrappers import _WRAPPERS

_KNOWN_TOOLS = set(_WRAPPERS)


def test_ids_are_unique():
    ids = [i.id for i in CATALOG]
    assert len(ids) == len(set(ids))
    assert len(CATALOG_BY_ID) == len(CATALOG)


def test_every_item_uses_a_known_tool():
    for item in CATALOG:
        assert item.tool in _KNOWN_TOOLS, f"{item.id} -> unknown tool {item.tool}"


def test_exploitation_phase_covers_injection_family():
    exp = {i.vuln_class for i in items_for_phase(PHASE_EXPLOIT)}
    for cls in ("sql_injection", "xss", "command_injection", "ssrf", "ssti",
                "lfi", "xxe", "open_redirect"):
        assert cls in exp, f"exploitation phase missing {cls}"


def test_nmap_is_scheduled_now():
    # nmap was unused (not in any catalog item) - it must now drive a recon
    # service scan and an NSE vuln pass.
    assert "RECON-NMAP-SERVICES" in CATALOG_BY_ID
    assert "VULN-NMAP-NSE" in CATALOG_BY_ID
    assert CATALOG_BY_ID["VULN-NMAP-NSE"].tool == "nmap"
    assert any("--script" in o for o in CATALOG_BY_ID["VULN-NMAP-NSE"].default_options)


def test_dedicated_exploit_items_exist():
    for iid in ("EXP-SSRF", "EXP-SSTI", "EXP-LFI", "EXP-XXE", "EXP-REDIRECT",
                "EXP-CRLF"):
        assert iid in CATALOG_BY_ID


def test_every_exploit_class_is_mapped_to_a_real_category():
    for item in items_for_phase(PHASE_EXPLOIT):
        # "multiple" (the generic DAST item) is allowed; everything else must
        # resolve to a concrete, non-"other" category.
        if item.vuln_class == "multiple":
            continue
        assert category_for_class(item.vuln_class) != "other", item.id


def test_exploitation_fires_on_paramless_endpoint():
    """Regression: EXP-SQLI/DAST/XSS must run on the base endpoint even with no
    query params (the tools discover params/forms themselves), otherwise a run
    with no proxy traffic never reaches exploitation."""
    from app.methodology.catalog import applies, CATALOG_BY_ID
    endpoint_no_params = {"is_host": False, "is_https": True,
                          "requires_params": False, "tech": []}
    host_ctx = {"is_host": True, "is_https": True, "requires_params": False, "tech": []}
    for item_id in ("EXP-DAST", "EXP-SQLI", "EXP-XSS"):
        item = CATALOG_BY_ID[item_id]
        assert applies(item, endpoint_no_params), f"{item_id} should fire on a paramless endpoint"
        assert not applies(item, host_ctx), f"{item_id} should not target a bare host"


def test_param_only_injection_items_still_require_params():
    from app.methodology.catalog import applies, CATALOG_BY_ID
    no_params = {"is_host": False, "is_https": True, "requires_params": False, "tech": []}
    for item_id in ("EXP-SSRF", "EXP-SSTI"):
        if item_id in CATALOG_BY_ID:
            assert not applies(CATALOG_BY_ID[item_id], no_params)
