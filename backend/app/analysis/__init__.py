"""Application-layer analysis over captured proxy traffic.

Each analyzer is saved as its own synthetic scan job, so they stay cleanly
partitioned in the UI and the report and a re-run replaces its own findings
instead of duplicating them. The traffic-driven half of a run lives here:

  * logic            - IDOR/BOLA, CSRF, BFLA/privesc
  * js-recon         - secrets + hidden endpoints mined from JavaScript bundles
  * jwt              - JWT weaknesses (alg=none, weak HMAC, kid/jku, no exp)
  * access-control   - missing-auth replay, method-tampering & mass-assignment flags
  * api_inventory    - shadow and zombie API versions (API9)
  * schema_audit     - the published contract itself (API1/2/3/4/8)
  * mass_assignment  - an injected property the server binds (API3)
  * rate_limit       - a bounded burst, reported as a measured bound (API4)
  * api_sequences    - create, learn the identifier, read it back (API1)

`run_analysis` runs them all (best-effort: one failing analyzer never blocks
the others) and returns a merged summary.

ANALYSER_TOOLS is the list of `tool` names those synthetic jobs carry. It is
here rather than inside run_analysis because diagnose_run needs it: a job with
no catalog_item_id was invisible to the diagnosis, which meant the whole
traffic-driven half of a run - every analyser above - could produce nothing and
the diagnostic would not mention it.
"""
from __future__ import annotations

import logging
from typing import Dict

from app.analysis.js_cache import materialise_js
from app.analysis.logic import analyze_logic
from app.analysis.js_recon import analyze_js
from app.analysis.jwt_analysis import analyze_jwt
from app.analysis.access_control import analyze_access_control
from app.analysis.cors import analyze_cors
from app.analysis.param_discovery import analyze_params
from app.analysis.graphql import analyze_graphql
from app.analysis.public_exploits import analyze_public_exploits

logger = logging.getLogger("syphax.analysis")

__all__ = ["analyze_logic", "analyze_js", "analyze_jwt", "materialise_js",
           "analyze_access_control", "analyze_cors", "analyze_params",
           "analyze_graphql", "analyze_public_exploits", "run_analysis",
           "ANALYSER_TOOLS"]

# The `tool` name each analyser's synthetic job carries. Derived from the
# save_analysis_job calls, not from run_analysis' step keys - the step key is
# an underscore name used for the summary dict ("js_recon") while the job's
# tool is the hyphenated one the UI and the validator know ("js-recon"), and
# conflating them is how a tool ends up missing from a set that gates its
# verdict. A test asserts this list is exactly what the source saves.
ANALYSER_TOOLS = (
    "js-recon", "params", "logic", "jwt", "access-control", "cors",
    "http_posture", "error_disclosure", "api_exposure",
    "api_inventory", "schema_audit", "mass_assignment", "rate_limit",
    "api_sequences", "dom_sinks", "auth_posture", "graphql", "llm-recon",
    "cve-checks",
    # Saved from app/exploit and app/intel, which run in the exploitation
    # phase and at finalisation rather than from run_analysis, but whose
    # findings arrive the same way.
    "exploit", "public-exploits", "auth-brute", "payload-probe", "cloud_creds",
)


async def run_analysis(engagement_id: str, *, allow_active: bool = True) -> Dict[str, Dict]:
    """Run every traffic-driven analyzer. Each is isolated so a failure in one
    (e.g. malformed flow) doesn't abort the rest.

    `allow_active` lets the caller suppress the analyzers that send crafted
    exploit payloads (cve_checks) when exploitation was denied/stopped - they
    also self-gate on allow_active_exploit, this is the per-run override."""
    from app.exploit import run_cve_checks  # targeted CVE checks (safe-PoC GETs)
    from app.analysis.llm_recon import analyze_llm_recon  # LLM response analyst
    from app.analysis.http_posture import analyze_http_posture
    from app.analysis.error_disclosure import analyze_error_disclosure
    from app.analysis.auth_posture import analyze_auth_posture
    from app.analysis.api_exposure import analyze_api_exposure
    from app.analysis.api_inventory import analyze_api_inventory
    from app.analysis.api_sequences import analyze_api_sequences
    from app.analysis.mass_assignment import analyze_mass_assignment
    from app.analysis.rate_limit import analyze_rate_limit
    from app.analysis.schema_audit import analyze_schema
    from app.analysis.dom_sinks import analyze_dom_sinks
    steps = [
        # Keep the JS on disk current for retire.js/jsluice, in case the
        # operator re-runs analysis and then a manual scan.
        ("js_cache", materialise_js),
        ("js_recon", analyze_js),            # first: may seed new endpoints
        ("params", analyze_params),          # also seeds parameterised endpoints
        ("logic", analyze_logic),
        ("jwt", analyze_jwt),
        ("access_control", analyze_access_control),
        ("cors", analyze_cors),
        # Read-only re-read of captured responses: cookie flags, CSP,
        # clickjacking, HSTS, version disclosure. Sends nothing, so it still
        # works on a WAF'd target where active probing stalls.
        ("http_posture", analyze_http_posture),
        # Stack traces / SQL errors / internal paths in captured responses.
        ("error_disclosure", analyze_error_disclosure),
        # Secrets and personal data handed back by the API itself.
        ("api_exposure", analyze_api_exposure),
        # Shadow and zombie APIs (OWASP API9): the version the application
        # stopped calling and the endpoint the archives remember. It also runs
        # before vuln analysis (orchestrator/loop.py) so the forgotten versions
        # it finds get scanned; here it sees the whole run's traffic.
        ("api_inventory", analyze_api_inventory),
        # The contract itself, read rather than exercised: no security scheme
        # on the operation that deletes an account, no 429 in three hundred
        # operations, a request body that accepts any property the caller
        # invents. Sends nothing - it reads the schema already in hand.
        ("schema_audit", analyze_schema),
        # The two live API checks. Both WRITE or BURST, so both take
        # allow_active like auth_posture does, and both self-gate on the
        # engagement's own allow_active_exploit as well - the per-run override
        # can only ever be more restrictive than the engagement.
        ("mass_assignment",
         lambda eid: analyze_mass_assignment(eid, allow_active=allow_active)),
        ("rate_limit",
         lambda eid: analyze_rate_limit(eid, allow_active=allow_active)),
        # The only check here that sends a SEQUENCE: create an object, learn
        # its identifier from the response, then ask a second question about
        # it. That is how the strongest authorisation findings are actually
        # established, and it is the one thing RESTler had that nothing else
        # here did - see analysis/api_sequences for why the binary is not
        # shipped. Starts with a write, so it takes the same gate.
        ("api_sequences",
         lambda eid: analyze_api_sequences(eid, allow_active=allow_active)),
        # Client-side: DOM XSS sinks fed from the URL, postMessage handlers.
        ("dom_sinks", analyze_dom_sinks),
        # Identity + authentication. The bypass probe is active (in-scope GETs),
        # so it self-gates on allow_active like the other active analyzers.
        ("auth_posture", lambda eid: analyze_auth_posture(eid, allow_active=allow_active)),
        ("graphql", analyze_graphql),
        ("llm_recon", analyze_llm_recon),    # LLM eye on captured traffic (grounded)
    ]
    if allow_active:
        steps.append(("cve_checks", run_cve_checks))    # confirm high-value CVEs
    # public_exploits used to run here. It now runs in the EXPLOITATION phase
    # (app/orchestrator/loop.py), after the known-CVE pass, for two reasons:
    # the pass discovers CVEs of its own that the aggregation was missing
    # entirely, and "which public PoCs exist for this" is exploitation
    # intelligence, not traffic analysis.
    out: Dict[str, Dict] = {}
    for name, fn in steps:
        try:
            out[name] = await fn(engagement_id)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] analyzer %s failed", engagement_id, name)
            out[name] = {"error": 1}
    return out
