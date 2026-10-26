"""GraphQL discovery and testing.

A GraphQL endpoint is one URL that answers for the whole API, which is why it
is worth real attention: one unguarded field is reachable from the same path as
every guarded one.

This analyser used to ask a single question - is introspection on? That is the
first question and the least interesting, because switching introspection off
is the one thing every team does. The checks in `graphql_probes` are the ones
that survive it: field suggestions (schema disclosure with introspection off),
__type when __schema is blocked at the WAF, alias and directive amplification
primitives, queries accepted in a URL, the console left in production, and the
engine behind it all.

Every check is one GET with a benign query, so the whole suite stays inside the
SafePoC model. Nothing sends a mutation (a write), a batch, or the thousands of
aliases that would turn a measurement into an outage - see graphql_probes for
why each of those is left out.

Stored as a synthetic job (tool="graphql").
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlencode, urlparse, urlunparse

from app.limits import cap
from app.analysis import graphql_probes as probes
from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.models import Finding
from app.validation.safe_poc import (SafePoC, ScopeError, identity_for)

logger = logging.getLogger("syphax.analysis.graphql")

_GQL_PATHS = ("/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
              "/v2/graphql", "/query", "/gql", "/graphql/console", "/api/gql")
_COMMON_PROBE = ("/graphql", "/api/graphql", "/v1/graphql", "/gql")

# A minimal introspection query - enough to prove the schema is readable.
_INTROSPECTION = "{__schema{queryType{name} types{name kind}}}"

MAX_ENDPOINTS = cap(6)          # the suite is 8 GETs per endpoint


async def analyze_graphql(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    candidates = await _candidates(eng)
    safe = SafePoC(in_scope=eng.host_in_scope,
        identity=identity_for(eng))
    findings: List[Finding] = []
    detected = 0
    introspection = 0

    for url in candidates[:MAX_ENDPOINTS]:
        checks = await run_suite(safe, url)
        if checks is None:
            continue
        detected += 1
        if checks.get("introspection"):
            introspection += 1
        findings.extend(findings_for(url, checks))

    await save_analysis_job(engagement_id, "graphql", findings, target="(graphql)")
    logger.info("[%s] graphql: candidates=%d detected=%d introspection=%d findings=%d",
                engagement_id, len(candidates), detected, introspection, len(findings))
    return {"candidates": len(candidates), "detected": detected,
            "introspection": introspection, "findings": len(findings)}


# ---------------------------------------------------------------------------
# the suite
# ---------------------------------------------------------------------------


async def run_suite(safe: SafePoC, url: str) -> Optional[Dict[str, Any]]:
    """Every check against one endpoint, or None if it is not GraphQL.

    Ordered so the cheap disqualification comes first: an endpoint that does
    not answer a GraphQL query at all costs one request, not eight.
    """
    typename = await _get(safe, url, probes.QUERY_TYPENAME)
    if typename is None:
        return None

    answered = probes.responds_to_graphql(typename.text, typename.status_code)
    console = ""
    if not answered:
        # The cheap disqualification did not fire. Before dropping the
        # endpoint, ask whether a console is served here: a GraphiQL or
        # Playground page proves the server exists even when the probe's
        # answer was not one we recognise.
        #
        # And if it does, run the WHOLE suite rather than reporting the
        # console alone. An end-to-end run against a deliberately odd server
        # caught this: the probe got an answer the matcher did not know, and
        # introspection, field suggestions, aliases and directives - all of
        # which that server had - were never asked about. One unrecognised
        # response must not cost seven checks.
        console = await _console(safe, url)
        if not console:
            return None

    checks: Dict[str, Any] = {
        "endpoint": True,
        "get_queries": typename.status_code == 200 and "__typename" in typename.text,
        "engine": probes.engine_from(typename.text),
        "evidence": {"typename": f"GET {url}?query={{__typename}} -> "
                                 f"{typename.status_code}"},
    }
    if console:
        checks["console"] = console
        checks["evidence"]["console"] = (
            f"GET {url} (Accept: text/html) -> {console}")

    full = await _get(safe, url, _INTROSPECTION)
    if full is not None and probes.schema_readable(full.text):
        checks["introspection"] = True
        checks["evidence"]["introspection"] = (
            f"GET {url}?query={{__schema...}} -> schema returned "
            f"({len(full.text)} bytes)")
    else:
        # __schema blocked: try __type, the string the WAF rule usually misses.
        partial = await _get(safe, url, probes.QUERY_PARTIAL_INTROSPECTION)
        if partial is not None:
            readable, field_count = probes.type_readable(partial.text)
            if readable:
                checks["partial_introspection"] = True
                checks["field_count"] = field_count
                checks["evidence"]["partial_introspection"] = (
                    f"GET {url}?query={{__type(name:\"Query\")...}} -> "
                    f"named {field_count} field(s) of Query while __schema "
                    f"was refused")

    # Field suggestions. Asked with a near-miss of __typename so the check
    # needs no knowledge of the schema.
    near = await _get(safe, url, probes.QUERY_SUGGESTION)
    if near is not None:
        on, message = probes.suggests_fields(near.text)
        if on:
            checks["suggestions"] = True
            checks["evidence"]["suggestions"] = (
                f"GET {url}?query={{{probes.NEAR_MISS_FIELD}}} -> {message}")
        if not checks.get("engine"):
            checks["engine"] = probes.engine_from(near.text)

    aliases = await _get(safe, url, probes.QUERY_ALIASES)
    if aliases is not None and probes.aliases_executed(aliases.text):
        checks["aliases"] = True
        checks["evidence"]["aliases"] = (
            f"GET {url}?query={{a:__typename b:__typename}} -> both aliases "
            f"resolved")

    directive = await _get(safe, url, probes.QUERY_DUPLICATE_DIRECTIVE)
    if directive is not None and probes.duplicate_directive_accepted(directive.text):
        checks["duplicate_directives"] = True
        checks["evidence"]["duplicate_directives"] = (
            f"GET {url}?query={{__typename @skip(if:false) @skip(if:false)}} "
            f"-> executed; the spec allows one @skip per location")

    if not checks.get("console"):      # not already settled above
        found = await _console(safe, url)
        if found:
            checks["console"] = found
            checks["evidence"]["console"] = (
                f"GET {url} (Accept: text/html) -> {found}")

    return checks


def findings_for(url: str, checks: Dict[str, Any]) -> List[Finding]:
    """One finding per thing established. Pure, so it is fully testable."""
    path = urlparse(url).path or "/"
    engine = str(checks.get("engine") or "")
    evidence = checks.get("evidence") or {}
    out: List[Finding] = []

    # The three schema-disclosure kinds carry `graphql_introspection`, which
    # the exploit strategy knows and can author from: with the schema in hand
    # the model can look for the admin mutation no client calls, which is the
    # escalation the disclosure actually enables. The class used to be
    # "graphql", which nothing routed, so every GraphQL finding this analyser
    # ever produced was discarded as "no route available".
    def add(severity: str, title: str, description: str, kind: str,
            vuln_class: str = "graphql_introspection", confidence: float = 0.9,
            status: str = "confirmed") -> None:
        out.append(Finding(
            severity=severity, title=title, description=description,
            target=url, evidence=str(evidence.get(kind) or ""),
            metadata={"tool": "graphql", "vuln_class": vuln_class,
                      "status": status, "confidence": confidence,
                      "kind": kind, "engine": engine,
                      "owasp_api": "API9:2023" if kind == "console" else ""},
        ))

    if checks.get("introspection"):
        add("medium", f"GraphQL introspection enabled: {path}",
            "The schema is fully readable: every query, mutation, type and "
            "field, including the operations no client calls. That is the "
            "whole API surface handed over in one request, and it is where an "
            "attacker gets the field names for everything else.",
            "introspection", confidence=0.95)
    elif checks.get("partial_introspection"):
        add("medium", f"GraphQL introspection is only partly blocked: {path}",
            f"__schema was refused but __type answered, naming "
            f"{checks.get('field_count', 0)} field(s) of Query. Introspection "
            f"is not off here - the literal string \"__schema\" is filtered, "
            f"which a different query walks straight around. The schema is "
            f"readable type by type.",
            "partial_introspection", confidence=0.9)

    if checks.get("suggestions"):
        add("medium", f"GraphQL field suggestions leak the schema: {path}",
            "A misspelt field name comes back with \"Did you mean ...\". That "
            "is schema disclosure that survives introspection being switched "
            "off: each wrong guess is answered with the right name, so the "
            "type graph can be walked one field at a time. Turn suggestions "
            "off in production (Apollo: NoSchemaIntrospectionCustomRule plus "
            "didYouMean disabled; graphql-js: a validation rule).",
            "suggestions", confidence=0.9)

    if checks.get("aliases"):
        add("low", f"GraphQL alias amplification is available: {path}",
            "One query may repeat the same field under many aliases, and the "
            "server resolves each one, so a single request costs N times the "
            "work. We sent TWO aliases and both resolved - enough to show the "
            "primitive exists. We did not send the thousands that turn it "
            "into an outage: that is a denial-of-service test and is out of "
            "scope for this tool. A query-complexity or alias limit is the "
            "fix (graphql-query-complexity, Apollo's maxAliases).",
            "aliases", vuln_class="rate_limit", confidence=0.85)

    if checks.get("duplicate_directives"):
        add("low", f"GraphQL accepts a repeated directive: {path}",
            "The specification allows @skip once per location; this server "
            "executed a field carrying it twice. A server that accepts two "
            "will accept ten thousand, which is the same amplification as "
            "aliases by another route. We sent two, and stopped there.",
            "duplicate_directives", vuln_class="rate_limit", confidence=0.85)

    if checks.get("console"):
        add("medium",
            f"GraphQL console exposed in production: {checks['console']} at {path}",
            f"{checks['console']} is being served here. It is an interactive "
            f"API client - schema browser, autocomplete, query editor - handed "
            f"to anyone who finds the path, and it makes every other weakness "
            f"on this endpoint easier to reach. Consoles belong behind "
            f"authentication or off.",
            "console", vuln_class="misconfiguration", confidence=0.95)

    if not out:
        # The endpoint exists and nothing above fired. Still worth recording:
        # it is the one URL the whole API answers on.
        severity = "info"
        detail = ("A GraphQL endpoint is exposed. Introspection, field "
                  "suggestions, alias and directive amplification and the "
                  "console were all tested and none answered"
                  f"{f'; the engine looks like {engine}' if engine else ''}. "
                  "Authorisation per field is the remaining question and it "
                  "needs the application's own identities.")
        add(severity, f"GraphQL endpoint detected: {path}", detail,
            "typename", confidence=0.6, status="unconfirmed")

    return out


# ---------------------------------------------------------------------------


async def _candidates(eng) -> List[str]:
    try:
        summaries = await FlowRepository().list_flows(limit=1000)
    except Exception:  # noqa: BLE001 - no traffic is not a failure
        summaries = []

    out: List[str] = []
    seen: Set[str] = set()

    def add(url: str) -> None:
        base = urlunparse(urlparse(url)._replace(query="", fragment=""))
        host = (urlparse(base).hostname or "").lower()
        if base not in seen and host and eng.host_in_scope(host):
            seen.add(base)
            out.append(base)

    for flow in summaries:
        if _is_graphql_path(flow.url):
            add(flow.url)
    base = urlunparse(urlparse(eng.target_url)._replace(path="", query="",
                                                        fragment=""))
    for path in _COMMON_PROBE:
        add(base + path)
    return out


def _is_graphql_path(url: str) -> bool:
    path = urlparse(url).path.lower().rstrip("/")
    return any(path.endswith(p) or path == p for p in _GQL_PATHS)


def _with_query(url: str, query: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode({"query": query})))


async def _get(safe: SafePoC, url: str, query: str):
    try:
        return await safe.fetch(_with_query(url, query), method="GET")
    except ScopeError:
        return None
    except Exception:  # noqa: BLE001 - one failed probe is not the suite
        logger.debug("graphql probe failed for %s", url)
        return None


async def _console(safe: SafePoC, url: str) -> str:
    """The console served at this path, or "". One GET, asking for HTML."""
    try:
        resp = await safe.fetch(url, method="GET",
                                headers={"Accept": "text/html"})
    except ScopeError:
        return ""
    except Exception:  # noqa: BLE001
        return ""
    if resp is None:
        return ""
    return probes.console_in_response(
        resp.text, (resp.headers or {}).get("content-type", ""))
