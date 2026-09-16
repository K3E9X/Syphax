"""GraphQL discovery + introspection test.

GraphQL endpoints are a common modern target: with introspection enabled an
attacker downloads the whole schema (every query, mutation and type), which maps
the entire API surface and frequently exposes hidden/admin operations.

We look for GraphQL endpoints in captured traffic and at a few common paths,
then send an introspection *query* over GET (queries are safe and most servers,
e.g. Apollo, accept them via GET). We never POST a mutation - that stays within
the read-only SafePoC model. If GET is refused we only report that the endpoint
exists.

Stored as a synthetic job (tool="graphql").
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List, Set
from urllib.parse import urlencode, urlparse, urlunparse

from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.models import Finding
from app.validation.safe_poc import SafePoC, ScopeError

logger = logging.getLogger("syphax.analysis.graphql")

_GQL_PATHS = ("/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
              "/v2/graphql", "/query", "/gql", "/graphql/console", "/api/gql")
_COMMON_PROBE = ("/graphql", "/api/graphql", "/v1/graphql", "/gql")

# A minimal introspection query - enough to prove the schema is readable.
_INTROSPECTION = "{__schema{queryType{name} types{name kind}}}"
_TYPENAME = "{__typename}"

_ERROR_SIGNS = ("must provide query", "cannot query field", "graphql",
                "syntax error", "query string")


async def analyze_graphql(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    flows_repo = FlowRepository()
    summaries = await flows_repo.list_flows(limit=1000)

    candidates: List[str] = []
    seen: Set[str] = set()

    def add(url: str) -> None:
        base = urlunparse(urlparse(url)._replace(query="", fragment=""))
        if base not in seen and eng.host_in_scope((urlparse(base).hostname or "").lower()):
            seen.add(base)
            candidates.append(base)

    for f in summaries:
        if _is_graphql_path(f.url):
            add(f.url)
    # Probe a few well-known paths on the base host even if never observed.
    base = urlunparse(urlparse(eng.target_url)._replace(path="", query="", fragment=""))
    for p in _COMMON_PROBE:
        add(base + p)

    safe = SafePoC(in_scope=eng.host_in_scope)
    findings: List[Finding] = []
    enabled = 0
    detected = 0

    for url in candidates[:10]:
        verdict = await _probe(safe, url)
        if verdict is None:
            continue
        detected += 1
        kind, evidence = verdict
        if kind == "introspection":
            enabled += 1
            findings.append(Finding(
                severity="medium",
                title=f"GraphQL introspection enabled: {urlparse(url).path}",
                description="The GraphQL schema is fully readable via introspection, "
                            "exposing every query/mutation/type (the whole API surface).",
                target=url, evidence=evidence,
                metadata={"vuln_class": "graphql", "status": "confirmed",
                          "confidence": 0.9, "kind": "introspection"},
            ))
        else:
            findings.append(Finding(
                severity="info",
                title=f"GraphQL endpoint detected: {urlparse(url).path}",
                description="A GraphQL endpoint is exposed (introspection not "
                            "confirmed over GET). Review queries/mutations and authz.",
                target=url, evidence=evidence,
                metadata={"vuln_class": "graphql", "status": "unconfirmed",
                          "confidence": 0.3, "kind": "endpoint"},
            ))

    await save_analysis_job(engagement_id, "graphql", findings, target="(graphql)")
    logger.info("[%s] graphql: candidates=%d detected=%d introspection=%d",
                engagement_id, len(candidates), detected, enabled)
    return {"candidates": len(candidates), "detected": detected, "introspection": enabled}


# --------------------------------------------------------------------------- #

def _is_graphql_path(url: str) -> bool:
    path = urlparse(url).path.lower().rstrip("/")
    return any(path.endswith(p) or path == p for p in _GQL_PATHS)


def _with_query(url: str, query: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode({"query": query})))


def _introspection_ok(text: str) -> bool:
    """True if the response is a GraphQL introspection result with a schema."""
    if "__schema" not in text:
        return False
    try:
        obj = json.loads(text)
    except Exception:  # noqa: BLE001
        return "queryType" in text  # clearly schema-shaped even if truncated
    data = obj.get("data") if isinstance(obj, dict) else None
    return isinstance(data, dict) and isinstance(data.get("__schema"), dict)


def _looks_like_graphql(text: str) -> bool:
    low = text.lower()
    return any(s in low for s in _ERROR_SIGNS)


async def _probe(safe: SafePoC, url: str):
    """Return ("introspection", evidence) | ("endpoint", evidence) | None."""
    try:
        resp = await safe.fetch(_with_query(url, _INTROSPECTION), method="GET")
    except ScopeError:
        return None
    if resp is not None and resp.status_code == 200 and _introspection_ok(resp.text):
        return ("introspection", f"GET {url}?query={{__schema...}} -> schema returned "
                                 f"({len(resp.text)} bytes).")
    # Not introspectable over GET; confirm it's at least a GraphQL endpoint.
    try:
        probe = await safe.fetch(_with_query(url, _TYPENAME), method="GET")
    except ScopeError:
        return None
    if probe is None:
        return None
    if _introspection_ok(probe.text):
        return ("introspection", f"GET {url} introspection returned a schema.")
    if "__typename" in probe.text or _looks_like_graphql(probe.text):
        return ("endpoint", f"GET {url} responds to a GraphQL query "
                            f"(HTTP {probe.status_code}).")
    return None
