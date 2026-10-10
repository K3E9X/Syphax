"""Build an OpenAPI schema from the traffic the run captured.

Most targets publish no schema. Salt Security measures a gap of up to 40%
between the spec an organisation documents and what is actually deployed, and
the undocumented half is where the interesting endpoints live - so even a
target that DOES publish one is only telling part of the story.

That matters here because VULN-API-CONTRACT (schemathesis) property-tests every
documented operation and applies only to an asset whose URL names a schema.
Without one it never runs. With a schema synthesised from what katana and httpx
actually spoke to the application, it runs on any target at all.

The schema is a description of OBSERVED behaviour, not a contract. It is
labelled as such in its own `info` block, because handing someone a generated
file that looks like the vendor's own specification would be a lie with a long
half-life.
"""
from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("syphax.analysis.openapi_synth")

MAX_FLOWS = 4000
MAX_OPERATIONS = 300

# Segments that are an identifier rather than a route. /users/4821 and
# /users/9f3c-... are one operation, and emitting them as two hundred separate
# paths would produce a schema no fuzzer can use.
_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_SLUG_ID = re.compile(r"^[0-9a-f]{8,}(?:-[0-9a-z]+)*$", re.I)

# Content types worth describing. A stylesheet has no API shape.
_API_TYPES = ("json", "xml", "x-www-form-urlencoded", "graphql")


def templated(path: str) -> str:
    """/users/4821/orders/9f3c -> /users/{id}/orders/{id}"""
    out = []
    for segment in (path or "/").split("/"):
        if not segment:
            out.append(segment)
            continue
        if (_NUMERIC.match(segment) or _UUID.match(segment)
                or _HEX.match(segment) or _SLUG_ID.match(segment)):
            out.append("{id}")
        else:
            out.append(segment)
    joined = "/".join(out)
    return joined if joined.startswith("/") else "/" + joined


def _is_api(content_type: Optional[str], path: str) -> bool:
    ct = (content_type or "").lower()
    if any(marker in ct for marker in _API_TYPES):
        return True
    # A JSON-less endpoint under /api is still an API operation.
    return "/api/" in path.lower() or path.lower().startswith("/api")


def _schema_for(value: str) -> Dict[str, str]:
    if _NUMERIC.match(value or ""):
        return {"type": "integer"}
    if (value or "").lower() in ("true", "false"):
        return {"type": "boolean"}
    return {"type": "string"}


def build(flows: List[Dict[str, Any]], *, base_url: str) -> Dict[str, Any]:
    """An OpenAPI 3.0 document describing what these flows did. Pure."""
    parsed_base = urlparse(base_url or "")
    operations: Dict[str, Dict[str, Any]] = defaultdict(dict)
    seen_ops = 0

    for flow in flows[:MAX_FLOWS]:
        method = str(flow.get("method") or "GET").lower()
        if method not in ("get", "post", "put", "patch", "delete", "head"):
            continue
        url = str(flow.get("url") or "")
        if not url:
            continue
        parts = urlparse(url)
        if not _is_api(flow.get("response_content_type"), parts.path):
            continue

        path = templated(parts.path)
        if path in operations and method in operations[path]:
            _merge_response(operations[path][method], flow)
            continue
        if seen_ops >= MAX_OPERATIONS:
            continue
        seen_ops += 1

        parameters = []
        for name, values in parse_qs(parts.query).items():
            parameters.append({
                "name": name, "in": "query", "required": False,
                "schema": _schema_for(values[0] if values else ""),
                "example": (values[0] if values else "")[:80],
            })
        for segment in path.split("/"):
            if segment == "{id}":
                parameters.append({
                    "name": "id", "in": "path", "required": True,
                    "schema": {"type": "string"},
                })
                break

        operation: Dict[str, Any] = {
            "summary": f"Observed {method.upper()} {path}",
            "parameters": parameters,
            "responses": {},
        }
        if method in ("post", "put", "patch"):
            ct = str(flow.get("request_content_type") or "application/json")
            operation["requestBody"] = {
                "required": False,
                "content": {ct.split(";")[0]: {"schema": {"type": "object"}}},
            }
        _merge_response(operation, flow)
        operations[path][method] = operation

    return {
        "openapi": "3.0.3",
        "info": {
            "title": f"Observed API for {parsed_base.hostname or base_url}",
            "version": "observed",
            "description": (
                "SYNTHESISED FROM CAPTURED TRAFFIC. This describes what the "
                "application was seen to do during this engagement; it is not "
                "the vendor's contract and has no authority. Operations the "
                "run never exercised are absent, and types are inferred from "
                "single observed values."),
        },
        "servers": [{"url": base_url.rstrip("/")}] if base_url else [],
        "paths": {path: ops for path, ops in sorted(operations.items())},
    }


def _merge_response(operation: Dict[str, Any], flow: Dict[str, Any]) -> None:
    status = flow.get("status_code")
    if status is None:
        return
    ct = str(flow.get("response_content_type") or "application/json").split(";")[0]
    operation.setdefault("responses", {})[str(status)] = {
        "description": f"Observed {status}",
        "content": {ct: {"schema": {"type": "object"}}},
    }


def operation_count(document: Dict[str, Any]) -> int:
    return sum(len(ops) for ops in (document.get("paths") or {}).values())


async def synthesise(engagement_id: str, *, run_id: str = "") -> Dict[str, Any]:
    """Write a schema for this engagement, if the traffic supports one."""
    from app.engagements import EngagementRepository
    from app.proxy import FlowRepository
    from app.scans.artifacts import OPENAPI, artifact_dir, ensure, write_artifact

    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    repo = FlowRepository()
    summaries = await repo.list_flows(limit=MAX_FLOWS)
    flows = [
        {"method": f.method, "url": f.url, "status_code": f.status_code,
         "request_content_type": f.request_content_type,
         "response_content_type": f.response_content_type}
        for f in summaries
        if eng.host_in_scope((urlparse(f.url).hostname or "").lower())
    ]
    if not flows:
        await _say(engagement_id, run_id,
                   "No captured traffic to build an API schema from. The "
                   "contract tests need either a published schema or traffic "
                   "to infer one from.")
        return {"operations": 0, "flows": 0}

    document = build(flows, base_url=eng.target_url or "")
    count = operation_count(document)
    if not count:
        await _say(engagement_id, run_id,
                   f"{len(flows)} captured request(s), none of them API-shaped "
                   f"(no JSON, XML or /api path), so no schema was built.")
        return {"operations": 0, "flows": len(flows)}

    directory = ensure(artifact_dir(eng.target_url or eng.target_host, OPENAPI))
    path = write_artifact(directory, "observed.json",
                          json.dumps(document, indent=2))
    if path is None:
        await _say(engagement_id, run_id,
                   f"Built a {count}-operation schema from traffic but could "
                   f"not write it to the artifact directory, so the contract "
                   f"tests have nothing to read.")
        return {"operations": count, "flows": len(flows), "path": ""}
    await _say(engagement_id, run_id,
               f"Built an OpenAPI schema from captured traffic: {count} "
               f"operation(s) across {len(document['paths'])} path(s). The "
               f"contract tests can now run on a target that publishes none.")
    return {"operations": count, "flows": len(flows), "path": str(path)}


def synthesised_spec(target: str):
    """The schema built for this target, or None. Used by the wrapper."""
    from app.scans.artifacts import OPENAPI, artifact_dir

    directory = artifact_dir(target, OPENAPI)
    if directory is None:
        return None
    candidate = directory / "observed.json"
    try:
        return candidate if candidate.is_file() and candidate.stat().st_size > 2 else None
    except OSError:
        return None


async def _say(engagement_id: str, run_id: str, message: str) -> None:
    try:
        from app import events
        await events.emit(engagement_id, events.THOUGHT, message,
                          run_id=run_id or None, level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001 - reporting never fails the pass
        logger.debug("could not report the synthesised schema")
