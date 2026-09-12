"""schemathesis: property-based testing of a documented API.

If the target publishes OpenAPI/Swagger, the whole parameterised surface is
already described: every operation, every parameter, every declared response.
schemathesis generates that surface and tests it against PROPERTIES rather
than signatures - an unexpected 500, a response that violates the schema the
API itself publishes, a status code the spec never documented, an endpoint
that ignores the auth it declares.

Two reasons this reduces false positives rather than adding noise:

  * the oracle is the target's own contract. "This endpoint returned 500" and
    "this response does not match the schema you published" are not heuristic
    matches - there is nothing to guess about them.
  * it reaches operations neither the proxy capture nor the crawl ever saw,
    which is the class of endpoint that otherwise produces "no finding"
    because nothing tested it.

The `coverage` phase sends unspecified HTTP methods (PUT/DELETE/TRACE) to
every operation to see how the API reacts. Against a live target that is a
write, so the catalog runs the fuzzing/examples phases only; an operator who
wants the rest adds `--phases=coverage` per scan.

Parsing: `--report ndjson --report-ndjson-path /dev/stdout` emits one JSON
event per line, interleaved with schemathesis' own progress banner, which
iter_json_lines skips. The failures live on ScenarioFinished events, under
`recorder.checks[case_id][].failure_info.failure`.
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult, iter_json_lines

# Which check failed -> (our severity, vuln_class). schemathesis rates its own
# failures, but its scale is about test outcomes: a 500 is "critical" to a test
# runner and a medium-severity bug to a report. We rate them ourselves so the
# validator's severity-driven confidence means the same thing as everywhere
# else in syphax.
CHECK_MEANING = {
    # An endpoint that ignores the authentication it declares is the one
    # finding here that is a real access-control break.
    "ignored_auth": ("high", "broken_authentication"),
    # An unhandled exception: a bug, often with a stack trace in the body.
    "not_a_server_error": ("medium", "unhandled_error"),
    "use_after_free": ("medium", "api_contract_violation"),
    "ensure_resource_availability": ("low", "api_contract_violation"),
    # The API disagrees with its own published contract.
    "response_schema_conformance": ("low", "api_contract_violation"),
    "status_code_conformance": ("low", "api_contract_violation"),
    "content_type_conformance": ("low", "api_contract_violation"),
    "response_headers_conformance": ("low", "api_contract_violation"),
    "allow_header_conformance": ("low", "api_contract_violation"),
    "unsupported_method": ("low", "api_contract_violation"),
    "missing_required_header": ("low", "api_contract_violation"),
    # Input validation the schema promises but the server does not enforce.
    "negative_data_rejection": ("low", "input_validation"),
    "positive_data_acceptance": ("low", "input_validation"),
}
DEFAULT_MEANING = ("low", "api_contract_violation")

MAX_FINDINGS = 60


def meaning_of(check: str):
    return CHECK_MEANING.get((check or "").strip().lower(), DEFAULT_MEANING)


def _case_uri(recorder: Dict[str, Any], case_id: str, target: str) -> str:
    """The exact URI schemathesis sent, when it recorded the interaction."""
    interactions = recorder.get("interactions")
    if isinstance(interactions, dict):
        entry = interactions.get(case_id)
        if isinstance(entry, dict):
            req = entry.get("request")
            if isinstance(req, dict) and req.get("uri"):
                return str(req["uri"])
    cases = recorder.get("cases")
    if isinstance(cases, dict):
        entry = cases.get(case_id)
        value = entry.get("value") if isinstance(entry, dict) else None
        if isinstance(value, dict) and value.get("path"):
            return f"{target.rstrip('/')}{value['path']}"
    return target


def _case_method(recorder: Dict[str, Any], case_id: str) -> str:
    cases = recorder.get("cases")
    if isinstance(cases, dict):
        entry = cases.get(case_id)
        value = entry.get("value") if isinstance(entry, dict) else None
        if isinstance(value, dict) and value.get("method"):
            return str(value["method"]).upper()
    return "GET"


def failures_of(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every failed check on one ScenarioFinished event, flattened."""
    scenario = event.get("ScenarioFinished")
    if not isinstance(scenario, dict):
        return []
    recorder = scenario.get("recorder")
    if not isinstance(recorder, dict):
        return []
    checks = recorder.get("checks")
    if not isinstance(checks, dict):
        return []
    label = str(recorder.get("label") or "")
    out = []
    for case_id, entries in checks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("status") != "failure":
                continue
            info = entry.get("failure_info")
            failure = info.get("failure") if isinstance(info, dict) else None
            failure = failure if isinstance(failure, dict) else {}
            out.append({
                "check": str(entry.get("name") or "unknown"),
                "case_id": str(case_id),
                "label": label,
                "operation": str(failure.get("operation") or label),
                "title": str(failure.get("title") or entry.get("name") or "check failed"),
                "message": str(failure.get("message") or ""),
                "type": str(failure.get("type") or ""),
                "phase": str(scenario.get("phase") or ""),
                "recorder": recorder,
            })
    return out


class SchemathesisWrapper(BaseWrapper):
    name = "schemathesis"
    binary = "schemathesis"
    description = "Property-based testing of an OpenAPI/GraphQL API against its own contract."
    category = "vuln"
    timeout_seconds = 25 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary, "run", target,
            "--report", "ndjson",
            "--report-ndjson-path", "/dev/stdout",
            # fuzzing + examples only. The coverage phase sends PUT/DELETE/
            # TRACE to every operation, which is a write against a live target.
            "--phases", "fuzzing,examples",
            "--max-examples", "25",
            "--rate-limit", "20/s",
            "--workers", "2",
            "--output-sanitize", "true",   # keep credentials out of the report
            "--continue-on-failure",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        seen = set()
        for event in iter_json_lines(stdout):
            for fail in failures_of(event):
                key = (fail["check"], fail["operation"])
                if key in seen:
                    continue   # one finding per (check, operation), not per case
                seen.add(key)
                severity, vuln_class = meaning_of(fail["check"])
                uri = _case_uri(fail["recorder"], fail["case_id"], target)
                method = _case_method(fail["recorder"], fail["case_id"])
                detail = fail["message"].strip()
                findings.append(Finding(
                    severity=severity,
                    title=f"{fail['title']} — {fail['operation']}",
                    description=(f"schemathesis check '{fail['check']}' failed against "
                                 f"the API's own published contract."
                                 + (f" {detail}" if detail else "")),
                    target=uri,
                    evidence=(f"{method} {uri}\ncheck: {fail['check']}\n"
                              f"failure: {fail['type'] or fail['title']}\n"
                              f"{detail}").strip(),
                    metadata={"tool": "schemathesis", "vuln_class": vuln_class,
                              "check": fail["check"], "operation": fail["operation"],
                              "phase": fail["phase"], "method": method},
                ))
                if len(findings) >= MAX_FINDINGS:
                    return ToolResult(findings=findings)
        return ToolResult(findings=findings)
