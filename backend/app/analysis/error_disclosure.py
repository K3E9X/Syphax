"""Verbose errors: stack traces, SQL errors and internal paths in responses.

The OWASP Error Handling family had no check. A stack trace is not cosmetic: it
names the framework and version, the absolute path of the source tree and often
the query that failed - which is both a CVE lookup and the oracle an injection
test needs. A database error in particular means unsanitised input reached the
driver.

Read-only: it re-reads response bodies the proxy already captured and sends
nothing. One finding per (host, kind) - the same traceback on fifty pages is
one weakness.

Stored as a synthetic job (tool="error_disclosure").
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple

from app import db
from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.error_disclosure")

MAX_FLOWS = 800
MAX_BODY = 200_000          # bodies are already truncated upstream
_SNIPPET = 300

# (kind, severity, label, pattern). Database errors rank highest: they mean raw
# input reached the driver, which is the injection oracle itself.
_SIGNATURES: List[Tuple[str, str, str, re.Pattern]] = [
    ("sql_error", "high", "SQL error",
     re.compile(r"(You have an error in your SQL syntax|SQLSTATE\[|"
                r"Unclosed quotation mark after the character string|"
                r"ORA-\d{5}|PG::\w+Error|psycopg2\.\w+Error|"
                r"SQLiteException|MySqlException|PostgresException)", re.I)),
    ("stack_trace", "medium", "Python traceback",
     re.compile(r"Traceback \(most recent call last\)")),
    ("stack_trace", "medium", "Java stack trace",
     re.compile(r"(Exception in thread \"|\bat (?:com|org|java)\.[\w.$]+\([\w$]+\.java:\d+\))")),
    ("stack_trace", "medium", ".NET stack trace",
     # A frame or an error page - not a bare "System.ArgumentNullException"
     # mentioned in prose or in API documentation.
     re.compile(r"(Server Error in '.*' Application|"
                r"\bat System\.[\w.]+\(|"
                r"System\.[\w.]+Exception\s*:)")),
    ("stack_trace", "medium", "PHP error",
     # Both shapes: the HTML one PHP emits in a browser, and the bare text one
     # it writes when html_errors is off. "Warning:" alone is too common in
     # ordinary content to match on its own.
     re.compile(r"((?:PHP )?(?:Fatal error|Parse error|Uncaught \w*Error)(?:</b>)?\s*:|"
                r"PHP (?:Warning|Notice)|"
                r"<b>Warning</b>:.{0,80}on line <b>\d+)", re.I)),
    ("stack_trace", "medium", "Node.js stack trace",
     # A real frame starts a line; "bundled at ./node_modules/..." in a
     # sourcemap comment is not an error.
     re.compile(r"(at Object\.<anonymous> \(|^\s+at .{0,80}node_modules[/\\])",
                re.M)),
    ("stack_trace", "medium", "Ruby stack trace",
     re.compile(r"(ActionController::\w+Error|ActiveRecord::\w+Error|"
                r"[\w/]{1,120}\.rb:\d+:in `)")),
    ("debug_page", "medium", "Framework debug page",
     # "DEBUG = True" is Python; with re.I it also matched JavaScript's
     # `var DEBUG = true`, so every bundle with a debug flag was a finding.
     # Case-sensitive alternative, kept out of the re.I group.
     re.compile(r"(Werkzeug Debugger|Whoops, looks like something went wrong|"
                r"Django Version:|Symfony Exception|Rails\.application|"
                r"__debugger__)", re.I)),
    ("debug_page", "medium", "Framework debug page",
     re.compile(r"\bDEBUG\s*=\s*True\b")),
    ("path_disclosure", "low", "Internal filesystem path",
     re.compile(r"((?:/var/www|/usr/local/|/home/[\w.-]+/|/opt/[\w.-]+/|"
                r"[A-Za-z]:\\\\?(?:inetpub|wwwroot|Users|xampp))[\w./\\-]{3,})")),
]


async def analyze_error_disclosure(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    try:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                'SELECT url, host, status_code, response_body, response_content_type '
                'FROM flows WHERE response_body IS NOT NULL '
                'ORDER BY "timestamp" DESC LIMIT $1', MAX_FLOWS)
    except Exception:  # noqa: BLE001 - no proxy data is a normal state
        logger.debug("error_disclosure: could not read flows")
        return {"skipped": 1}

    hits: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for r in rows:
        host = (r["host"] or "").lower()
        if not host or not eng.host_in_scope(host):
            continue
        ctype = (r["response_content_type"] or "").lower()
        # Binary payloads carry no error pages; skip them cheaply.
        if ctype.startswith(("image/", "video/", "audio/", "font/")):
            continue
        body = _text(r["response_body"])
        if not body:
            continue
        matched = [(k, sev, label, pattern.search(body))
                   for k, sev, label, pattern in _SIGNATURES]
        matched = [(k, sev, label, m) for k, sev, label, m in matched if m]
        has_error = any(k != "path_disclosure" for k, _, _, _ in matched)
        failed = r["status_code"] is not None and r["status_code"] >= 400
        for kind, sev, label, m in matched:
            # A filesystem path inside a bundle or a sourcemap is the build
            # machine's layout, not a leak: /home/runner/work/... is every
            # GitHub Actions artefact. Only report one when the response is
            # actually an error, or when a real error signature sits with it.
            if kind == "path_disclosure" and not (has_error or failed):
                continue
            key = (host, kind, label)
            if key in hits:
                continue
            hits[key] = {"url": r["url"], "status": r["status_code"],
                         "snippet": _around(body, m.start()), "sev": sev}

    findings = [
        Finding(
            severity=data["sev"],
            title=f"{label} exposed on {host}",
            description=(
                "The server returned an internal error verbatim. It reveals the "
                "component and version, often the source path, and - for a "
                "database error - that unsanitised input reached the driver, "
                "which is exactly the oracle an injection test needs."
                if kind == "sql_error" else
                "The server returned an internal error verbatim, revealing the "
                "component, its version and internal paths."),
            target=data["url"],
            evidence=data["snippet"],
            metadata={"vuln_class": "information_disclosure", "kind": kind,
                      "signature": label, "host": host,
                      "status": data["status"], "tool": "error_disclosure"},
        )
        for (host, kind, label), data in hits.items()
    ]

    if findings:
        await save_analysis_job(engagement_id, "error_disclosure", findings,
                                target=eng.target_host or eng.target_url)
    return {"findings": len(findings)}


def _text(body: Any) -> str:
    if not body:
        return ""
    if isinstance(body, memoryview):
        body = body.tobytes()
    if isinstance(body, (bytes, bytearray)):
        return bytes(body[:MAX_BODY]).decode("utf-8", errors="replace")
    return str(body)[:MAX_BODY]


def _around(body: str, pos: int) -> str:
    start = max(0, pos - 80)
    return body[start:start + _SNIPPET].strip()
