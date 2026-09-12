"""jsluice: parse the JavaScript instead of regexing it.

`js_recon.py` mines captured bodies with regexes, and that is why it both
misses and over-reports: a URL built by string concatenation
(`"/api/" + version + "/users"`) never matches a literal pattern, while a
plausible-looking string inside a comment or a minified variable name does.
jsluice walks a real JavaScript AST, so the URLs and secrets it reports came
out of the code's actual structure - including the pieces it can reassemble
from concatenation and template literals.

What it adds that the regex pass cannot:
  * endpoints the crawler and the proxy never saw, with their METHOD and their
    query/body parameter names - which is exactly what the adaptive prober
    needs to have an injection point at all;
  * a second, structural opinion on secrets, which the corroboration pass then
    weighs against js_recon's regex opinion.

Two subcommands, both emitting JSONL: `urls` and `secrets`. The catalog runs
`urls`; `secrets` is available per scan. jsluice takes files as arguments and
the worker execs without a shell, so the wrapper lists the artifact directory
itself at command-build time.
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence
from urllib.parse import urljoin, urlparse

from app.scans.artifacts import js_dir, listdir
from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult, iter_json_lines

MAX_FILES = 120
MAX_FINDINGS = 120

JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".map", ".json", ".html")


def absolute(url: str, target: str) -> str:
    """A relative endpoint made absolute against the target's origin."""
    raw = str(url or "").strip()
    if not raw:
        return target
    if "://" in raw:
        return raw
    parsed = urlparse(target or "")
    if not parsed.scheme or not parsed.netloc:
        return raw
    return urljoin(f"{parsed.scheme}://{parsed.netloc}/", raw.lstrip("/"))


def params_of(rec: Dict[str, Any]) -> List[str]:
    out = []
    for key in ("queryParams", "bodyParams"):
        value = rec.get(key)
        if isinstance(value, list):
            out.extend(str(v) for v in value if v)
    return out


def secret_severity(rec: Dict[str, Any]) -> str:
    """jsluice rates some secrets; anything unrated is a lead, not a finding.

    A structural match is still a match on shape, not a proven credential -
    trufflehog's verified pass is what turns one of these into "live".
    """
    sev = str(rec.get("severity") or "").strip().lower()
    if sev in ("critical", "high", "medium", "low", "info"):
        return sev
    return "medium"


class JsluiceWrapper(BaseWrapper):
    name = "jsluice"
    binary = "jsluice"
    description = "Extract URLs, parameters and secrets from JavaScript with a real parser."
    category = "recon"
    timeout_seconds = 10 * 60

    # "urls" | "secrets". Overridden per scan via options.
    subcommand = "urls"

    def js_files(self, target: str) -> List[str]:
        return [str(p) for p in listdir(js_dir(target), suffixes=JS_SUFFIXES,
                                        limit=MAX_FILES)]

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        opts = list(options)
        sub = self.subcommand
        # Let the operator pick the subcommand as the first option.
        if opts and opts[0] in ("urls", "secrets"):
            sub = opts.pop(0)
        return [self.binary, sub, *opts, *self.js_files(target)]

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        seen = set()
        for rec in iter_json_lines(stdout):
            if rec.get("kind") or rec.get("data"):
                finding = self._secret(rec, target)
            elif rec.get("url"):
                finding = self._endpoint(rec, target)
            else:
                continue
            if finding is None:
                continue
            key = (finding.title, finding.target)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
            if len(findings) >= MAX_FINDINGS:
                break
        return ToolResult(findings=findings)

    def _endpoint(self, rec: Dict[str, Any], target: str):
        url = absolute(str(rec.get("url")), target)
        method = str(rec.get("method") or "GET").upper()
        params = params_of(rec)
        kind = str(rec.get("type") or "reference")
        return Finding(
            severity="info",
            title=f"Endpoint in JavaScript: {method} {urlparse(url).path or url}",
            description=(f"jsluice extracted this endpoint from the page's JavaScript "
                         f"({kind}). It is attack surface that is not linked from the "
                         f"UI, so nothing else in the run would have tested it."
                         + (f" Parameters: {', '.join(params)}." if params else "")),
            target=url,
            evidence=(f"{method} {url}\nsource: {rec.get('filename') or '(captured JS)'}\n"
                      + (f"params: {', '.join(params)}\n" if params else "")
                      + str(rec.get("source") or "")[:300]).strip(),
            metadata={"tool": "jsluice", "vuln_class": "recon", "method": method,
                      "params": params, "asset": url, "asset_kind": "endpoint"},
        )

    def _secret(self, rec: Dict[str, Any], target: str):
        kind = str(rec.get("kind") or "secret")
        data = rec.get("data")
        # Never echo the credential itself into a finding; report its shape.
        shape = ", ".join(sorted(data)) if isinstance(data, dict) else ""
        return Finding(
            severity=secret_severity(rec),
            title=f"Possible {kind} in JavaScript",
            description=("jsluice matched a credential structure in the page's "
                         "JavaScript. A structural match is a lead: trufflehog's "
                         "verified pass is what decides whether it is live."),
            target=target,
            evidence=(f"Kind   : {kind}\nFields : {shape or '(unnamed)'}\n"
                      f"Source : {rec.get('filename') or '(captured JS)'}"),
            metadata={"tool": "jsluice", "vuln_class": "secret_exposure",
                      "kind": kind, "fields": sorted(data) if isinstance(data, dict) else []},
        )
