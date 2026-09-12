"""Finding validator (spec §7).

Decides a ValidationStatus for each candidate finding, preferring real proof:

  1. Tool-confirmed   - sqlmap/commix/dalfox actively confirm their own
     findings (boolean/time oracle, command output, executed payload). We
     trust those and carry the payload as the PoC.
  2. Safe-PoC re-check - for classes we can prove with one in-scope GET:
       * exposed sensitive files (.git/.env/backup/phpinfo/...) -> fetch,
         confirm a content signature.
       * reflected XSS marker -> send a benign unique marker in the param,
         confirm it reflects unencoded.
  3. Heuristic        - nuclei/nikto/etc. carry their own match; treat as
     LIKELY (severity-scaled) unless a re-check applies.

Everything that touches the target goes through SafePoC (GET/HEAD only,
in-scope only). Nothing here sends a destructive payload.
"""
from __future__ import annotations

import logging
import re
import secrets
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.scans.models import Finding
from app.validation.models import ValidationResult, ValidationStatus
from app.validation.safe_poc import SafePoC, ScopeError

logger = logging.getLogger("syphax.validation.validator")

# Tools whose positive findings are already actively proven.
_TOOL_CONFIRMED = {"sqlmap", "commix", "dalfox"}

# Traffic-driven analyzers that precompute their own status/confidence/PoC in
# finding.metadata (see app/analysis/*). We trust that verdict verbatim.
_ANALYSIS_TOOLS = {"logic", "js-recon", "jwt", "access-control", "cors",
                   "params", "graphql", "exploit", "public-exploits", "cve-checks",
                   "auth-brute", "llm-recon", "payload-probe"}

# A dotenv line is an uppercase KEY=VALUE; an .htaccess carries a directive.
_ENV_LINE = re.compile(r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S")
_HTACCESS_DIRECTIVE = re.compile(
    r"(?mi)^\s*(RewriteEngine|RewriteRule|RewriteCond|Options|AuthType|AuthName"
    r"|Require|Deny|Allow|Order|DirectoryIndex|ErrorDocument|Header|AddType"
    r"|php_value|SetHandler|FilesMatch)\b")

# path-signature pairs: if the finding target ends with <path>, fetching it
# should contain <signature> to confirm the exposure.
_EXPOSED_SIGNATURES = [
    (".git/config", "[core]"),
    (".git/HEAD", "ref:"),
    # A bare "=" matched every HTML page and a bare "" matched any 200, so both
    # confirmed "publicly readable" on ordinary content. Require the file to
    # actually look like what it claims to be.
    (".env", _ENV_LINE),
    (".htaccess", _HTACCESS_DIRECTIVE),
    ("phpinfo", "phpinfo()"),
    ("server-status", "Apache Server Status"),
    ("/.svn/entries", ""),
    ("wp-config.php.bak", "DB_PASSWORD"),
    ("/actuator/env", "propertySources"),
]

_XSS_CLASSES = {"xss"}
_MARKER_RE_TMPL = r"{marker}"


class FindingValidator:
    def __init__(self, safe_poc: SafePoC) -> None:
        self.safe = safe_poc

    async def validate(self, finding: Finding, tool: str, vuln_class: str) -> ValidationResult:
        # 0. traffic-driven analyzers (logic/IDOR/CSRF/BFLA, JS secrets, JWT,
        # access-control) already decided their status from captured traffic +
        # safe re-fetch; trust the precomputed verdict.
        if tool in _ANALYSIS_TOOLS:
            md = finding.metadata or {}
            status_str = str(md.get("status", "likely"))
            try:
                conf = float(md.get("confidence", 0.55))
            except (TypeError, ValueError):
                conf = 0.55
            conf = max(0.0, min(1.0, conf))  # never trust an out-of-range value
            try:
                status = ValidationStatus(status_str)
            except ValueError:
                status = ValidationStatus.LIKELY
            return ValidationResult(
                status=status, confidence=conf, method=f"analysis ({tool})",
                poc=finding.evidence or "", detail="From captured traffic analysis.",
            )

        # 1. tool already proved it
        if tool in _TOOL_CONFIRMED:
            poc = finding.evidence or (finding.metadata or {}).get("payload") or ""
            return ValidationResult.confirmed(
                method=f"tool-confirmed ({tool})",
                poc=str(poc),
                detail=f"{tool} actively confirmed this finding.",
            )

        # 2a. exposed sensitive resource -> fetch and check signature
        exposed = await self._check_exposed_resource(finding)
        if exposed is not None:
            return exposed

        # 2b. reflected XSS marker
        if vuln_class in _XSS_CLASSES:
            reflected = await self._check_reflection(finding)
            if reflected is not None:
                return reflected

        # 3. heuristic: trust the scanner's own match as LIKELY, scaled by severity
        sev = (finding.severity or "info").lower()
        conf = {"critical": 0.7, "high": 0.65, "medium": 0.6, "low": 0.5, "info": 0.4}.get(sev, 0.5)
        return ValidationResult.likely(
            method=f"scanner-match ({tool})",
            confidence=conf,
            detail="Reported by the scanner; not independently re-checked. Manual review advised.",
            poc=finding.evidence or "",
        )

    async def _check_exposed_resource(self, finding: Finding) -> Optional[ValidationResult]:
        url = finding.target
        if not url or "://" not in url:
            return None
        path = urlparse(url).path.lower()
        match = next(((p, sig) for (p, sig) in _EXPOSED_SIGNATURES if p.lower().lstrip("/") in path), None)
        if match is None:
            return None
        p, signature = match
        try:
            resp = await self.safe.fetch(url, method="GET")
        except ScopeError as exc:
            return ValidationResult.unconfirmed("safe-poc", detail=str(exc))
        if resp is None:
            return ValidationResult.unconfirmed("safe-poc", detail="resource not reachable")
        if resp.status_code != 200:
            return ValidationResult.false_positive(
                "safe-poc", detail=f"resource returned HTTP {resp.status_code}, not exposed"
            )
        if not _signature_present(signature, resp.text):
            return ValidationResult.false_positive(
                "safe-poc", detail="200 but expected content signature absent"
            )
        snippet = resp.text[:300].replace("\n", " ")
        return ValidationResult.confirmed(
            method="safe-poc (exposed-resource)",
            poc=f"GET {url} -> HTTP 200; body matches the expected {p} signature\n{snippet}",
            detail=f"Sensitive resource {p} is publicly readable.",
        )

    async def _check_reflection(self, finding: Finding) -> Optional[ValidationResult]:
        url = finding.target
        if not url or "://" not in url or "?" not in url:
            return None
        marker = "syphax" + secrets.token_hex(4)
        variants = marker_variants(url, marker)
        if not variants:
            return None

        reached = False
        for param, injected in variants:
            try:
                resp = await self.safe.fetch(injected, method="GET")
            except ScopeError as exc:
                return ValidationResult.unconfirmed("safe-poc", detail=str(exc))
            if resp is None:
                continue
            reached = True
            # The marker is benign: we check reflection only, we never inject a
            # script. An encoded reflection is not exploitable as-is.
            if marker in resp.text:
                return ValidationResult.confirmed(
                    method="safe-poc (reflection)",
                    poc=f"GET {injected} -> benign marker '{marker}' reflected "
                        f"unencoded via parameter '{param}'",
                    confidence=0.9,
                    detail="Parameter reflects input unencoded; XSS is plausible. "
                           "Manual confirmation with a script payload recommended.",
                )

        if not reached:
            return ValidationResult.unconfirmed("safe-poc", detail="endpoint not reachable")
        # Every parameter was probed and none reflected, so calling it a false
        # positive is defensible - which it was not when only one was tried.
        return ValidationResult.false_positive(
            "safe-poc (reflection)",
            detail=f"benign marker not reflected in any of {len(variants)} parameter(s)",
        )


def _signature_present(signature, body: str) -> bool:
    """Signature may be a substring or a compiled pattern; empty means any body."""
    if not signature:
        return bool(body)
    if hasattr(signature, "search"):
        return bool(signature.search(body or ""))
    return signature.lower() in (body or "").lower()


MAX_REFLECTION_PARAMS = 8


def marker_variants(url: str, marker: str, *, limit: int = MAX_REFLECTION_PARAMS):
    """One URL per query parameter, each with that parameter set to the marker.

    Probing only the first parameter meant a real reflection in the second was
    never seen - and the caller then recorded a FALSE POSITIVE, deleting a true
    finding from the report. Returns [(param, url), ...].
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return []
    out = []
    for key in list(qs)[:limit]:
        probe = {k: v[-1] for k, v in qs.items()}
        probe[key] = marker
        out.append((key, urlunparse(parsed._replace(query=urlencode(probe)))))
    return out


def _inject_marker(url: str, marker: str) -> Optional[str]:
    """Back-compat single-variant helper (first parameter)."""
    variants = marker_variants(url, marker, limit=1)
    return variants[0][1] if variants else None
