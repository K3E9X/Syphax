"""nosqli: NoSQL injection scanner (MongoDB-style operator injection).

sqlmap covers classic SQL; it does not test NoSQL operator injection
(`param[$ne]=`, `param[$gt]=`, `[$regex]`, auth-bypass via `$ne`). nosqli does,
against a URL with parameters. We run it per parameterised endpoint and parse
its block output for a confirmed injection.

The tool prints human-readable blocks, not JSON. parse() matches on the stable
marker it prints on a hit ("NoSQL injection" / "Vulnerable") and is defensive:
unexpected text costs one result, never the scan.
"""
from __future__ import annotations

import re
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


class NoSqliWrapper(BaseWrapper):
    name = "nosqli"
    binary = "nosqli"
    description = "NoSQL (MongoDB operator) injection scanner for parameterised URLs."
    category = "injection"
    timeout_seconds = 10 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [self.binary, "scan", "-t", target]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = (stdout or b"").decode("utf-8", errors="replace")
        upper = text.upper()
        hit = ("NOSQL INJECTION" in upper) or ("VULNERABLE" in upper and "INJECT" in upper)
        if not hit:
            return ToolResult(findings=[])

        # Horizontal whitespace only around the colon: a bare \s* would let the
        # value run onto the next line (\s matches \n) and capture the wrong field.
        param = _field(text, r"Param(?:eter)?[ \t]*:[ \t]*(\S+)")
        itype = _field(text, r"Type[ \t]*:[ \t]*([^\n\r]+)")
        inj = _field(text, r"Inject(?:ion)?[ \t]*:[ \t]*([^\n\r]+)")
        url = _field(text, r"(?:Target|URL)[ \t]*:[ \t]*(\S+)") or target

        desc = "nosqli confirmed a NoSQL operator injection"
        if param:
            desc += f" on parameter '{param}'"
        if itype:
            desc += f" ({itype})"
        return ToolResult(findings=[Finding(
            severity="high",
            title=f"NoSQL injection: {url}",
            description=desc + ".",
            target=url,
            evidence=(inj or text.strip())[:800],
            metadata={
                "vuln_class": "nosql_injection",
                "parameter": param,
                "injection_type": itype,
                "payload": inj,
                "tool": "nosqli",
            },
        )])


def _field(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else ""
