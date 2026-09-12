"""sqlmap: the reference SQL injection tool.

We run it in batch mode against a single URL. sqlmap writes structured output
to an `--output-dir`; we read `log` (human readable summary) and the target
session file to extract confirmed findings.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

# One DOTALL pattern spanning Parameter->Payload used to run straight past the
# end of a truncated block and pair a parameter with the NEXT block's payload -
# and since sqlmap findings are auto-trusted as confirmed, that shipped a
# critical whose PoC did not reproduce. Split on the parameter headers first and
# parse each block in isolation instead.
_PARAM_HEADER = re.compile(r"^\s*Parameter:\s*(?P<param>\S+)(?P<rest>.*)$", re.M)
_FIELD = {
    "type": re.compile(r"^\s*Type:\s*(?P<v>.+)$", re.M),
    "title": re.compile(r"^\s*Title:\s*(?P<v>.+)$", re.M),
    "payload": re.compile(r"^\s*Payload:\s*(?P<v>.+)$", re.M),
}


def parse_injection_blocks(text: str) -> List[dict]:
    """sqlmap's "Parameter: / Type: / Title: / Payload:" blocks.

    A block without a Payload line is incomplete (tool killed, output truncated)
    and is skipped rather than completed from its neighbour.
    """
    heads = list(_PARAM_HEADER.finditer(text or ""))
    out: List[dict] = []
    for i, head in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        block = text[head.end():end]
        fields = {}
        for name, pat in _FIELD.items():
            m = pat.search(block)
            if m:
                fields[name] = m.group("v").strip()
        if "payload" not in fields:
            continue                      # incomplete block: do not guess
        out.append({
            "parameter": head.group("param").strip(),
            "injection_type": fields.get("type", "unknown"),
            "technique_title": fields.get("title", ""),
            "payload": fields["payload"],
        })
    return out


class SqlmapWrapper(BaseWrapper):
    name = "sqlmap"
    binary = "sqlmap"
    description = "Automatic SQL injection and database takeover tool."
    category = "injection"
    timeout_seconds = 45 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "-u", target,
            "--batch",          # no interactive prompts
            "--random-agent",
            "--level=2",
            "--risk=2",
            "--disable-coloring",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = stdout.decode("utf-8", errors="replace")
        findings: List[Finding] = []

        for block in parse_injection_blocks(text):
            param = block["parameter"]
            injection_type = block["injection_type"]
            title = block["technique_title"]
            payload = block["payload"]

            findings.append(
                Finding(
                    severity="high",
                    title=f"SQL injection in parameter '{param}'",
                    description=(
                        f"{injection_type} injection: {title}. "
                        "Confirmed by sqlmap."
                    ),
                    target=target,
                    evidence=f"Payload: {payload}",
                    metadata={
                        "parameter": param,
                        "injection_type": injection_type,
                        "technique_title": title,
                    },
                )
            )

        # If sqlmap concluded there was no injection and we still returned 0, leave it at 0.
        return ToolResult(findings=findings)
