"""Shared interface for CLI tool wrappers.

Each wrapper knows how to:
  1. build a command from (target, options),
  2. declare if its binary is installed,
  3. parse its own output into a list of normalized `Finding`s.

The actual subprocess execution happens in `app.scans.runner` so the wrappers
stay pure and unit-testable (no asyncio, no DB).
"""
from __future__ import annotations

import json

import shutil
from dataclasses import dataclass
from typing import List, Sequence

from app.scans.models import Finding


@dataclass
class ToolResult:
    """Return type of `parse`."""
    findings: List[Finding]


class BaseWrapper:
    name: str = ""
    binary: str = ""
    description: str = ""
    # Coarse grouping for the UI and the methodology engine. One of:
    # recon | fingerprint | content_discovery | vuln | injection | xss |
    # tls | cms | waf
    category: str = "vuln"

    # Hard cap on runtime (seconds). Subclasses can override.
    timeout_seconds: int = 30 * 60

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        """Return the argv to run. Must include the binary as argv[0]."""
        raise NotImplementedError

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        raise NotImplementedError

def iter_json_lines(stdout: bytes):
    """Yield each JSONL record from a tool's stdout as a dict.

    Everything that is not a usable record is skipped rather than raising, one
    line at a time, so a single corrupt line costs one record and not the whole
    scan. Three real failure modes this centralises:

      * bytes handed straight to json.loads: it sniffs the encoding, and binary
        output made it guess UTF-16 and raise UnicodeDecodeError;
      * a top-level list/string/number, whose .get() raised AttributeError;
      * blank lines and progress noise.
    """
    text = (stdout or b"").decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            yield obj
