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


@dataclass
class Readiness:
    """Whether a tool can actually find anything, and why not."""
    tool: str
    installed: bool
    ready: bool
    reason: str

    def to_dict(self) -> dict:
        return {"tool": self.tool, "installed": self.installed,
                "ready": self.ready, "reason": self.reason}


def _missing_data(path: str) -> str:
    """"" when the data is usable, else why it is not."""
    import os

    try:
        if not os.path.exists(path):
            return "missing"
        if os.path.isdir(path):
            # An empty directory is the nuclei-templates failure mode.
            for _root, _dirs, files in os.walk(path):
                if files:
                    return ""
            return "empty"
        return "" if os.path.getsize(path) > 0 else "empty"
    except OSError as exc:  # noqa: BLE001 - unreadable counts as unusable
        return f"unreadable ({exc.__class__.__name__})"


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

    # Data files the tool cannot work without: templates, wordlists, a route
    # database. Declared per wrapper as (path, what it is). A missing one is
    # NOT an absent tool - the binary runs, scans nothing and exits 0, which
    # the pipeline records as "scanned, found nothing".
    required_data: Sequence = ()

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def readiness(self) -> "Readiness":
        """Is this tool actually able to find anything?

        `is_available` only answers "is the binary on PATH", and for several
        tools that is not the same question at all:

          * nuclei with an empty templates directory scans for nothing. It
            exits 0 and prints nothing, so a target full of known CVEs comes
            back clean. The image runs `nuclei -update-templates || true` at
            build time, so a rate-limited or offline build produces exactly
            this - and the build succeeds.
          * ffuf without its wordlist fuzzes an empty list.
          * kiterunner without its .kite route file replays no routes.

        Every one of those looks identical to a clean target from the outside.
        This is what the preflight reports so it cannot be invisible.
        """
        if not self.is_available():
            return Readiness(self.name, False, False,
                             f"{self.binary} is not installed in this image")
        for path, what in self.required_data:
            missing = _missing_data(path)
            if missing:
                return Readiness(
                    self.name, True, False,
                    f"{what} is {missing} ({path}), so {self.binary} would run "
                    f"and find nothing")
        return Readiness(self.name, True, True, "")

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
