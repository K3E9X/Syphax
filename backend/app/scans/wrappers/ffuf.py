"""ffuf: URL fuzzer. We run it against `{target}/FUZZ` with a bundled wordlist
and parse the JSON report printed on stdout (`-of json -o -`).
"""
from __future__ import annotations

import json
import os
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

DEFAULT_WORDLIST = os.environ.get(
    "FFUF_WORDLIST",
    "/opt/wordlists/common.txt",
)


class FfufWrapper(BaseWrapper):
    name = "ffuf"
    binary = "ffuf"
    description = "Fast web fuzzer for directories, parameters and vhosts."
    category = "content_discovery"
    timeout_seconds = 20 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        # If the caller did not embed FUZZ in the target, assume directory fuzzing.
        url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
        cmd = [
            self.binary,
            "-u", url,
            "-w", DEFAULT_WORDLIST,
            "-of", "json",
            "-o", "-",
            "-s",          # silent progress
            "-mc", "200,204,301,302,307,401,403,405",
            "-t", "40",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        try:
            data = json.loads(stdout.decode("utf-8", errors="replace") or "{}")
        except json.JSONDecodeError:
            return ToolResult(findings=[])

        if not isinstance(data, dict):
            return ToolResult(findings=[])   # ffuf emits an object; anything else is noise
        results = data.get("results") or []
        findings: List[Finding] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            url = item.get("url") or target
            status = item.get("status")
            length = item.get("length")
            words = item.get("words")
            input_value = (item.get("input") or {}).get("FUZZ", "")

            findings.append(
                Finding(
                    severity="info",
                    title=f"Discovered path: {input_value or url}",
                    description=f"HTTP {status}, {length} bytes, {words} words.",
                    target=url,
                    evidence=f"status={status} length={length} words={words}",
                    metadata={
                        "status": status,
                        "length": length,
                        "words": words,
                        "input": input_value,
                    },
                )
            )
        return ToolResult(findings=findings)
