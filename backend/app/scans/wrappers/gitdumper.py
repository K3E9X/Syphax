"""git-dumper: recover the source from an exposed .git directory.

syphax already DETECTS an exposed `.git` - nuclei and nikto both report it, and
the validator confirms `/.git/config` returns a `[core]` block. What it could
not do is act on it, so the finding stayed "a .git directory is readable,
medium": a statement about a path, with no idea what is in it.

git-dumper walks the exposed objects and rebuilds the working tree. That turns
the finding into the thing that actually matters - the source - and it gives
trufflehog a directory to verify secrets in, which is where "probably exposed"
becomes "this deploy key is live".

The dump goes to the host's artifact directory (see app/scans/artifacts.py) so
trufflehog can find it from nothing but the target string.

Read-only: git-dumper issues GETs against the exposed directory and writes
only inside our own data directory.
"""
from __future__ import annotations

from typing import List, Sequence

from app.scans.artifacts import count_files, ensure, git_dir, listdir
from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

# Files whose recovery is worth calling out by name in the finding.
NOTABLE = (
    ".env", "config.php", "wp-config.php", "settings.py", "application.yml",
    "application.properties", "database.yml", "docker-compose.yml",
    "id_rsa", "credentials", ".npmrc", ".netrc", "secrets.json",
)


def dump_url(target: str) -> str:
    """The .git URL to dump, from a target that may or may not include it."""
    raw = (target or "").strip()
    if not raw:
        return ""
    if "/.git" in raw:
        base, _, _ = raw.partition("/.git")
        return base.rstrip("/") + "/.git/"
    return raw.rstrip("/") + "/.git/"


def notable_files(paths: Sequence) -> List[str]:
    out = []
    for p in paths:
        name = getattr(p, "name", str(p)).lower()
        if any(name == n or name.endswith(n) for n in NOTABLE):
            out.append(str(p))
    return out


class GitDumperWrapper(BaseWrapper):
    name = "gitdumper"
    binary = "git-dumper"
    description = "Recover the source tree from an exposed .git directory."
    category = "vuln"
    timeout_seconds = 20 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        out = ensure(git_dir(target))
        cmd = [
            self.binary,
            dump_url(target),
            str(out) if out else "/tmp/git-dump",
            "--jobs", "8",
            "--retry", "2",
            "--timeout", "10",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        out = git_dir(target)
        files = listdir(out, limit=10 ** 6)
        if not files:
            # Nothing recovered: the .git was not actually readable, or it was
            # a catch-all answering 200 for every object. Either way there is
            # no finding here - and saying so is the point.
            return ToolResult(findings=[])

        total = count_files(out)
        secrets = notable_files(files)
        severity = "critical" if secrets else "high"
        listing = "\n".join(str(p) for p in files[:40])
        evidence = (f"Recovered {total} file(s) from {dump_url(target)} into {out}\n"
                    f"{listing}")
        if secrets:
            evidence += ("\n\nConfiguration/credential files recovered:\n"
                         + "\n".join(secrets[:20]))
        return ToolResult(findings=[Finding(
            severity=severity,
            title=f"Source code recovered from exposed .git ({total} files)",
            description=(
                "The .git directory is publicly readable and the repository was "
                "reconstructed from it. This discloses the application source, "
                "its history, and anything ever committed to it - including "
                "secrets that were later removed from the working tree but "
                "remain in the object store."
                + (" Configuration or credential files are among the recovered "
                   "files; they are verified separately by trufflehog."
                   if secrets else "")),
            target=dump_url(target),
            evidence=evidence,
            metadata={"tool": "gitdumper", "vuln_class": "source_code_disclosure",
                      "files": total, "dump_dir": str(out),
                      "notable": secrets[:20]},
        )])
