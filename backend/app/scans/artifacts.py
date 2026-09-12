"""Per-host artifact directories: the files tools hand to each other.

Three of the bundled tools do not speak HTTP - they read files off disk:

    git-dumper   WRITES a recovered working tree
    trufflehog   READS it, and verifies each secret against its provider
    retire.js    READS the target's JavaScript and rates the client libraries
    jsluice      READS the same JavaScript with a real JS parser

So syphax needs one agreed place per host for those files. Layout:

    {data_dir}/artifacts/{host-slug}/git/    recovered source (git-dumper)
    {data_dir}/artifacts/{host-slug}/js/     client JavaScript (proxy capture)

The slug is derived from the target, so a wrapper can find the directory from
nothing but the target string it is given - no engagement id has to be
threaded through the tool layer.

Nothing here reaches the network. `listdir` returns [] for a directory that
does not exist, which is how a tool whose input was never produced degrades to
zero findings instead of an error.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from app.config import settings

GIT = "git"
JS = "js"

# Filenames we will write. Anything outside this is rejected rather than
# sanitised: a URL-derived name is attacker-influenced input, and a path that
# escapes the artifact directory is not worth being clever about.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")

MAX_FILES_PER_COMMAND = 200


def host_of(target: str) -> str:
    """The host a target refers to, whether it is a URL or a bare hostname."""
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        return (urlparse(raw).hostname or "").lower()
    return raw.split("/")[0].split(":")[0].lower()


def host_slug(target: str) -> str:
    """A filesystem-safe directory name for a target's host."""
    host = host_of(target)
    if not host:
        return ""
    slug = _UNSAFE_CHARS.sub("-", host).strip("-.")[:80]
    return slug or "host"


def artifact_dir(target: str, kind: str) -> Optional[Path]:
    """Where `kind` artifacts for this target live. None for a junk target."""
    slug = host_slug(target)
    if not slug or kind not in (GIT, JS):
        return None
    return settings.data_dir / "artifacts" / slug / kind


def git_dir(target: str) -> Optional[Path]:
    return artifact_dir(target, GIT)


def js_dir(target: str) -> Optional[Path]:
    return artifact_dir(target, JS)


def ensure(path: Optional[Path]) -> Optional[Path]:
    """Create the directory. None (rather than raising) when we cannot."""
    if path is None:
        return None
    try:
        path.mkdir(parents=True, exist_ok=True)
        return path
    except OSError:
        return None


def safe_filename(url: str, *, suffix: str = ".js") -> str:
    """A stable, collision-resistant filename for a fetched resource.

    The last path segment is kept when it is already safe, because a human
    reading a retire.js report needs to recognise `jquery-1.7.2.min.js`. A
    short hash of the full URL is always appended so two bundles with the same
    basename on different paths cannot overwrite each other.
    """
    digest = hashlib.sha256((url or "").encode()).hexdigest()[:10]
    base = (urlparse(url or "").path or "").rstrip("/").split("/")[-1]
    base = _UNSAFE_CHARS.sub("-", base).strip("-.")[:60]
    if not base or not _SAFE_NAME.match(base):
        base = "resource"
    if not base.endswith(suffix):
        base = f"{base}{suffix}"
    stem, dot, ext = base.rpartition(".")
    return f"{stem}-{digest}{dot}{ext}" if dot else f"{base}-{digest}"


def write_artifact(directory: Optional[Path], name: str, text: str) -> Optional[Path]:
    """Write one artifact. Refuses a name that is not plainly safe."""
    if directory is None or not _SAFE_NAME.match(name or ""):
        return None
    target = ensure(directory)
    if target is None:
        return None
    path = target / name
    try:
        path.write_text(text or "", encoding="utf-8", errors="replace")
        return path
    except OSError:
        return None


def listdir(path: Optional[Path], *, suffixes: tuple = (),
            limit: int = MAX_FILES_PER_COMMAND) -> List[Path]:
    """Files in an artifact directory, sorted. [] when it does not exist.

    A tool whose input was never produced then builds a command with no file
    arguments, reports zero findings, and does not fail the run.
    """
    if path is None:
        return []
    try:
        entries = sorted(p for p in path.rglob("*") if p.is_file())
    except OSError:
        return []
    if suffixes:
        entries = [p for p in entries if p.suffix.lower() in suffixes]
    return entries[:limit]


def count_files(path: Optional[Path]) -> int:
    return len(listdir(path, limit=10 ** 6))
