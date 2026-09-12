"""The Dockerfile's pinned downloads, checked without touching the network.

The multi-arch build is the only place these URLs are exercised, it takes ~20
minutes under QEMU, and it fails at whichever step 404s - so a missing asset is
found late. scripts/check_download_urls.py resolves the same URLs in seconds
and runs in the nightly before the build.

These tests cover its resolution logic (pure); the reachability check itself is
what the nightly does, and is deliberately not run here.
"""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_download_urls.py"
DOCKERFILE = ROOT / "Dockerfile"

sys.path.insert(0, str(ROOT / "scripts"))
import check_download_urls as chk  # noqa: E402


@pytest.fixture(scope="module")
def text():
    return DOCKERFILE.read_text(encoding="utf-8")


def test_the_script_and_dockerfile_both_exist():
    assert SCRIPT.is_file()
    assert DOCKERFILE.is_file()


def test_every_release_url_resolves_to_a_concrete_link(text):
    """No ${VERSION} may survive: an unresolved variable means the ARG default
    was renamed and the check would silently test a nonsense URL."""
    args = chk.arg_defaults(text)
    urls = chk.URL_RE.findall(text)
    assert urls, "no release downloads found - did the Dockerfile change shape?"
    for template in urls:
        for arch in ("amd64", "arm64"):
            url = chk.expand(template, args, arch)
            assert "${" not in url, f"unresolved variable in {url}"
            assert url.startswith("https://github.com/")
            assert arch in url


def test_every_pinned_tool_is_found(text):
    urls = chk.URL_RE.findall(text)
    names = {chk.tool_name(u) for u in urls}
    for expected in ("nuclei", "ffuf", "dalfox", "subfinder", "httpx",
                     "katana", "naabu", "dnsx", "gau", "trufflehog"):
        assert expected in names, f"{expected} download no longer detected"


def test_versions_come_from_the_dockerfile_args(text):
    """The checker must not carry its own copy of the versions, or the two
    drift and it starts verifying URLs the build never uses."""
    args = chk.arg_defaults(text)
    assert args["NAABU_VERSION"]
    assert args["TRUFFLEHOG_VERSION"]
    urls = [chk.expand(u, args, "amd64") for u in chk.URL_RE.findall(text)]
    assert any(args["TRUFFLEHOG_VERSION"] in u for u in urls)


def test_naabu_is_the_documented_exception():
    """naabu links libpcap and ships no linux/arm64 asset at any version, so
    its absence must not fail the build - every other tool's must."""
    assert "naabu" in chk.OPTIONAL
    assert chk.OPTIONAL["naabu"]
    assert set(chk.OPTIONAL) == {"naabu"}, (
        "a new optional tool was added; confirm the orchestrator really does "
        "degrade without it before allowing the build to skip it")


def test_the_dockerfile_tolerates_a_missing_naabu(text):
    """The fix itself: a hard `curl -f` on naabu broke the whole arm64 image."""
    block = text[text.index("# naabu (port scanner)"):]
    block = block[:block.index("# dnsx")]
    assert "if curl -fsSL -o naabu.zip" in block
    assert "else" in block and "skipping" in block


def test_script_runs_and_reports(tmp_path):
    """Smoke: it must not crash on a Dockerfile with no downloads."""
    empty = tmp_path / "Dockerfile"
    empty.write_text("FROM scratch\n")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--dockerfile", str(empty)],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 1
    assert "no release URLs" in proc.stderr
