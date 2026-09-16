"""The 23 wrapped tools, and the pins that install them.

A wrapper is four things that have to agree: a module, an entry in the
registry, a binary in the image, and a vulnerability class in the taxonomy.
Nothing fails loudly when they drift. A wrapper whose binary was never added to
the Dockerfile reports "unavailable" in the UI - which is indistinguishable
from a tool the operator chose not to install - and a wrapper missing from the
taxonomy has its findings silently classified as surface noise.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from app.scans.wrappers import _WRAPPERS, available_wrappers
from app.validation.classes import TOOL_VULN_CLASS

BACKEND = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILE = (BACKEND / "Dockerfile").read_text()
WRAPPER_DIR = BACKEND / "app" / "scans" / "wrappers"

REQUIREMENTS = sorted(BACKEND.glob("requirements*.txt"))

# naabu publishes no linux/arm64 asset at any version, so the Dockerfile
# installs it conditionally and carries on. nmap covers port scanning.
OPTIONAL_BINARIES = {"naabu"}


def wrapper_modules():
    return {p.stem for p in WRAPPER_DIR.glob("*.py")} - {"__init__", "base"}


# ---- the four things that have to agree -------------------------------------

def test_every_wrapper_module_is_registered():
    """A module nobody registered is a tool that exists and can never run."""
    assert wrapper_modules() == set(_WRAPPERS), (
        f"unregistered: {sorted(wrapper_modules() - set(_WRAPPERS))}; "
        f"registered with no module: {sorted(set(_WRAPPERS) - wrapper_modules())}")


@pytest.mark.parametrize("name", sorted(_WRAPPERS))
def test_every_registered_tool_is_installed_in_the_image(name):
    binary = _WRAPPERS[name].binary
    assert binary, f"{name} declares no binary"
    assert binary in DOCKERFILE, (
        f"{name} runs `{binary}`, which the image never installs. It will "
        f"report 'unavailable' forever, and that looks like a choice.")


@pytest.mark.parametrize("name", sorted(_WRAPPERS))
def test_every_registered_tool_has_a_vulnerability_class(name):
    """Without an entry the finding is classified as surface noise, which is
    the quietest way for a real finding to disappear."""
    assert name in TOOL_VULN_CLASS


def test_the_taxonomy_has_no_entry_for_a_tool_that_no_longer_exists():
    assert set(TOOL_VULN_CLASS) - set(_WRAPPERS) == set()


def test_every_wrapper_describes_itself_for_the_ui():
    for tool in available_wrappers():
        assert tool["name"], tool
        assert tool["description"], f"{tool['name']} has no description"
        assert tool["category"], f"{tool['name']} has no category"


def test_only_the_tool_with_no_arm64_release_is_optional():
    """Kept explicit so the next optional install is a decision, not a habit.

    naabu is conditional because it publishes no linux/arm64 asset at any
    version - the nightly found that, and the alternative was a Dockerfile that
    could not build on Apple Silicon at all.
    """
    conditional = set(re.findall(r"if curl -fsSL -o (\w+)\.zip", DOCKERFILE))
    assert conditional <= OPTIONAL_BINARIES, (
        f"newly optional and undocumented: {sorted(conditional - OPTIONAL_BINARIES)}")


# ---- the pins ---------------------------------------------------------------

def requirement_lines(path):
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            yield line


@pytest.mark.parametrize("path", REQUIREMENTS, ids=lambda p: p.name)
def test_every_python_dependency_is_pinned_exactly(path):
    """`>=` in a requirements file means the image you build today and the one
    you build in three months are different images. For a tool that has to be
    reproducible across an engagement, that is a defect."""
    for line in requirement_lines(path):
        assert "==" in line, f"{path.name}: {line!r} is not pinned"
        assert not any(op in line.replace("==", "") for op in (">=", "<=", ">", "<", "~=")), \
            f"{path.name}: {line!r} mixes a pin with a range"


@pytest.mark.parametrize("path", REQUIREMENTS, ids=lambda p: p.name)
def test_no_dependency_is_declared_twice_in_one_file(path):
    names = [re.split(r"[=<>\[]", line, maxsplit=1)[0].strip().lower()
             for line in requirement_lines(path)]
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"{path.name} pins these twice: {dupes}"


def test_the_test_requirements_agree_with_production():
    """A package pinned to one version in production and another in CI means
    the tests never exercised what ships."""
    def pins(path):
        out = {}
        for line in requirement_lines(path):
            name, _, version = line.partition("==")
            out[re.split(r"\[", name, maxsplit=1)[0].strip().lower()] = version.strip()
        return out

    prod = pins(BACKEND / "requirements.txt")
    test = pins(BACKEND / "requirements-test.txt")
    conflicts = {n: (prod[n], test[n]) for n in prod.keys() & test.keys()
                 if prod[n] != test[n]}
    assert not conflicts, f"pinned differently in production and CI: {conflicts}"


def test_the_pinned_tool_versions_are_all_build_arguments():
    """A version buried in a RUN line is a version nobody updates, and one that
    scripts/check_download_urls.py cannot pre-flight."""
    versioned = re.findall(r"^ARG (\w+_VERSION)=", DOCKERFILE, re.MULTILINE)
    assert len(versioned) >= 10, f"only {len(versioned)} tool versions are ARGs"
    # Every ARG is actually used, or it is a version pin that pins nothing.
    for arg in versioned:
        assert DOCKERFILE.count(arg) >= 2, f"{arg} is declared and never used"
