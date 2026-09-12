"""Per-host artifact directories: the files the tools hand to each other.

git-dumper writes a recovered tree, trufflehog verifies the secrets in it,
retire.js rates the client libraries and jsluice parses the JS. None of them
speak HTTP, so they need one agreed place per host - reachable from nothing
but the target string a wrapper is handed.

The filename rules are the part worth testing: a URL-derived name is
attacker-influenced input, so a path that would escape the artifact directory
must be refused rather than sanitised.
"""
import pytest

import app.scans.artifacts as artifacts
from app.scans.artifacts import (
    count_files,
    ensure,
    git_dir,
    host_of,
    host_slug,
    js_dir,
    listdir,
    safe_filename,
    write_artifact,
)


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts.settings, "data_dir", tmp_path)
    return tmp_path


# --------------------------------------------------------------------------
# addressing
# --------------------------------------------------------------------------

@pytest.mark.parametrize("target,host", [
    ("https://target.example.com/a/b?x=1", "target.example.com"),
    ("http://TARGET.example.com:8080/", "target.example.com"),
    ("target.example.com", "target.example.com"),
    ("target.example.com:8443/path", "target.example.com"),
    ("", ""),
    (None, ""),
])
def test_host_is_read_from_a_url_or_a_bare_name(target, host):
    assert host_of(target) == host


def test_the_same_host_always_maps_to_the_same_directory():
    """A wrapper is handed a target string, not an engagement id."""
    a = git_dir("https://t.example.com/a?x=1")
    b = git_dir("http://T.EXAMPLE.COM:8080/other/path")
    assert a == b


def test_git_and_js_are_separate_directories():
    assert git_dir("https://t.example.com/") != js_dir("https://t.example.com/")


def test_a_junk_target_has_no_directory():
    for bad in ("", None, "://"):
        assert git_dir(bad) is None
        assert js_dir(bad) is None


@pytest.mark.parametrize("host", ["a/../../etc", "a\\b", "a b", "a;rm -rf /"])
def test_a_hostile_host_cannot_escape_the_artifact_root(host, data_dir):
    slug = host_slug(host)
    assert "/" not in slug and "\\" not in slug and ".." not in slug
    d = git_dir(host)
    assert d is None or str(data_dir) in str(d.resolve())


# --------------------------------------------------------------------------
# filenames
# --------------------------------------------------------------------------

def test_a_recognisable_basename_survives():
    """A human reading a retire.js report needs to see jquery-1.7.2.min.js."""
    name = safe_filename("https://t.example/static/jquery-1.7.2.min.js")
    assert name.startswith("jquery-1.7.2.min-")
    assert name.endswith(".js")


def test_two_bundles_with_the_same_basename_do_not_collide():
    a = safe_filename("https://t.example/v1/app.js")
    b = safe_filename("https://t.example/v2/app.js")
    assert a != b


def test_the_same_url_always_produces_the_same_name():
    """Caching twice must rewrite, not accumulate copies."""
    url = "https://t.example/app.js"
    assert safe_filename(url) == safe_filename(url)


@pytest.mark.parametrize("url", [
    "https://t.example/../../etc/passwd",
    "https://t.example/a/%2e%2e%2f%2e%2e%2fshadow",
    "https://t.example/",
    "https://t.example/a?q=<script>",
    "",
])
def test_no_url_can_produce_a_traversing_filename(url):
    name = safe_filename(url)
    assert "/" not in name and ".." not in name and "\\" not in name


# --------------------------------------------------------------------------
# writing and listing
# --------------------------------------------------------------------------

def test_write_then_list():
    d = js_dir("https://t.example/")
    assert write_artifact(d, "app.js", "var a = 1") is not None
    files = listdir(d)
    assert [p.name for p in files] == ["app.js"]
    assert files[0].read_text() == "var a = 1"
    assert count_files(d) == 1


def test_writing_creates_the_directory():
    d = js_dir("https://t.example/")
    assert not d.exists()
    write_artifact(d, "app.js", "x")
    assert d.exists()


@pytest.mark.parametrize("name", ["../escape.js", "a/b.js", "", "a b.js",
                                  "x" * 200])
def test_an_unsafe_filename_is_refused_not_sanitised(name):
    d = js_dir("https://t.example/")
    assert write_artifact(d, name, "x") is None


def test_listing_a_directory_that_was_never_produced_is_empty():
    """This is how a tool whose input never arrived reports zero findings
    instead of failing the run."""
    assert listdir(git_dir("https://t.example/")) == []
    assert listdir(None) == []
    assert count_files(git_dir("https://t.example/")) == 0


def test_listing_filters_by_suffix_and_recurses():
    d = ensure(git_dir("https://t.example/"))
    (d / "sub").mkdir()
    (d / "app.js").write_text("x")
    (d / "sub" / "deep.js").write_text("x")
    (d / "README.md").write_text("x")
    assert len(listdir(d)) == 3
    assert [p.name for p in listdir(d, suffixes=(".js",))] == ["app.js", "deep.js"]


def test_listing_is_bounded():
    d = ensure(js_dir("https://t.example/"))
    for i in range(30):
        (d / f"f{i:03d}.js").write_text("x")
    assert len(listdir(d, limit=10)) == 10
    assert count_files(d) == 30


def test_write_to_an_unusable_directory_degrades(monkeypatch):
    monkeypatch.setattr(artifacts.settings, "data_dir",
                        artifacts.Path("/proc/definitely-not-writable"))
    assert write_artifact(js_dir("https://t.example/"), "app.js", "x") is None
    assert ensure(js_dir("https://t.example/")) is None


# --------------------------------------------------------------------------
# js_cache: which captured responses are worth handing to a JS parser
# --------------------------------------------------------------------------

from app.analysis.js_cache import looks_like_js


@pytest.mark.parametrize("url,ctype", [
    ("https://t.example/app.js", "text/html"),
    ("https://t.example/app.mjs", ""),
    ("https://t.example/bundle.js.map", ""),
    ("https://t.example/x", "application/javascript"),
    ("https://t.example/x", "text/ecmascript; charset=utf-8"),
    ("https://t.example/x", "application/sourcemap+json"),
])
def test_javascript_is_recognised_by_type_or_extension(url, ctype):
    assert looks_like_js(url, ctype)


@pytest.mark.parametrize("url,ctype", [
    ("https://t.example/", "text/html"),
    ("https://t.example/logo.png", "image/png"),
    ("https://t.example/api/users", "application/json"),
    ("", ""),
])
def test_everything_else_is_not_cached_as_javascript(url, ctype):
    assert not looks_like_js(url, ctype)
