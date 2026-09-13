"""Which crawler output becomes a scanned asset.

katana parses JavaScript, so it emits regex literals, router templates and
fragments of code alongside real links. The gate only checked the scheme - and
a regex literal joined to the base URL has one. On Juice Shop that produced the
asset `http://target:3001/\/index\.html`, a 404 that every later phase then
tested. The run reported no findings and looked broken.
"""
import pytest

from app.orchestrator.executor import _looks_like_http_url as accepted


@pytest.mark.parametrize("url", [
    "http://t.example:3001/",
    "http://t.example/rest/products/search?q=apple",
    "https://t.example/a/b.html",
    "https://t.example/api/v2/users/1337",
    "http://t.example/x?a=1&b=2#frag",
    "http://192.168.65.254:8081/index.php",
])
def test_real_urls_are_kept(url):
    assert accepted(url)


@pytest.mark.parametrize("url", [
    r"http://t.example:3001/\/index\.html",   # the one that broke the run
    r"http://t.example/\.js",
    r"http://t.example/a\/b",
])
def test_regex_literals_from_javascript_are_refused(url):
    """A backslash is not a URL character; in a crawler's output it means the
    parser picked up a regex, not a link."""
    assert not accepted(url)


@pytest.mark.parametrize("url", [
    "http://t.example/${id}/x",
    "http://t.example/{{route}}",
    "http://t.example/a{b}c",
])
def test_unresolved_templates_are_refused(url):
    assert not accepted(url)


@pytest.mark.parametrize("url", [
    "http://t.example/a b",
    'http://t.example/a"b',
    "http://t.example/a<b>",
    "http://t.example/a|b",
    "http://t.example/a\tb",
    "http://t.example/a\nb",
])
def test_characters_rfc3986_excludes_are_refused(url):
    assert not accepted(url)


@pytest.mark.parametrize("url", [
    "", None, "not a url", "ftp://t.example/x", "file:///etc/passwd",
    "javascript:alert(1)", "http:///nohost", "//t.example/x",
])
def test_non_http_input_is_refused(url):
    assert not accepted(url)


def test_percent_encoding_still_passes():
    """A legitimately encoded path must survive: %20 is a space in the path,
    not a raw one in the URL."""
    assert accepted("http://t.example/a%20b/c%2Fd")
