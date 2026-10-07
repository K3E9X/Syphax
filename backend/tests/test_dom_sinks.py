"""DOM XSS sinks and postMessage handlers in shipped JavaScript."""
import pytest

from app.analysis.dom_sinks import (find_sink_hits, listener_without_origin_check,
                                    wildcard_post_message)


@pytest.mark.parametrize("code,sink", [
    ("var h = location.hash.slice(1); el.innerHTML = h;", "innerHTML"),
    ("document.write(location.search)", "document.write"),
    ("eval(document.referrer)", "eval"),
    ("node.insertAdjacentHTML('beforeend', location.href)", "insertAdjacentHTML"),
    ("$('#x').html(window.name)", "jQuery .html()"),
])
def test_sink_with_url_source_is_reported(code, sink):
    assert sink in [h["sink"] for h in find_sink_hits(code)]


@pytest.mark.parametrize("code", [
    "el.innerHTML = sanitize(staticTemplate);",      # sink, no source
    "var h = location.hash;",                         # source, no sink
    "const x = 1 + 2;",
])
def test_no_source_or_no_sink_is_not_reported(code):
    assert find_sink_hits(code) == []


def test_distant_source_and_sink_are_not_paired():
    code = "var h = location.hash;" + ("\n// filler" * 80) + "el.innerHTML = safe;"
    assert find_sink_hits(code) == []


def test_message_listener_without_origin_check():
    assert listener_without_origin_check(
        'window.addEventListener("message", function(e){ run(e.data); })')


def test_message_listener_checking_origin_is_clean():
    assert listener_without_origin_check(
        'window.addEventListener("message", function(e){'
        ' if (e.origin !== "https://x") return; run(e.data); })') is None


def test_no_listener_at_all():
    assert listener_without_origin_check("const a = 1;") is None


def test_wildcard_post_message():
    assert wildcard_post_message('w.postMessage(payload, "*")')
    assert wildcard_post_message('w.postMessage(payload, "https://x")') is None
