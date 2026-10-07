"""DOM XSS sinks and postMessage handlers in shipped JavaScript.

The detector is deliberately strict about data flow. An earlier version only
required a source within 200 characters of a sink, which on a MINIFIED bundle
(one long line, everything adjacent) paired an unused `location.href` with an
unrelated `innerHTML = TEMPLATE`, and flagged React code that escapes properly.
Production SPA bundles are always minified, so that version would have buried
every real finding under noise. Proximity is not data flow.
"""
import pytest

from app.analysis.dom_sinks import (find_sink_hits, listener_without_origin_check,
                                    wildcard_post_message)


def _sinks(code):
    return [h["sink"] for h in find_sink_hits(code)]


@pytest.mark.parametrize("code,sink", [
    ("el.innerHTML = location.hash.slice(1);", "innerHTML"),
    ("document.write(location.search)", "document.write"),
    ("eval(document.referrer)", "eval"),
    ("node.insertAdjacentHTML('beforeend', location.href)", "insertAdjacentHTML"),
    ("$('#x').html(window.name)", "jQuery .html()"),
])
def test_source_inside_the_sink_expression_is_reported(code, sink):
    assert sink in _sinks(code)


def test_readable_alias_is_followed_one_hop():
    hits = find_sink_hits("const userInput = location.hash; el.innerHTML = userInput;")
    assert hits and hits[0]["via"] == "variable"


# ---- false positives that the proximity version produced --------------------

def test_minified_bundle_does_not_pair_unrelated_code():
    """One long line: an unused location.href next to a safe innerHTML."""
    code = ('var t=location.href,n=e.length;function o(e){'
            'var t=document.createElement("div");t.innerHTML=SAFE_TEMPLATE;return t}')
    assert _sinks(code) == []


def test_escaped_react_output_is_not_flagged():
    code = ('const u=new URL(location.href);'
            'fetch("/api").then(d=>{root.innerHTML=escapeHtml(d.name)})')
    assert _sinks(code) == []


def test_single_letter_minified_alias_is_not_followed():
    """Minifiers rename everything to one or two letters; matching those would
    pair unrelated statements on every line. Accepted false negative."""
    assert _sinks("var t=location.hash;el.innerHTML=t;") == []


@pytest.mark.parametrize("code", [
    "el.innerHTML = sanitize(staticTemplate);",   # sink, no source
    "var h = location.hash;",                      # source, no sink
    "const x = 1 + 2;",
])
def test_no_source_or_no_sink(code):
    assert _sinks(code) == []


# ---- postMessage -----------------------------------------------------------

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
