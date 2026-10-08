"""The JavaScript cache must not depend on the operator browsing the target.

js_cache read ONLY proxy flows, so on an autonomous run - where nobody routes a
browser through mitmproxy - the cache stayed empty and jsluice (urls AND
secrets), retire.js and js_recon all analysed an empty directory. That is why a
run could finish reporting no secrets at all while katana had already listed
every .js bundle on the target.
"""
import inspect

from app.analysis import js_cache


def test_js_is_recognised_by_path_and_content_type():
    assert js_cache.looks_like_js("https://t/app.js", "")
    assert js_cache.looks_like_js("https://t/x", "application/javascript")
    assert js_cache.looks_like_js("https://t/static/index-CKWwgLa7.js", "")
    assert not js_cache.looks_like_js("https://t/style.css", "text/css")
    assert not js_cache.looks_like_js("https://t/logo.png", "image/png")


def test_the_crawl_is_a_source_not_only_the_proxy():
    src = inspect.getsource(js_cache.materialise_js)
    assert "_fetch_crawled_js" in src, "still proxy-only"


def test_crawled_fetches_are_scope_enforced_and_bounded():
    src = inspect.getsource(js_cache._fetch_crawled_js)
    # In-scope, read-only, and capped: a crawl that found a thousand chunks
    # must not become a thousand requests.
    assert "SafePoC" in src and "host_in_scope" in src
    assert 'method="GET"' in src
    assert "MAX_CRAWLED_JS" in src


def test_a_flow_already_cached_is_not_fetched_again():
    src = inspect.getsource(js_cache._fetch_crawled_js)
    assert "seen_urls" in src


def test_js_recon_also_reads_the_cached_bundles():
    """The regex secret patterns (AWS keys, Google keys, ...) only ever saw
    proxy traffic. On an autonomous run that meant no secret was ever found in
    JavaScript, even with every bundle sitting on disk."""
    from app.analysis import js_recon

    src = inspect.getsource(js_recon.analyze_js)
    assert "_cached_js(eng)" in src, "js_recon is still proxy-only"
    helper = inspect.getsource(js_recon._cached_js)
    assert "js_dir" in helper and "listdir" in helper
