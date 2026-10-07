"""HTTP security posture: cookies, CSP, clickjacking, transport, disclosure.

The OWASP Session Management and Client-side families had no check at all:
a session cookie without HttpOnly, a CSP that allows 'unsafe-inline', a page
that can be framed. These pin the detection logic (pure, no DB, no network).
"""
from app.analysis.http_posture import (_host_findings, csp_weaknesses,
                                       is_session_cookie, parse_cookie)


def _data(headers, cookies=(), https=True):
    return {"headers": headers, "url": "https://t.example/",
            "https": https, "cookies": list(cookies)}


def _classes(findings):
    return [f.metadata["vuln_class"] for f in findings]


def test_parse_cookie_flags():
    c = parse_cookie("SESSIONID=abc; Path=/; HttpOnly; Secure; SameSite=Lax")
    assert c == {"name": "SESSIONID", "value": "abc", "deleted": False,
                 "secure": True, "httponly": True, "samesite": "lax"}


def test_session_cookie_detection():
    assert is_session_cookie("PHPSESSID") and is_session_cookie("auth_token")
    assert not is_session_cookie("theme")


def test_session_cookie_without_httponly_is_flagged():
    f = _host_findings("t.example", _data([], ["SESSIONID=a; Secure; SameSite=Lax"]))
    cookie = [x for x in f if x.metadata["vuln_class"] == "cookie_security"]
    assert len(cookie) == 1
    assert "HttpOnly" in cookie[0].description
    assert cookie[0].severity == "medium"       # it is a session cookie


def test_hardened_cookie_is_not_flagged():
    f = _host_findings("t.example", _data([], ["SESSIONID=a; Secure; HttpOnly; SameSite=Lax"]))
    assert not [x for x in f if x.metadata["vuln_class"] == "cookie_security"]


def test_samesite_none_without_secure():
    f = _host_findings("t.example", _data([], ["tok=1; HttpOnly; SameSite=None"]))
    desc = " ".join(x.description for x in f if x.metadata["vuln_class"] == "cookie_security")
    assert "SameSite=None without Secure" in desc


def test_missing_csp_and_clickjacking():
    f = _host_findings("t.example", _data([["Server", "nginx"]]))
    assert "security_headers" in _classes(f)
    assert "clickjacking" in _classes(f)


def test_frame_ancestors_covers_clickjacking():
    headers = [["Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"],
               ["Strict-Transport-Security", "max-age=31536000"],
               ["X-Content-Type-Options", "nosniff"],
               ["Referrer-Policy", "no-referrer"]]
    f = _host_findings("t.example", _data(headers))
    assert "clickjacking" not in _classes(f)


def test_unsafe_inline_csp_is_weak():
    assert any("unsafe-inline" in w for w in
               csp_weaknesses("script-src 'self' 'unsafe-inline'"))


def test_short_hsts_is_low():
    headers = [["Strict-Transport-Security", "max-age=300"]]
    f = _host_findings("t.example", _data(headers))
    hsts = [x for x in f if "HSTS max-age" in x.title]
    assert hsts and hsts[0].severity == "low"


def test_version_disclosure():
    f = _host_findings("t.example", _data([["Server", "nginx/1.12.0"]]))
    disc = [x for x in f if x.metadata["vuln_class"] == "information_disclosure"]
    assert disc and "nginx/1.12.0" in disc[0].evidence


def test_bare_product_name_is_not_disclosure():
    f = _host_findings("t.example", _data([["Server", "nginx"]]))
    assert not [x for x in f if x.metadata["vuln_class"] == "information_disclosure"]


def test_http_only_site_is_not_asked_for_hsts():
    f = _host_findings("t.example", _data([], https=False))
    assert not [x for x in f if "HSTS" in x.title]
