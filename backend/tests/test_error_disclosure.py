"""Verbose-error detection (OWASP Error Handling, previously untested)."""
import pytest

from app.analysis.error_disclosure import _SIGNATURES, _around, _text


def _match(body: str):
    return [(kind, sev, label) for kind, sev, label, pat in _SIGNATURES
            if pat.search(body)]


@pytest.mark.parametrize("body,kind,sev", [
    ("You have an error in your SQL syntax; check the manual", "sql_error", "high"),
    ("SQLSTATE[42000]: Syntax error", "sql_error", "high"),
    ("ORA-00933: SQL command not properly ended", "sql_error", "high"),
    ('Traceback (most recent call last):\n  File "/app/x.py", line 3', "stack_trace", "medium"),
    ("at com.acme.Foo.bar(Foo.java:120)", "stack_trace", "medium"),
    ("System.NullReferenceException: Object reference not set", "stack_trace", "medium"),
    ("<b>Warning</b>: include() failed on line <b>42</b>", "stack_trace", "medium"),
    ("Werkzeug Debugger", "debug_page", "medium"),
    ("open /var/www/html/config.php failed", "path_disclosure", "low"),
])
def test_signatures_match(body, kind, sev):
    hits = _match(body)
    assert any(k == kind and s == sev for k, s, _ in hits), hits


@pytest.mark.parametrize("body", [
    "<html><body>Welcome</body></html>",
    '{"status":"ok","items":[]}',
    "",
    "body { color: #fff; }",
])
def test_clean_responses_are_not_flagged(body):
    assert _match(body) == []


def test_text_handles_bytes_and_memoryview():
    assert _text(b"hello") == "hello"
    assert _text(memoryview(b"hello")) == "hello"
    assert _text(None) == ""


def test_snippet_is_bounded():
    body = "x" * 1000 + "Traceback (most recent call last)" + "y" * 1000
    out = _around(body, 1000)
    assert 0 < len(out) <= 300
