"""nuclei findings must be classified from their template tags, not lumped
under 'multiple'."""
import pytest

from app.scans.wrappers.nuclei import _classify


@pytest.mark.parametrize("tags,expected", [
    ("ssrf,oast", "ssrf"),
    ("xss,dom", "xss"),
    ("sqli", "sql_injection"),
    ("ssti", "ssti"),
    ("xxe", "xxe"),
    (["lfi", "file"], "lfi"),
    ("traversal", "lfi"),
    ("cve,redirect", "open_redirect"),
    ("cors", "cors"),
    ("crlf", "crlf_injection"),
    ("takeover", "subdomain_takeover"),
    ("config,exposure", "exposed_resource"),
    ("default-login", "auth"),
    (["tls", "ssl"], "weak_tls"),
    ("wordpress", "cms_vulnerability"),
    # RCE family: distinct from pure OS command injection.
    ("rce,oast", "rce"),
    ("log4j", "rce"),
    (["spring", "cve"], "rce"),
    ("struts", "rce"),
    ("fileupload", "rce"),
    ("deserialization", "deserialization"),
    ("cmdi", "command_injection"),
    ("command-injection", "command_injection"),
])
def test_classify_tags(tags, expected):
    assert _classify(tags, "") == expected


def test_unmatched_falls_back_to_multiple():
    assert _classify("tech,misc,info", "generic-template") == "multiple"
    assert _classify(None, "") == "multiple"


def test_template_id_substring_matches():
    # When tags are unhelpful, the template id is a fallback signal.
    assert _classify("cve", "CVE-2023-0001-ssrf-in-proxy") == "ssrf"
