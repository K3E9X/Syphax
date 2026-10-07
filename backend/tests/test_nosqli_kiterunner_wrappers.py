"""nosqli (NoSQL injection) and kiterunner (API route discovery) wrappers."""
from app.scans.wrappers.kiterunner import KiterunnerWrapper
from app.scans.wrappers.nosqli import NoSqliWrapper

NOSQLI = NoSqliWrapper()
KR = KiterunnerWrapper()

TARGET = "https://api.target.example/login?user=admin"

NOSQLI_HIT = b"""
Running NoSQL scan...
Found NoSQL injection:
  Target: https://api.target.example/login?user=admin
  Parameter: user
  Type: Boolean blind ($ne)
  Injection: user[$ne]=x
"""

NOSQLI_CLEAN = b"Running NoSQL scan...\nNo injection found.\n"


def test_nosqli_reports_injection_as_high():
    res = NOSQLI.parse(NOSQLI_HIT, b"", 0, TARGET)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "high"
    assert f.metadata["vuln_class"] == "nosql_injection"
    assert f.metadata["parameter"] == "user"
    assert "$ne" in f.metadata["payload"]


def test_nosqli_clean_output_is_empty():
    assert NOSQLI.parse(NOSQLI_CLEAN, b"", 0, TARGET).findings == []


def test_nosqli_command_shape():
    cmd = NOSQLI.build_command(TARGET, [])
    assert cmd[:3] == ["nosqli", "scan", "-t"]


# kiterunner JSONL (one matched route per line).
KR_JSON = (
    b'{"url":"https://api.target.example/api/v1/users","status":200,"method":"GET"}\n'
    b'{"url":"https://api.target.example/api/v1/admin","status":401,"method":"POST"}\n'
    b'garbage line that must be skipped\n'
)

# Older kr text output.
KR_TEXT = (
    b"200 [  1452,   40,   6] https://api.target.example/api/v2/orders\n"
    b"GET      500 ignored line without the bracket block\n"
)


def test_kiterunner_parses_jsonl_routes():
    res = KR.parse(KR_JSON, b"", 0, TARGET)
    urls = {f.metadata["method"] + " " + f.target for f in res.findings}
    assert "GET https://api.target.example/api/v1/users" in urls
    assert "POST https://api.target.example/api/v1/admin" in urls
    assert all(f.metadata["vuln_class"] == "api_route" for f in res.findings)


def test_kiterunner_falls_back_to_text():
    res = KR.parse(KR_TEXT, b"", 0, TARGET)
    assert len(res.findings) == 1
    assert res.findings[0].target == "https://api.target.example/api/v2/orders"


def test_kiterunner_command_shape():
    cmd = KR.build_command(TARGET, [])
    assert cmd[:3] == ["kr", "scan", TARGET]
    assert "-o" in cmd and "json" in cmd
