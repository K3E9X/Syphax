"""Which probes carry the credential, and which must not.

syphax could always test as a logged-in user: scans/runner injects
`engagement.primary_auth` into every tool it launches. The analysers could
not - SafePoC and ProbeClient took `in_scope` and nothing else, so each one had
to remember to pass headers per call and NONE of the ten did. An operator who
filled in the credentials got an authenticated nuclei and an anonymous
mass-assignment, api-sequences and rate-limit pass: exactly the checks a
credential is worth having for.

The fix is not "credentials everywhere". Three probes have the ABSENCE of a
credential as their whole claim, and sending one there does not test more - it
makes the test wrong, and wrong in the direction of a false positive on every
target. That split is what these tests pin, in both directions.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest

from app.exploit.probe_client import ProbeClient
from app.validation.safe_poc import Identity, SafePoC, identity_for


class _Eng:
    primary_auth = [{"name": "Cookie", "value": "sid=abc"}]
    secondary_auth = [{"name": "Cookie", "value": "sid=other"}]


# ---- the identity itself -----------------------------------------------

def test_an_identity_is_built_from_the_engagement():
    ident = identity_for(_Eng())
    assert ident.present
    assert ident.headers == (("Cookie", "sid=abc"),)


def test_the_second_identity_is_the_other_account():
    assert identity_for(_Eng(), secondary=True).headers == (("Cookie", "sid=other"),)


def test_an_empty_engagement_is_an_empty_identity():
    class _Blank:
        primary_auth = []
    ident = identity_for(_Blank())
    assert not ident.present
    assert ident.merge(None) is None          # behaves exactly as before


@pytest.mark.parametrize("auth", [
    None, [], [{}], [{"name": "", "value": "x"}], [{"name": "X", "value": ""}],
])
def test_a_half_filled_header_is_not_an_identity(auth):
    """A header with no value would be sent as 'X: ' and silently
    un-authenticate the request."""
    assert not Identity.from_auth(auth).present


def test_the_callers_headers_do_not_displace_the_identity():
    """THE bug, in one assertion. mass_assignment and api_sequences pass
    {"Content-Type": "application/json"} and were therefore probing as
    nobody; they are authenticated now without either of them changing."""
    merged = identity_for(_Eng()).merge({"Content-Type": "application/json"})
    assert merged == {"Cookie": "sid=abc", "Content-Type": "application/json"}


def test_a_caller_can_still_override_one_header():
    merged = identity_for(_Eng()).merge({"Cookie": "sid=mine"})
    assert merged == {"Cookie": "sid=mine"}


# ---- the clients send it, unless asked not to --------------------------

class _Resp:
    status_code = 200
    headers: dict = {}
    content = b"ok"
    text = "ok"
    url = "https://t.example/x"


def _record(monkeypatch, module):
    """Capture the headers the client actually puts on the wire."""
    sent = {}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, **kw):
            sent["headers"] = kw.get("headers")
            return _Resp()

    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **k: _Client())
    return sent


def test_safepoc_sends_the_identity_by_default(monkeypatch):
    import app.validation.safe_poc as mod
    sent = _record(monkeypatch, mod)
    safe = SafePoC(in_scope=lambda h: True, identity=identity_for(_Eng()))
    asyncio.run(safe.fetch("https://t.example/x"))
    assert sent["headers"] == {"Cookie": "sid=abc"}


def test_safepoc_sends_nothing_when_asked_for_anonymous(monkeypatch):
    import app.validation.safe_poc as mod
    sent = _record(monkeypatch, mod)
    safe = SafePoC(in_scope=lambda h: True, identity=identity_for(_Eng()))
    asyncio.run(safe.fetch("https://t.example/x", anonymous=True))
    assert not sent["headers"]


def test_the_probe_client_sends_the_identity_on_a_write(monkeypatch):
    import app.exploit.probe_client as mod
    sent = _record(monkeypatch, mod)
    client = ProbeClient(in_scope=lambda h: True, identity=identity_for(_Eng()))
    asyncio.run(client.fetch("https://t.example/x", method="POST",
                             content="{}",
                             headers={"Content-Type": "application/json"}))
    assert sent["headers"]["Cookie"] == "sid=abc"
    assert sent["headers"]["Content-Type"] == "application/json"


def test_anonymous_still_refuses_a_forbidden_method(monkeypatch):
    """The identity is orthogonal to the method policy; neither relaxes the
    other."""
    from app.validation.safe_poc import PolicyError
    safe = SafePoC(in_scope=lambda h: True, identity=identity_for(_Eng()))
    with pytest.raises(PolicyError):
        asyncio.run(safe.fetch("https://t.example/x", method="DELETE"))


def test_an_identity_never_widens_scope():
    from app.validation.safe_poc import ScopeError
    safe = SafePoC(in_scope=lambda h: False, identity=identity_for(_Eng()))
    with pytest.raises(ScopeError):
        asyncio.run(safe.fetch("https://elsewhere.example/x"))


# ---- which analysers are authenticated ---------------------------------

AUTHENTICATED = [
    ("app.analysis.mass_assignment", "analyze_mass_assignment"),
    ("app.analysis.rate_limit", "analyze_rate_limit"),
    ("app.analysis.cors", "analyze_cors"),
    ("app.analysis.graphql", "analyze_graphql"),
    ("app.analysis.param_discovery", "analyze_params"),
    ("app.analysis.jwt_analysis", "analyze_jwt"),
    ("app.analysis.logic", "analyze_logic"),
    ("app.exploit.cve_checks", "run_cve_checks"),
]


@pytest.mark.parametrize("module_name,fn_name", AUTHENTICATED)
def test_these_probe_as_the_logged_in_user(module_name, fn_name):
    """These test what an account can do, so they need the account. The two
    the operator asked for by name - mass assignment behind the gate, rate
    limiting behind the gate - are the first two."""
    import importlib
    mod = importlib.import_module(module_name)
    fn = getattr(mod, fn_name, None)
    if fn is None:
        pytest.skip(f"{module_name}.{fn_name} moved")
    src = inspect.getsource(mod)
    assert "identity_for(" in src, (
        f"{module_name} builds its client without an identity, so it probes "
        "anonymously even when the operator supplied credentials")


ANONYMOUS_IS_THE_POINT = [
    ("app.analysis.api_inventory", "_probe",
     "its claim is that a forgotten route answers with NO credential - and "
     "that is what the unauth_endpoint leads on the blackboard mean"),
    ("app.analysis.auth_posture", "_probe_bypass",
     "it only proceeds when the URL answers 401/403, so authenticated it "
     "would get a 200 and silently find nothing"),
]


@pytest.mark.parametrize("module_name,fn_name,why", ANONYMOUS_IS_THE_POINT)
def test_these_must_stay_anonymous(module_name, fn_name, why):
    import importlib
    mod = importlib.import_module(module_name)
    assert hasattr(mod, fn_name), f"{module_name}.{fn_name} moved"
    # The client these use is built without an identity. Checking the
    # construction rather than the call, because that is where it is decided.
    whole = inspect.getsource(mod)
    build = whole[whole.index("SafePoC(in_scope"):]
    build = build[:build.index("\n\n")] if "\n\n" in build else build
    assert "identity_for" not in build, f"{module_name} must stay anonymous: {why}"


def test_the_cross_identity_replays_ask_for_anonymous_by_name():
    """access_control and logic replay a captured request with no credential
    to see whether it still answers. They said so with an empty headers dict,
    which is indistinguishable from "no extra headers" - and became
    authenticated the moment the client grew an identity."""
    from app.analysis import access_control, logic
    for mod in (access_control, logic):
        src = inspect.getsource(mod)
        assert "anonymous=True" in src
        assert 'headers={}' not in src
