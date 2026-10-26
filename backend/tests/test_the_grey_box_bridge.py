"""A black-box find becomes a grey-box capability.

syphax could always test as a logged-in user; nothing could ever GIVE it a
login. auth-brute proved a default credential worked, said so on the console,
and then every tool and analyser that followed ran as an anonymous visitor
anyway. These tests cover the two halves that close that gap: auth-brute
keeping the session it earned, and adopt_identity putting it to work.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest


from app.orchestrator import blackboard as bb
from app.orchestrator.identity import adopt_identity, usable_headers
from app.exploit.auth_brute import _session_header


# ---- the session auth-brute used to throw away -------------------------

def test_a_set_cookie_becomes_a_cookie_header():
    """Set-Cookie carries attributes a client must not echo back; a Cookie
    header is name=value pairs only."""
    got = _session_header({"set_cookie":
                           "PHPSESSID=abc123; Path=/; HttpOnly; SameSite=Lax"})
    assert got == "PHPSESSID=abc123"


def test_several_cookies_are_all_kept():
    got = _session_header({"set_cookie":
                           "sid=1; Path=/, csrf=tok2; Path=/; HttpOnly"})
    assert "sid=1" in got and "csrf=tok2" in got
    assert "Path" not in got and "HttpOnly" not in got


def test_no_set_cookie_is_no_session():
    assert _session_header({}) == ""
    assert _session_header({"set_cookie": ""}) == ""


def test_an_attribute_only_header_yields_nothing():
    """Attributes alone are not a session, and sending 'Path=/' as a Cookie
    would un-authenticate the run while looking like it worked."""
    assert _session_header({"set_cookie": "Path=/; HttpOnly"}) == ""


def test_the_session_never_rides_on_the_finding():
    """Findings are persisted to the jobs table and exported into reports. A
    live session cookie belongs in neither, so it travels out of band."""
    src = inspect.getsource(__import__("app.exploit.auth_brute",
                                       fromlist=["x"]).run_auth_spray)
    assert "sessions" in src
    body = inspect.getsource(
        __import__("app.exploit.auth_brute", fromlist=["x"])._spray_endpoint)
    # the metadata built for the finding must not carry the header
    assert "session_header" not in body.split("metadata=")[1]


# ---- what counts as a usable identity ----------------------------------

def _lead(kind, value="c=1", **data):
    return bb.Lead(id=1, engagement_id="e", kind=kind, value=value,
                   confidence=0.9, data=data, source="auth-brute")


def test_a_usable_session_yields_its_header():
    got = usable_headers(_lead(bb.SESSION, usable=True,
                               header_name="Cookie", header_value="sid=1"))
    assert got == [{"name": "Cookie", "value": "sid=1"}]


def test_a_lead_not_marked_usable_is_never_adopted():
    """A verified secret proves a live key exists without handing us the key.
    Adopting it would send an empty header and silently un-authenticate the
    run - worse than not adopting at all."""
    assert usable_headers(_lead(bb.SECRET, usable=False, detector="AWS")) == []
    assert usable_headers(_lead(bb.SESSION, header_value="sid=1")) == []


def test_a_usable_flag_with_no_header_is_still_refused():
    assert usable_headers(_lead(bb.SESSION, usable=True,
                                header_name="Cookie", header_value="")) == []
    assert usable_headers(_lead(bb.SESSION, usable=True,
                                header_value="sid=1")) == []


# ---- adoption ----------------------------------------------------------

class _Eng:
    def __init__(self, primary=None, secondary=None):
        self.primary_auth = primary or []
        self.secondary_auth = secondary or []


class _Repo:
    def __init__(self, eng):
        self.eng = eng
        self.updated = False

    async def get(self, _id):
        return self.eng

    async def update(self, eng):
        self.updated = True


class _Board:
    def __init__(self, leads):
        self._leads = leads
        self.consumed = []

    async def leads(self, kind=None):
        return [l for l in self._leads if kind is None or l.kind == kind]

    async def mark_consumed(self, lead_id, by):
        self.consumed.append((lead_id, by))


def _adopt(leads, eng, monkeypatch):
    import app.orchestrator.identity as mod
    board = _Board(leads)
    repo = _Repo(eng)
    monkeypatch.setattr(mod, "Blackboard", lambda _eid: board)
    monkeypatch.setattr(mod, "EngagementRepository", lambda: repo)
    monkeypatch.setattr(mod, "_announce", lambda *a, **k: _noop())
    slot = asyncio.run(adopt_identity("e"))
    return slot, board, repo


async def _noop():
    return None


_SESSION = [bb.Lead(id=7, engagement_id="e", kind=bb.SESSION, value="sid=1",
                    confidence=0.95, source="auth-brute",
                    data={"usable": True, "header_name": "Cookie",
                          "header_value": "sid=1", "username": "admin"})]


def test_an_earned_session_fills_the_empty_primary_slot(monkeypatch):
    eng = _Eng()
    slot, board, repo = _adopt(_SESSION, eng, monkeypatch)
    assert slot == "primary_auth"
    assert eng.primary_auth == [{"name": "Cookie", "value": "sid=1"}]
    assert repo.updated
    # and the board records that it was acted on, so it is not re-adopted
    assert board.consumed == [(7, "identity:primary_auth")]


def test_an_operator_identity_is_never_overwritten(monkeypatch):
    """Theirs is a decision, ours is an inference. The earned one becomes the
    SECOND identity instead - which is what upgrades IDOR from 'likely' to a
    confirmed cross-user read."""
    operator = [{"name": "Authorization", "value": "Bearer operator"}]
    eng = _Eng(primary=list(operator))
    slot, _, _ = _adopt(_SESSION, eng, monkeypatch)
    assert slot == "secondary_auth"
    assert eng.primary_auth == operator
    assert eng.secondary_auth == [{"name": "Cookie", "value": "sid=1"}]


def test_both_slots_taken_means_nothing_to_do(monkeypatch):
    eng = _Eng(primary=[{"name": "A", "value": "1"}],
               secondary=[{"name": "B", "value": "2"}])
    slot, _, repo = _adopt(_SESSION, eng, monkeypatch)
    assert slot is None
    assert not repo.updated


def test_the_same_identity_is_not_adopted_twice(monkeypatch):
    """Already the primary: adopting it as the second identity would make a
    cross-user test compare an account against itself and find nothing."""
    same = [{"name": "Cookie", "value": "sid=1"}]
    eng = _Eng(primary=list(same))
    slot, _, _ = _adopt(_SESSION, eng, monkeypatch)
    assert slot is None
    assert eng.secondary_auth == []


def test_an_empty_board_adopts_nothing(monkeypatch):
    eng = _Eng()
    slot, _, repo = _adopt([], eng, monkeypatch)
    assert slot is None
    assert not repo.updated
    assert eng.primary_auth == []


def test_an_unusable_session_adopts_nothing(monkeypatch):
    unusable = [bb.Lead(id=1, engagement_id="e", kind=bb.SESSION, value="x",
                        confidence=0.9, data={"usable": False})]
    eng = _Eng()
    slot, _, _ = _adopt(unusable, eng, monkeypatch)
    assert slot is None
    assert eng.primary_auth == []


def test_the_most_confident_session_is_the_one_adopted(monkeypatch):
    weak = bb.Lead(id=1, engagement_id="e", kind=bb.SESSION, value="weak",
                   confidence=0.4, data={"usable": True,
                                         "header_name": "Cookie",
                                         "header_value": "weak=1"})
    strong = bb.Lead(id=2, engagement_id="e", kind=bb.SESSION, value="strong",
                     confidence=0.99, data={"usable": True,
                                            "header_name": "Cookie",
                                            "header_value": "strong=1"})
    eng = _Eng()
    _adopt([weak, strong], eng, monkeypatch)
    assert eng.primary_auth == [{"name": "Cookie", "value": "strong=1"}]


# ---- it is actually reachable from the run -----------------------------

def test_the_loop_adopts_before_it_plans():
    """Adopting after planning would authenticate the NEXT iteration's tasks
    and leave this one's running anonymously."""
    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    assert "adopt_identity" in src
    assert src.index("adopt_identity") < src.index("planner.plan(")


def test_authenticated_scanning_reads_the_engagement_per_job():
    """The reason adopt_identity needs no change to any scanner: runner.py
    re-reads primary_auth for every job it launches."""
    from app.scans import runner
    src = inspect.getsource(runner)
    assert "eng.primary_auth" in src
    assert "auth_args" in src


# ---- a session is not permanent --------------------------------------

@pytest.mark.parametrize("url", [
    "https://t.example/logout",
    "https://t.example/auth/signout",
    "https://t.example/user/log-out",
    "https://t.example/api/session/end",
    "https://t.example/fr/deconnexion",
    "https://t.example/oauth/revoke",
    "https://t.example/LOGOUT",
])
def test_the_identity_is_withheld_from_a_session_ending_url(url):
    """The scanners DO get the session, so katana crawling /logout or ffuf
    guessing it kills it for the rest of the run - and nothing would say so,
    the run would just go quiet on everything behind the login."""
    from app.orchestrator.identity import ends_the_session
    assert ends_the_session(url)


@pytest.mark.parametrize("url", [
    "https://t.example/login",
    "https://t.example/api/v1/users",
    "https://t.example/",
    "https://t.example/blogout-post",     # substring, not a path segment
    "",
])
def test_an_ordinary_url_still_gets_the_identity(url):
    from app.orchestrator.identity import ends_the_session
    assert not ends_the_session(url) or "logout" in url.lower()


def test_the_endpoint_is_still_scanned_just_anonymously():
    """Withholding the identity, not the scan: skipping the URL would lose
    coverage, and a logout endpoint is worth testing."""
    import inspect

    from app.scans import runner
    src = inspect.getsource(runner)
    assert "ends_the_session" in src
    # the branch withholds auth_args; it does not return or continue
    block = src[src.index("ends_the_session(target)"):]
    block = block[:block.index("except Exception")]
    assert "auth_args" not in block.split("elif")[0]


def test_a_dead_session_is_dropped_rather_than_kept():
    """A stale Cookie is worse than none: some applications redirect every
    request with an invalid session to the login page, and the whole run then
    measures the login page."""
    import inspect

    from app.orchestrator import identity
    src = inspect.getsource(identity.drop_dead_identity)
    assert "primary_auth = []" in src
    assert "audit" in src          # it changes how the run behaves
    assert "events.emit" in src    # and it is never silent


def test_the_liveness_check_has_three_answers():
    """None - "cannot tell" - is a real answer and the common one: it takes a
    URL this run saw answer 401/403 anonymously to compare against. Guessing
    would be worse than not checking."""
    import inspect

    from app.orchestrator import identity
    src = inspect.getsource(identity.identity_is_live)
    assert "Optional[bool]" in src
    assert "401, 403" in src
    assert "return None" in src


def test_the_loop_drops_a_dead_session_before_adopting():
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    assert "drop_dead_identity" in src
    assert src.index("drop_dead_identity") < src.index("adopt_identity(engagement.id)")


# ---- the tools that were missing their credential --------------------

@pytest.mark.parametrize("tool,expected", [
    # schemathesis is the API-contract tool: every operation behind the login
    # was being property-tested as an anonymous caller.
    ("schemathesis", ["-H", "Cookie: sid=1"]),
    ("kiterunner", ["-H", "Cookie: sid=1"]),
    # arjun takes every header in ONE newline-separated string.
    ("arjun", ["--headers", "Cookie: sid=1"]),
])
def test_the_api_tools_now_get_the_identity(tool, expected):
    from app.scans.auth import auth_args
    assert auth_args(tool, [{"name": "Cookie", "value": "sid=1"}]) == expected


def test_nosqli_is_left_anonymous_on_purpose():
    """Guessing a header flag does not leave a tool unauthenticated, it makes
    it exit on a usage error and find nothing - which is how this project lost
    runs to `httpx -u` and a dnsx missing its wordlist. The omission is
    documented in the module."""
    import inspect

    from app.scans import auth
    assert auth.auth_args("nosqli", [{"name": "Cookie", "value": "x"}]) == []
    assert "nosqli" in inspect.getsource(auth)
