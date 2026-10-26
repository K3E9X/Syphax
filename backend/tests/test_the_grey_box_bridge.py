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
