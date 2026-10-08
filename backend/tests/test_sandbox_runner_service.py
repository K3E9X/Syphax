"""The sandbox runner's own behaviour, exercised rather than grepped.

Every other sandbox test reads entrypoint.sh or docker-compose.yml as text. That
catches a deleted rule and nothing else - and the defect these tests exist for
was invisible to text: the runner accepted `scope_hosts` on every request,
echoed it back, and never applied it. The allowlist came from
SANDBOX_ALLOWED_HOSTS at boot, which nothing ever set, so the jail denied every
packet while /health answered "ok". Each PoC then failed on
icmp-port-unreachable and the operator was told the exploit had not worked.

So these import runner.py and drive it, with iptables and the subprocess faked,
and assert what the kernel would have been told and what the PoC would have
been handed.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import pathlib
import sys

import pytest
from fastapi import HTTPException

RUNNER_PY = pathlib.Path(__file__).resolve().parents[2] / "sandbox-runner" / "runner.py"


def _load():
    spec = importlib.util.spec_from_file_location("syphax_sandbox_runner", RUNNER_PY)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def runner():
    return _load()


class _FakeProc:
    returncode = 0

    async def communicate(self):
        return b"proved it: root:x:0:0\n", b""

    def kill(self):  # pragma: no cover - only on the timeout path
        pass


@pytest.fixture
def driven(runner, monkeypatch):
    """runner with iptables, DNS, the poc account and exec all faked."""
    calls = []
    spawned = {}

    monkeypatch.setattr(runner, "_iptables",
                        lambda binary, *args: (calls.append((binary, *args)), (0, ""))[1])
    monkeypatch.setattr(runner, "_resolve",
                        lambda host: (["93.184.216.34"], []) if "example" in host else ([], []))
    monkeypatch.setattr(runner, "_poc_ids", lambda: (4242, 4242))
    monkeypatch.setattr(runner.shutil, "which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(runner.os, "chown", lambda *a, **k: None)
    monkeypatch.setattr(runner, "WORKDIR", pathlib.Path(os.environ.get("TMPDIR", "/tmp")))

    async def _spawn(*cmd, **kwargs):
        spawned["cmd"] = list(cmd)
        spawned["env"] = kwargs.get("env")
        return _FakeProc()

    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", _spawn)
    return runner, calls, spawned


def _req(runner, **over):
    payload = {"code": "print('x')", "language": "python",
               "scope_hosts": ["app.example.com"], "timeout": 5}
    payload.update(over)
    return runner.RunRequest(**payload)


# ---- the allowlist is applied, not echoed -----------------------------------

def test_the_engagement_scope_reaches_the_kernel(driven):
    runner, calls, _ = driven
    asyncio.run(runner.run_v1(_req(runner)))

    chain = runner.EGRESS_CHAIN
    flushes = [c for c in calls if c[:3] == ("iptables", "-F", chain)]
    accepts = [c for c in calls
               if c[:2] == ("iptables", "-A") and c[2] == chain and "ACCEPT" in c]
    assert flushes, "the chain was never flushed before the run"
    assert accepts, "the scope was accepted by nobody: egress would deny everything"
    assert "93.184.216.34" in accepts[0], accepts[0]


def test_the_allowlist_is_closed_again_afterwards(driven):
    """An idle container must not stay a proxy to the last engagement's scope."""
    runner, calls, _ = driven
    asyncio.run(runner.run_v1(_req(runner)))
    chain = runner.EGRESS_CHAIN
    last_write = max(i for i, c in enumerate(calls)
                     if c[:2] == ("iptables", "-A") and c[2] == chain)
    later_flush = [i for i, c in enumerate(calls)
                   if c[:3] == ("iptables", "-F", chain) and i > last_write]
    assert later_flush, "the allowlist outlived the run"


def test_a_scope_that_resolves_to_nothing_refuses_instead_of_running(driven):
    """This was reported to the operator as a failed exploit. It is a DNS
    problem, and running with a deny-all jail proves nothing either way."""
    runner, _calls, spawned = driven
    with pytest.raises(HTTPException) as exc:
        asyncio.run(runner.run_v1(_req(runner, scope_hosts=["nowhere.invalid"])))
    assert exc.value.status_code == 400
    assert "not a failed exploit" in str(exc.value.detail)
    assert not spawned, "code ran with an empty allowlist"


def test_no_scope_is_refused(driven):
    runner, _calls, spawned = driven
    with pytest.raises(HTTPException) as exc:
        asyncio.run(runner.run_v1(_req(runner, scope_hosts=[])))
    assert exc.value.status_code == 400
    assert not spawned


# ---- the PoC is the thing that loses privilege ------------------------------

def test_the_poc_runs_as_the_unprivileged_user(driven):
    """The server keeps root so it can write the allowlist; the PoC must not."""
    runner, _calls, spawned = driven
    asyncio.run(runner.run_v1(_req(runner)))
    assert spawned["cmd"][:2] == ["gosu", runner.POC_USER], spawned["cmd"]


def test_the_poc_never_sees_the_runner_token(driven, monkeypatch):
    """The token is what lets the backend widen the egress allowlist. A PoC that
    could read it out of its own environment could allowlist its exfiltration
    host, which is the whole reason the owner-match iptables rule exists too."""
    runner, _calls, spawned = driven
    monkeypatch.setattr(runner, "RUNNER_TOKEN", "s3cret")
    asyncio.run(runner.run_v1(_req(runner), x_sandbox_token="s3cret"))
    env = spawned["env"]
    assert "s3cret" not in repr(env)
    assert set(env) == {"PATH", "HOME", "LANG"}, env


# ---- authentication actually happens ----------------------------------------

def test_a_wrong_token_is_rejected(driven, monkeypatch):
    """RUNNER_TOKEN was read at import and then checked by no endpoint at all,
    so it authenticated nothing."""
    runner, _calls, spawned = driven
    monkeypatch.setattr(runner, "RUNNER_TOKEN", "s3cret")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(runner.run_v1(_req(runner), x_sandbox_token="guess"))
    assert exc.value.status_code == 401
    assert not spawned


def test_a_bearer_prefix_is_accepted(driven, monkeypatch):
    runner, _calls, spawned = driven
    monkeypatch.setattr(runner, "RUNNER_TOKEN", "s3cret")
    asyncio.run(runner.run_v1(_req(runner), x_sandbox_token="Bearer s3cret"))
    assert spawned


# ---- health says enough for the backend to refuse a stale image -------------

def test_health_reports_the_egress_mode_and_the_clients(runner, monkeypatch):
    monkeypatch.setattr(runner, "_current_allowlist", lambda: ["93.184.216.34"])
    monkeypatch.setattr(runner, "_egress_mode", lambda: "per-request")
    out = asyncio.run(runner.health())
    assert out["egress_mode"] == "per-request"
    assert out["egress_allowlist"] == ["93.184.216.34"]
    # The image shipped with no HTTP client while the authoring prompt promised
    # `requests`. Reported so that can never be silent again.
    assert set(out["clients"]) == {"python_requests", "curl", "node"}


def test_an_image_without_the_mode_marker_reads_as_boot(runner, monkeypatch):
    """The backend refuses a 'boot' runner, because that one denies everything."""
    monkeypatch.setattr(runner, "EGRESS_MODE_FILE", pathlib.Path("/nonexistent/mode"))
    assert runner._egress_mode() == "boot"
