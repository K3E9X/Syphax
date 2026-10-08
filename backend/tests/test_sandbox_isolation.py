"""The sandbox's isolation, asserted against the compose file itself.

These read like configuration tests because that is where the isolation lives.
The runner executes code an attacker wrote; what stops it reaching Postgres is
not a check in Python, it is the absence of a network. If someone later adds
`syphax-net` to that service for convenience, nothing would visibly break - the
tool would keep working, quietly handing untrusted code a route to the database
and every API key. That is exactly the kind of regression a test has to catch.
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

COMPOSE = pathlib.Path(__file__).resolve().parents[2] / "docker-compose.yml"


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text())


@pytest.fixture(scope="module")
def runner(compose):
    svc = compose["services"].get("sandbox-runner")
    assert svc, "sandbox-runner service is missing"
    return svc


# ---- Network: the isolation that actually matters ----

def test_runner_is_not_on_the_stack_network(runner):
    """No route to Postgres or Redis. Not filtered - unaddressable."""
    assert runner.get("networks") == ["sandbox-net"]
    assert "syphax-net" not in (runner.get("networks") or [])


def test_stateful_services_are_not_on_the_sandbox_network(compose):
    for name in ("postgres", "redis", "worker", "orchestrator"):
        nets = compose["services"][name].get("networks") or []
        assert "sandbox-net" not in nets, f"{name} is reachable from the sandbox"


def test_backend_is_the_only_bridge(compose):
    """The backend needs both: the DB on one side, the runner on the other."""
    assert set(compose["services"]["backend"]["networks"]) == {"syphax-net", "sandbox-net"}
    bridges = [n for n, s in compose["services"].items()
               if set(s.get("networks") or []) >= {"syphax-net", "sandbox-net"}]
    assert bridges == ["backend"]


def test_runner_is_not_published_to_the_host(runner):
    """Reachable from the backend, not from the network the operator is on."""
    assert "ports" not in runner
    assert runner.get("expose") == ["8090"]


# ---- Secrets: nothing worth stealing ----

def test_runner_has_no_env_file(runner):
    """A trojaned PoC's usual objective is the environment. There is nothing
    in this one: no provider keys, no database password."""
    assert "env_file" not in runner


# The one credential the sandbox is allowed to hold, because it is the
# credential FOR the sandbox: the runner keeps CAP_NET_ADMIN so it can pin
# egress per request, so only the backend may drive /v1/run. It is worthless
# anywhere else - it grants "run code in a box that already runs code" - and
# test_the_poc_never_sees_the_runner_token proves the PoC cannot read it.
_SANDBOX_OWN_CREDENTIAL = "SANDBOX_RUNNER_TOKEN"


def test_runner_environment_carries_no_credentials(runner):
    for entry in runner.get("environment") or []:
        key = str(entry).split("=", 1)[0].upper()
        if key == _SANDBOX_OWN_CREDENTIAL:
            continue
        assert not any(w in key for w in ("KEY", "TOKEN", "PASSWORD", "SECRET", "DSN")), \
            f"{key} does not belong in the sandbox"


def test_runner_mounts_nothing_from_the_host(runner):
    """No ./data: no mitmproxy CA, no settings key."""
    assert not runner.get("volumes")


# ---- Privilege ----

def test_runner_drops_all_capabilities_but_the_one_it_needs(runner):
    """NET_ADMIN pins egress; SETUID/SETGID let the root entrypoint gosu down to
    the unprivileged `poc` user (gosu fails without them). All three are held
    only by entrypoint.sh; the PoC itself runs as `poc` with no capabilities."""
    assert runner.get("cap_drop") == ["ALL"]
    assert runner.get("cap_add") == ["NET_ADMIN", "SETUID", "SETGID"]


def test_runner_cannot_gain_privileges(runner):
    assert "no-new-privileges:true" in (runner.get("security_opt") or [])


def test_runner_filesystem_is_read_only_with_tmpfs_workdir(runner):
    """Staged code never touches a disk that survives the container."""
    assert runner.get("read_only") is True
    assert any(str(t).startswith("/work") for t in (runner.get("tmpfs") or []))


def test_runner_has_resource_limits(runner):
    assert runner.get("mem_limit")
    assert runner.get("pids_limit")


# ---- The entrypoint's ordering is the whole design ----

def _entrypoint() -> list:
    """entrypoint.sh as logical lines: backslash continuations joined.

    The rules are written across continuations for readability, so a per-line
    grep silently matches nothing - which is how an assertion about them can
    pass while testing air.
    """
    raw = (COMPOSE.parent / "sandbox-runner" / "entrypoint.sh").read_text()
    joined = raw.replace("\\\n", " ")
    return [" ".join(ln.split()) for ln in joined.splitlines() if ln.strip()]


def test_entrypoint_closes_the_jail_before_serving():
    """Nothing may be served until the final REJECT is in place.

    The server now keeps root, because writing the per-request allowlist needs
    CAP_NET_ADMIN - so the ordering guarantee moved from "drop privileges last"
    to "serve last". The PoC is what gets de-privileged, inside runner.py.
    """
    src = (COMPOSE.parent / "sandbox-runner" / "entrypoint.sh").read_text()
    assert src.index("iptables -A OUTPUT -j REJECT") < src.index('exec "$@"'), \
        "the runner must not accept a request before egress is closed"


def test_the_poc_cannot_reach_the_control_port():
    """This is what pays for the server keeping NET_ADMIN.

    The server can widen the egress allowlist; the PoC runs as a different uid
    and an owner-match rule rejects anything it sends to the control port, on
    every interface including loopback. Without this rule a PoC could POST to
    /v1/run and allowlist its own exfiltration host.
    """
    src = _entrypoint()
    rule = [ln for ln in src
            if "--uid-owner" in ln and "--dport" in ln and "iptables -A OUTPUT" in ln]
    assert rule, "no owner-match rule guards the control port"
    # And it must be the FIRST OUTPUT rule: a loopback ACCEPT before it would
    # let the PoC straight through to 127.0.0.1:8090.
    # `in`, not startswith: the rule is written as `if ! iptables -A OUTPUT ...`
    # so that a missing xt_owner aborts the boot, and a startswith filter would
    # skip it and then assert the ordering of the wrong rule.
    outputs = [ln for ln in src if "iptables -A OUTPUT" in ln]
    assert "--uid-owner" in outputs[0], \
        f"the owner-match rule must come first, not after {outputs[0]!r}"
    # Fail closed when there is nothing else: a kernel with no xt_owner must
    # either have SANDBOX_RUNNER_TOKEN (which a PoC cannot read - its
    # environment is wiped to PATH/HOME/LANG) or refuse to boot. What it must
    # NOT do is start with neither control.
    tail = "\n".join(src[src.index(rule[0]):src.index(rule[0]) + 25])
    assert "SANDBOX_RUNNER_TOKEN" in tail, \
        "no fallback control named for a kernel without xt_owner"
    assert "die " in tail, \
        "with neither the owner rule nor a token, the runner must not start"


def test_entrypoint_denies_everything_by_default():
    """Empty scope must mean deny-all.

    The allowlist is per request now, so "by default" means two things: the
    chain OUTPUT jumps to is created empty, and the policy still ends in a
    REJECT. An unconfigured SANDBOX_ALLOWED_HOSTS is no longer a dead sandbox -
    it is the normal case - but an idle one must still reach nothing.
    """
    src = (COMPOSE.parent / "sandbox-runner" / "entrypoint.sh").read_text()
    assert "iptables -N SYPHAX_EGRESS" in src.replace('"$chain"', "SYPHAX_EGRESS") \
        or "SYPHAX_EGRESS" in src
    assert "iptables -A OUTPUT -j REJECT" in src
    # IPv6 was unconfigured, which meant the whole v4 policy could be walked
    # around with a v6 literal or a AAAA record.
    assert "ip6tables" in src and "ip6tables -A OUTPUT -j REJECT" in src


def test_the_runner_flushes_the_allowlist_after_every_run():
    """Deny-all at rest. Otherwise the container stays a usable proxy to the
    last engagement's scope for as long as it is up."""
    src = (COMPOSE.parent / "sandbox-runner" / "runner.py").read_text()
    assert "_flush_egress()" in src
    body = src.split("async def run_v1")[1]
    assert "finally:" in body and "_flush_egress()" in body.split("finally:")[1], \
        "the allowlist must be flushed in a finally, so a crash still closes it"


def test_entrypoint_refuses_to_start_without_iptables():
    """A sandbox that cannot enforce egress must not run untrusted code.

    This asserted the phrase "refusing to start", which broke the moment the
    message was reworded even though the behaviour was unchanged. Assert the
    behaviour instead: every path that cannot apply the policy exits non-zero,
    and the script aborts on any unhandled failure.
    """
    src = (COMPOSE.parent / "sandbox-runner" / "entrypoint.sh").read_text()
    assert "set -euo pipefail" in src, "an unchecked failure would start anyway"

    # Both ways the policy can be impossible: no iptables binary, or iptables
    # refusing to write rules (no NET_ADMIN, or a kernel without nf_tables).
    assert "command -v iptables" in src
    assert "iptables -F OUTPUT" in src

    # Each of those leads to a non-zero exit rather than falling through.
    assert src.count("exit 1") >= 1
    assert "die " in src or "exit 1" in src

    # And the deny-all rule is the last one, so anything not explicitly
    # allowed above it is rejected.
    rules = [l.strip() for l in src.splitlines() if l.strip().startswith("iptables -A OUTPUT")]
    assert rules[-1].startswith("iptables -A OUTPUT -j REJECT"), (
        f"the final rule must reject; it is {rules[-1]!r}")


def test_entrypoint_says_which_step_failed():
    """The operator only ever saw "runner unavailable" in the UI. The container
    log has to name the cause, or there is nothing to act on."""
    src = (COMPOSE.parent / "sandbox-runner" / "entrypoint.sh").read_text()
    assert "NET_ADMIN" in src, "the capability case is the common one"
    assert "nf_tables" in src, "Docker Desktop's kernel is the other common one"
    assert "docker compose logs sandbox-runner" in src


def test_runner_image_ships_no_network_tooling():
    """Every extra binary is one a trojaned PoC gets to use.

    Only the install lines are inspected: the comments in that Dockerfile name
    these tools precisely to say they are excluded.
    """
    dockerfile = (COMPOSE.parent / "sandbox-runner" / "Dockerfile").read_text()
    installs = " ".join(
        line.split("#", 1)[0].lower()
        for line in dockerfile.splitlines()
        if "apt-get install" in line or "apk add" in line
    )
    for tool in ("curl", "git", "openssh", "wget", "netcat", "nmap", "socat"):
        assert tool not in installs, f"{tool} does not belong in the sandbox image"


# ---- Client-side refusals ----

async def test_client_refuses_to_run_without_a_scope():
    from app.sandbox.runner_client import run_poc

    with pytest.raises(ValueError, match="scope"):
        await run_poc("print(1)", scope_hosts=[])


async def test_client_refuses_an_unlocked_runner(monkeypatch):
    """The single most dangerous failure mode: a runner whose egress policy
    never applied still answers /health and looks perfectly healthy."""
    from app.sandbox import runner_client

    async def unlocked():
        return {"status": "ok", "egress_locked": False}

    monkeypatch.setattr(runner_client, "health", unlocked)
    with pytest.raises(runner_client.SandboxUnavailable, match="egress"):
        await runner_client.run_poc("print(1)", scope_hosts=["app.example.com"])


async def test_client_rejects_unknown_languages():
    from app.sandbox.runner_client import run_poc

    with pytest.raises(ValueError, match="language"):
        await run_poc("x", language="ruby", scope_hosts=["app.example.com"])


async def test_client_rejects_empty_code():
    from app.sandbox.runner_client import run_poc

    with pytest.raises(ValueError, match="empty"):
        await run_poc("   ", scope_hosts=["app.example.com"])
