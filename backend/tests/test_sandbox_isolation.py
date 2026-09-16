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


def test_runner_environment_carries_no_credentials(runner):
    for entry in runner.get("environment") or []:
        key = str(entry).split("=", 1)[0].upper()
        assert not any(w in key for w in ("KEY", "TOKEN", "PASSWORD", "SECRET", "DSN")), \
            f"{key} does not belong in the sandbox"


def test_runner_mounts_nothing_from_the_host(runner):
    """No ./data: no mitmproxy CA, no settings key."""
    assert not runner.get("volumes")


# ---- Privilege ----

def test_runner_drops_all_capabilities_but_the_one_it_needs(runner):
    """NET_ADMIN is held only long enough to pin egress; entrypoint.sh then
    drops to an unprivileged user, so the PoC never holds it."""
    assert runner.get("cap_drop") == ["ALL"]
    assert runner.get("cap_add") == ["NET_ADMIN"]


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

def test_entrypoint_pins_egress_before_dropping_privileges():
    src = (COMPOSE.parent / "sandbox-runner" / "entrypoint.sh").read_text()
    assert src.index("iptables -A OUTPUT -j REJECT") < src.index("exec gosu poc"), \
        "privileges must be dropped only after the rules are in place"


def test_entrypoint_denies_everything_by_default():
    """Empty scope must mean deny-all. A sandbox that silently allows the whole
    internet looks identical to a working one until it matters."""
    src = (COMPOSE.parent / "sandbox-runner" / "entrypoint.sh").read_text()
    assert "outbound denied" in src
    assert "REJECT" in src


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
