"""Keep a run from taking the whole VM down.

A run on a 2GB Scaleway instance made the host unreachable - ping 100% loss,
SSH dead, reboot required. The cause was the worker launching eight heavy tool
subprocesses at once with no memory ceiling anywhere, so the box swapped
itself to death. These lock in the two levers that prevent it.
"""
from __future__ import annotations

import os
import pathlib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())


# ---- scan concurrency is bounded and tunable --------------------------

def test_the_default_concurrency_is_not_eight():
    """Eight parallel scanners is what killed the 2GB box."""
    os.environ.pop("SYPHAX_SCAN_CONCURRENCY", None)
    from app.workers import _scan_concurrency
    assert _scan_concurrency() <= 4


@pytest.mark.parametrize("env,expected", [
    ("2", 2), ("1", 1), ("8", 8), ("", 4), ("garbage", 4), ("999", 32), ("0", 1),
])
def test_concurrency_is_env_driven_and_clamped(env, expected, monkeypatch):
    if env:
        monkeypatch.setenv("SYPHAX_SCAN_CONCURRENCY", env)
    else:
        monkeypatch.delenv("SYPHAX_SCAN_CONCURRENCY", raising=False)
    from app.workers import _scan_concurrency
    assert _scan_concurrency() == expected


def test_the_worker_reads_the_knob():
    import inspect

    from app import workers
    assert "_scan_concurrency()" in inspect.getsource(workers.WorkerSettings)


# ---- every stateful/active service has a memory ceiling, no swap ------

_MUST_BE_CAPPED = ("postgres", "redis", "backend", "proxy", "worker",
                   "orchestrator", "frontend", "sandbox-runner")


@pytest.mark.parametrize("service", _MUST_BE_CAPPED)
def test_every_service_has_a_memory_limit(service):
    """Without a ceiling a single spike takes the whole host, not one
    container - which is the difference between a restart and a reboot."""
    spec = COMPOSE["services"][service]
    assert spec.get("mem_limit"), f"{service} has no mem_limit"


@pytest.mark.parametrize("service", _MUST_BE_CAPPED)
def test_swap_is_disabled_per_container(service):
    """memswap_limit == mem_limit means no swap for that container, so it is
    OOM-killed cleanly instead of thrashing the host into unreachability.
    (sandbox-runner sets mem_limit without swap config, which is acceptable -
    it is already the most constrained, read-only container.)"""
    spec = COMPOSE["services"][service]
    if service == "sandbox-runner":
        return
    assert spec.get("memswap_limit") == spec.get("mem_limit"), service


def test_the_worker_ceiling_is_the_largest_of_the_app_services():
    """Tools spawn as children inside the worker container, so their RAM
    counts against its cgroup - it needs the most headroom."""
    def mib(value: str) -> int:
        v = str(value).split(":-")[-1].rstrip("}").strip()
        return int(v[:-1]) * (1024 if v.endswith("g") else 1)
    services = COMPOSE["services"]
    worker = mib(services["worker"]["mem_limit"])
    for other in ("backend", "orchestrator", "frontend", "redis"):
        assert worker >= mib(services[other]["mem_limit"]), other


def test_the_limits_are_overridable_for_a_bigger_vm():
    """A larger instance must be able to raise them without editing compose."""
    raw = (ROOT / "docker-compose.yml").read_text()
    assert "${WORKER_MEM:-" in raw
    assert "${BACKEND_MEM:-" in raw


def test_the_knobs_are_documented():
    env = (ROOT / ".env.example").read_text()
    assert "SYPHAX_SCAN_CONCURRENCY" in env
    assert "WORKER_MEM" in env
