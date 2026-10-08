"""Client for the isolated sandbox runner.

The backend never executes untrusted code itself and never talks to Docker to
arrange it - handing the backend a Docker socket would trade "untrusted code
runs in a container" for "the service holding every API key can take the host",
which is a worse deal. Instead it POSTs the code to a service on a private
network and reads the result back.

Three refusals live here, and all three are deliberate:

  * If the runner reports its egress was never locked, no work is sent. A
    sandbox that silently allows the whole internet looks identical to a
    working one right up until a trojaned PoC uses it.
  * If the caller passes no scope, nothing is sent. "Run this anywhere" is
    never what an engagement means.
  * If the runner does not apply the scope PER REQUEST, no work is sent. The
    older image resolved SANDBOX_ALLOWED_HOSTS once at boot; that variable is
    empty in every normal install, so the jail denied every outbound packet
    while /health still answered "ok". Every PoC then failed on
    icmp-port-unreachable and the operator was told the exploit had not worked.
    Refusing with a message that names the cause is the whole point.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import httpx

logger = logging.getLogger("syphax.sandbox.runner_client")

RUNNER_URL = os.environ.get("SANDBOX_RUNNER_URL", "http://sandbox-runner:8090")
CONNECT_TIMEOUT = 5.0

# Shared with the runner by compose. The runner holds CAP_NET_ADMIN so that it
# can set the egress allowlist per request, which makes "only the backend may
# drive it" a requirement rather than hygiene. Read at call time so a key set
# in the environment after import still applies.
def _token() -> str:
    return (os.environ.get("SANDBOX_RUNNER_TOKEN", "") or "").strip()


def _headers() -> Dict[str, str]:
    token = _token()
    return {"X-Sandbox-Token": token} if token else {}

LANGUAGES = {"python", "bash", "javascript"}


class SandboxUnavailable(RuntimeError):
    """The runner is absent, unhealthy, or its egress was never pinned."""


@dataclass
class SandboxResult:
    exit_code: Optional[int]
    timed_out: bool
    duration_s: float
    stdout: str
    stderr: str
    scope_hosts: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_s": self.duration_s,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "scope_hosts": self.scope_hosts,
        }


async def health() -> Dict[str, Any]:
    """Runner status, including whether its egress policy actually applied."""
    async with httpx.AsyncClient(timeout=CONNECT_TIMEOUT) as client:
        resp = await client.get(f"{RUNNER_URL}/health", headers=_headers())
        resp.raise_for_status()
        return resp.json() or {}


async def is_available() -> bool:
    try:
        return bool((await health()).get("status") == "ok")
    except Exception as exc:  # noqa: BLE001 - absent runner is a normal state
        logger.debug("sandbox runner unavailable: %s", exc)
        return False


async def run_poc(code: str, *, language: str = "python",
                  scope_hosts: Sequence[str], argv: Optional[Sequence[str]] = None,
                  timeout: int = 60) -> SandboxResult:
    """Execute an approved PoC in the isolated runner.

    Everything upstream - inspection, operator review, approval - has already
    happened. This is the last hop, and it still refuses two things.
    """
    if language not in LANGUAGES:
        raise ValueError(f"language must be one of {sorted(LANGUAGES)}")
    if not (code or "").strip():
        raise ValueError("empty code")

    hosts = [h for h in (scope_hosts or []) if (h or "").strip()]
    if not hosts:
        # Without a scope there is nothing to pin egress to, and "run this
        # against anything" is never what an engagement authorises.
        raise ValueError("scope_hosts is required: refusing to run with no scope")

    try:
        status = await health()
    except Exception as exc:  # noqa: BLE001
        raise SandboxUnavailable(
            f"sandbox runner not reachable at {RUNNER_URL}: {exc}") from exc

    if not status.get("egress_locked"):
        raise SandboxUnavailable(
            "sandbox runner started without an egress policy - refusing to run "
            "untrusted code with unrestricted outbound access")

    mode = str(status.get("egress_mode") or "boot")
    if mode != "per-request":
        raise SandboxUnavailable(
            "the sandbox runner image predates per-request egress: it pins its "
            "allowlist once at boot from SANDBOX_ALLOWED_HOSTS, which is empty "
            "here, so it would deny every packet this PoC sends and the failure "
            "would look like a failed exploit. Rebuild the sandbox-runner image "
            "(docker compose up -d --build sandbox-runner).")

    # The image shipped with no HTTP client while the authoring prompt promised
    # `requests` and curl. A PoC could not reach the target at all, and the
    # ModuleNotFoundError was reported as a failed exploit.
    clients = status.get("clients") or {}
    needs = {"python": "python_requests", "bash": "curl", "javascript": "node"}
    needed = needs.get(language)
    if needed and clients and not clients.get(needed, True):
        raise SandboxUnavailable(
            f"the sandbox runner has no HTTP client for {language} ({needed} is "
            "absent), so a PoC cannot reach the target at all. Rebuild the "
            "sandbox-runner image (docker compose up -d --build sandbox-runner).")

    payload = {"code": code, "language": language, "timeout": int(timeout),
               "argv": [str(a) for a in (argv or [])], "scope_hosts": hosts}

    # Generous read timeout: the PoC's own timeout is enforced runner-side, and
    # cutting the HTTP call early would lose the output we came for.
    async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout + 30, connect=CONNECT_TIMEOUT)) as client:
        resp = await client.post(f"{RUNNER_URL}/v1/run", json=payload,
                                 headers=_headers())
        if resp.status_code == 400:
            # The runner refuses before executing when the scope resolves to
            # nothing. That is a scope/DNS problem, and saying so beats
            # reporting a non-zero exit as a failed exploit.
            raise SandboxUnavailable(_detail(resp))
        if resp.status_code == 401:
            raise SandboxUnavailable(
                "the sandbox runner rejected the backend's token: set the same "
                "SANDBOX_RUNNER_TOKEN on both services")
        resp.raise_for_status()
        data = resp.json() or {}

    return SandboxResult(
        exit_code=data.get("exit_code"),
        timed_out=bool(data.get("timed_out")),
        duration_s=float(data.get("duration_s") or 0.0),
        stdout=str(data.get("stdout") or ""),
        stderr=str(data.get("stderr") or ""),
        scope_hosts=list(data.get("scope_hosts") or hosts),
    )


def _detail(resp) -> str:
    try:
        return str((resp.json() or {}).get("detail") or resp.text)[:500]
    except Exception:  # noqa: BLE001 - a non-JSON body is still worth showing
        return (resp.text or "")[:500]
