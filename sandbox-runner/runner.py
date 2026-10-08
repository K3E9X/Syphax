"""Isolated PoC runner.

Runs untrusted third-party code. It is deliberately the dumbest service in the
stack: one endpoint, no database, no queue, no credentials, no knowledge of the
rest of Syphax. The backend pushes it a file and a target over a private
network and reads the output back. It never calls out to the backend, so a
compromised runner has nothing to call.

What protects the rest of the system, in order of how much it matters:

  1. Network. This container sits on `sandbox-net` only. Postgres, Redis and
     the backend's secrets live on `syphax-net`, which it is not attached to.
     No route, not a firewall rule - it cannot address them at all.
  2. No secrets. No env_file, no /data mount. The environment holds nothing
     worth stealing, which is the usual objective of a trojaned PoC.
  3. Egress. entrypoint.sh (as root) builds the jail; this process rewrites the
     SYPHAX_EGRESS chain from the scope the backend sends with each request, and
     flushes it back to deny-all afterwards. The allowlist used to be applied
     once at boot from SANDBOX_ALLOWED_HOSTS, which is empty in every normal
     install - so the sandbox denied every outbound packet while reporting
     itself healthy, and every PoC "failed" against a firewall.
  4. Privilege. This process keeps root and CAP_NET_ADMIN, because setting the
     allowlist needs it. The PoC does not: it is spawned through `gosu poc`, and
     an iptables owner-match rule rejects anything from that uid to this port,
     so a PoC cannot ask the runner to widen its own jail. /v1/run additionally
     requires SANDBOX_RUNNER_TOKEN, which is never put in the PoC environment.
  5. Execution limits. Unprivileged PoC, tmpfs workdir, wall-clock timeout,
     output cap.

The runner does NOT decide whether code is safe to run. That judgment happened
upstream: inspection, operator review, approval. By the time anything gets
here, a human has read it and said yes.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import pwd
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger("syphax.sandbox.runner")

app = FastAPI(title="syphax sandbox runner", version="1.0.0")

# The token the backend authenticates with. Set by compose, shared with the
# backend only. Not a secret worth stealing - it grants "run code in a box that
# already runs code" - but it stops anything else on the network driving it.
#
# It was read here and then never checked by any endpoint, never set by compose
# and never sent by the backend - so it authenticated nothing. It is enforced
# now (see _authenticate), because this process holds CAP_NET_ADMIN.
RUNNER_TOKEN = os.environ.get("SANDBOX_RUNNER_TOKEN", "")

# The unprivileged account each PoC is spawned under.
POC_USER = os.environ.get("SANDBOX_POC_USER", "poc")

# The chain entrypoint.sh created for us, jumped to from OUTPUT just before the
# final REJECT. Empty at rest; one request's scope at a time.
EGRESS_CHAIN = "SYPHAX_EGRESS"
EGRESS_MODE_FILE = Path("/run/egress.mode")
EGRESS_LOCK_FILE = Path("/run/egress.locked")

# One PoC at a time. The allowlist is a single kernel chain, so two concurrent
# runs would each see the other's scope - which is both wrong and a scope
# violation. Serialising here is the honest fix.
_RUN_LOCK = asyncio.Lock()

MAX_TIMEOUT = int(os.environ.get("SANDBOX_MAX_TIMEOUT", "120"))
MAX_OUTPUT = int(os.environ.get("SANDBOX_MAX_OUTPUT", "64000"))
WORKDIR = Path(os.environ.get("SANDBOX_WORKDIR", "/work"))

INTERPRETERS = {
    "python": ["python3", "-I"],   # -I: ignore env vars and user site-packages
    "bash": ["bash"],
    "javascript": ["node"],
}


class RunRequest(BaseModel):
    code: str
    language: str = "python"
    argv: List[str] = Field(default_factory=list)
    timeout: int = 60
    # The engagement scope. ENFORCED: these hosts are resolved and written into
    # the SYPHAX_EGRESS chain for the duration of this request, and the chain is
    # flushed back to deny-all afterwards. Nothing else is reachable.
    scope_hosts: List[str] = Field(default_factory=list)


def _iptables(binary: str, *args: str) -> Tuple[int, str]:
    """Run one iptables command. Returns (returncode, stderr)."""
    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True,
                              timeout=15)
    except FileNotFoundError:
        return 127, f"{binary} not found"
    except subprocess.TimeoutExpired:
        return 124, f"{binary} timed out"
    return proc.returncode, (proc.stderr or "").strip()


def _resolve(host: str) -> Tuple[List[str], List[str]]:
    """Addresses for one scope entry -> (v4, v6). A literal resolves to itself.

    A wildcard entry like `*.example.com` has no address of its own; the caller
    is expected to have expanded it into concrete hosts. We strip the label so
    `*.example.com` at least pins the apex rather than resolving nothing.
    """
    entry = (host or "").strip().lower()
    if entry.startswith("*."):
        entry = entry[2:]
    if not entry:
        return [], []
    try:
        addr = ipaddress.ip_address(entry)
        return ([str(addr)], []) if addr.version == 4 else ([], [str(addr)])
    except ValueError:
        pass
    v4: List[str] = []
    v6: List[str] = []
    try:
        for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(
                entry, None, proto=socket.IPPROTO_TCP):
            ip = sockaddr[0]
            if family == socket.AF_INET6:
                v6.append(ip)
            else:
                v4.append(ip)
    except OSError:
        return [], []
    return sorted(set(v4)), sorted(set(v6))


def _flush_egress() -> None:
    """Back to deny-all. Called after every run, including a failed one."""
    _iptables("iptables", "-F", EGRESS_CHAIN)
    _iptables("ip6tables", "-F", EGRESS_CHAIN)


def _apply_egress(hosts: Sequence[str]) -> Dict[str, Any]:
    """Pin outbound traffic to `hosts` for the next run.

    Resolution happens HERE, once, and the addresses are what the kernel
    enforces - so a DNS rebind after this point cannot move the allowlist. The
    PoC is free to resolve the name again and get something else; it will not
    be able to reach it.
    """
    rc, err = _iptables("iptables", "-F", EGRESS_CHAIN)
    if rc != 0:
        raise HTTPException(
            status_code=503,
            detail=f"cannot write the egress allowlist ({err or rc}). The runner "
                   f"needs CAP_NET_ADMIN and the {EGRESS_CHAIN} chain that "
                   f"entrypoint.sh creates.")
    _iptables("ip6tables", "-F", EGRESS_CHAIN)

    applied: List[str] = []
    unresolved: List[str] = []
    for host in hosts:
        v4, v6 = _resolve(host)
        if not v4 and not v6:
            unresolved.append(host)
            continue
        for ip in v4:
            rc, err = _iptables("iptables", "-A", EGRESS_CHAIN, "-d", ip,
                                "-j", "ACCEPT")
            if rc == 0:
                applied.append(ip)
        for ip in v6:
            rc, _err = _iptables("ip6tables", "-A", EGRESS_CHAIN, "-d", ip,
                                 "-j", "ACCEPT")
            if rc == 0:
                applied.append(ip)

    if not applied:
        # Running now would mean running with deny-all, which is the failure the
        # operator used to see reported as "the exploit did not work".
        _flush_egress()
        raise HTTPException(
            status_code=400,
            detail="none of the scope hosts resolved to an address, so egress "
                   f"would deny everything: {', '.join(hosts) or '(empty)'}. "
                   "Nothing was run - this is a scope/DNS problem, not a failed "
                   "exploit.")
    return {"allowed_ips": applied, "unresolved": unresolved}


def _current_allowlist() -> List[str]:
    """What the kernel has in the chain right now. For /health."""
    out: List[str] = []
    try:
        proc = subprocess.run(["iptables", "-S", EGRESS_CHAIN],
                              capture_output=True, text=True, timeout=10)
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            if "-d" in parts:
                out.append(parts[parts.index("-d") + 1])
    except Exception:  # noqa: BLE001 - /health must never raise
        return []
    return out


def _egress_mode() -> str:
    try:
        return EGRESS_MODE_FILE.read_text().strip() or "boot"
    except OSError:
        return "boot"


def _authenticate(token: Optional[str]) -> None:
    """Reject anything on the network that is not the backend.

    A no-op when no token is configured, which keeps an existing deployment
    working - but the backend sets one, and without it the only thing standing
    between a PoC and this endpoint is the iptables owner-match rule.
    """
    if not RUNNER_TOKEN:
        return
    supplied = (token or "").strip()
    if supplied.lower().startswith("bearer "):
        supplied = supplied[7:].strip()
    if not supplied or not _constant_eq(supplied, RUNNER_TOKEN):
        raise HTTPException(status_code=401, detail="bad or missing runner token")


def _constant_eq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


def _poc_ids() -> Optional[Tuple[int, int]]:
    try:
        entry = pwd.getpwnam(POC_USER)
        return entry.pw_uid, entry.pw_gid
    except KeyError:
        return None


def _effective_user() -> str:
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:  # noqa: BLE001 - a missing passwd entry is not fatal
        return f"uid:{os.geteuid()}"


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "egress_locked": EGRESS_LOCK_FILE.exists(),
        # "per-request" means this runner takes the scope from each request.
        # Anything else is an image built before that change, which would deny
        # every outbound packet while still answering "ok" here - so the backend
        # checks this key and refuses rather than blaming the exploit.
        "egress_mode": _egress_mode(),
        # Off the event loop: this shells out to iptables and the backend calls
        # /health before every single run.
        "egress_allowlist": await asyncio.to_thread(_current_allowlist),
        "auth_required": bool(RUNNER_TOKEN),
        "poc_user": POC_USER,
        "clients": _available_clients(),
        # The REAL effective user, not the USER env var: gosu does not set it,
        # so this always answered "unknown" - useless for the one question it
        # exists to answer, which is whether untrusted code is about to run as
        # root.
        "user": _effective_user(),
        "uid": os.geteuid(),
    }


@app.post("/run")
async def run(req: RunRequest, authorization: str = "") -> Dict[str, Any]:
    raise HTTPException(status_code=501, detail="use /v1/run")


def _available_clients() -> Dict[str, bool]:
    """Which HTTP clients a PoC can actually use. Reported by /health.

    The image shipped without any of them while the authoring prompt promised
    `requests` and curl, so every authored exploit died on ModuleNotFoundError
    and the operator was told the exploit had failed. Surfaced so that can
    never be invisible again.
    """
    import importlib.util
    return {
        "python_requests": importlib.util.find_spec("requests") is not None,
        "curl": shutil.which("curl") is not None,
        "node": shutil.which("node") is not None,
    }


@app.post("/v1/run")
async def run_v1(req: RunRequest,
                 x_sandbox_token: str = Header(default="")) -> Dict[str, Any]:
    _authenticate(x_sandbox_token)

    if req.language not in INTERPRETERS:
        raise HTTPException(status_code=400,
                            detail=f"language must be one of {sorted(INTERPRETERS)}")
    if not (req.code or "").strip():
        raise HTTPException(status_code=400, detail="empty code")

    hosts = [h.strip() for h in (req.scope_hosts or []) if (h or "").strip()]
    if not hosts:
        # Without a scope there is nothing to pin egress to, and "run this
        # against anything" is never what an engagement authorises.
        raise HTTPException(status_code=400,
                            detail="scope_hosts is required: refusing to run "
                                   "untrusted code with no egress allowlist")

    timeout = max(1, min(int(req.timeout or 60), MAX_TIMEOUT))
    suffix = {"python": ".py", "bash": ".sh", "javascript": ".js"}[req.language]

    WORKDIR.mkdir(parents=True, exist_ok=True)

    # One at a time: the allowlist is one kernel chain, so a concurrent run
    # would execute under the other engagement's scope.
    async with _RUN_LOCK:
        egress = _apply_egress(hosts)
        tmpdir = tempfile.mkdtemp(dir=str(WORKDIR))
        started = time.time()
        try:
            path = Path(tmpdir) / f"poc{suffix}"
            path.write_text(req.code)

            # The PoC runs as `poc`, this process as root, so hand over the
            # directory it has to read the script from and write scratch into.
            ids = _poc_ids()
            if ids is not None:
                uid, gid = ids
                os.chown(tmpdir, uid, gid)
                os.chown(path, uid, gid)
                os.chmod(tmpdir, 0o700)
                os.chmod(path, 0o500)

            # De-privilege the PoC, not the server. The server keeps
            # CAP_NET_ADMIN so it can set the allowlist above; `gosu poc` means
            # the untrusted code holds nothing, and the owner-match rule
            # entrypoint.sh installed stops it reaching this endpoint to ask for
            # a wider one.
            cmd = INTERPRETERS[req.language] + [str(path)] + [str(a) for a in req.argv]
            if ids is not None and shutil.which("gosu"):
                cmd = ["gosu", POC_USER, *cmd]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=tmpdir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # A minimal environment: nothing inherited that could leak, and
                # nothing to harvest. SANDBOX_RUNNER_TOKEN in particular is NOT
                # in here, so a PoC cannot authenticate to /v1/run even if it
                # found a route to the port.
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": tmpdir,
                     "LANG": "C.UTF-8"},
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                timed_out = False
            except asyncio.TimeoutError:
                proc.kill()
                out, err = b"", b""
                timed_out = True

            return {
                "exit_code": None if timed_out else proc.returncode,
                "timed_out": timed_out,
                "duration_s": round(time.time() - started, 2),
                "stdout": out.decode("utf-8", errors="replace")[:MAX_OUTPUT],
                "stderr": err.decode("utf-8", errors="replace")[:MAX_OUTPUT],
                "scope_hosts": hosts,
                "egress_locked": EGRESS_LOCK_FILE.exists(),
                # What the kernel actually enforced, so a run that could not
                # reach the target is distinguishable from an exploit that did
                # not work.
                "egress_allowed_ips": egress.get("allowed_ips", []),
                "egress_unresolved": egress.get("unresolved", []),
            }
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
            # Deny-all at rest. An idle container must not be a usable proxy.
            _flush_egress()
