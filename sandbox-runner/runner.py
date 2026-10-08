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
  3. Egress. entrypoint.sh (as root) pins iptables to the engagement scope,
     then drops to an unprivileged user. The PoC runs as `poc`, so it cannot
     undo the rules that contain it.
  4. Execution limits. Non-root, read-only root filesystem, tmpfs workdir,
     wall-clock timeout, output cap.

The runner does NOT decide whether code is safe to run. That judgment happened
upstream: inspection, operator review, approval. By the time anything gets
here, a human has read it and said yes.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="syphax sandbox runner", version="1.0.0")

# The token the backend authenticates with. Set by compose, shared with the
# backend only. Not a secret worth stealing - it grants "run code in a box that
# already runs code" - but it stops anything else on the network driving it.
RUNNER_TOKEN = os.environ.get("SANDBOX_RUNNER_TOKEN", "")

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
    # Informational: the egress allowlist is applied by entrypoint.sh at boot,
    # not per request. Echoed back so the caller can record what was in force.
    scope_hosts: List[str] = Field(default_factory=list)


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
        "egress_locked": Path("/run/egress.locked").exists(),
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


@app.post("/v1/run")
async def run_v1(req: RunRequest) -> Dict[str, Any]:
    if req.language not in INTERPRETERS:
        raise HTTPException(status_code=400,
                            detail=f"language must be one of {sorted(INTERPRETERS)}")
    if not (req.code or "").strip():
        raise HTTPException(status_code=400, detail="empty code")

    timeout = max(1, min(int(req.timeout or 60), MAX_TIMEOUT))
    suffix = {"python": ".py", "bash": ".sh", "javascript": ".js"}[req.language]

    WORKDIR.mkdir(parents=True, exist_ok=True)
    tmpdir = tempfile.mkdtemp(dir=str(WORKDIR))
    started = time.time()
    try:
        path = Path(tmpdir) / f"poc{suffix}"
        path.write_text(req.code)

        cmd = INTERPRETERS[req.language] + [str(path)] + [str(a) for a in req.argv]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=tmpdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # A minimal environment: nothing inherited that could leak, and
            # nothing to harvest.
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
            "scope_hosts": req.scope_hosts,
            "egress_locked": Path("/run/egress.locked").exists(),
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
