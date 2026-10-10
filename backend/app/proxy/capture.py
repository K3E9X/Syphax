"""Where the MITM capture proxy listens, from the worker's point of view.

The traffic-driven analysers - IDOR and BFLA, broken access control, JWT,
secrets in JavaScript bundles - all read FlowRepository. Nothing routed tool
traffic through the capture proxy, so on an automated run that table was empty
and every one of them ran against nothing. They were in the run; they had no
input.

The proxy container runs with `network_mode: service:backend`, so it shares
the backend's network namespace and is reached at the backend's address on
MITM_PORT - not at a hostname of its own. Getting that wrong would route the
crawl into a black hole, so it is read from the environment with a default
that matches docker-compose.yml rather than guessed per call site.
"""
from __future__ import annotations

import os
import socket

# Set CAPTURE_PROXY_URL to override, or CAPTURE_PROXY=off to disable.
_ENV_URL = "CAPTURE_PROXY_URL"
_ENV_OFF = "CAPTURE_PROXY"


def capture_proxy_url() -> str:
    """The proxy URL to hand a tool, or "" when capture is off or unreachable."""
    if (os.environ.get(_ENV_OFF, "") or "").strip().lower() in ("off", "0", "false"):
        return ""
    url = (os.environ.get(_ENV_URL, "") or "").strip()
    if not url:
        host = (os.environ.get("CAPTURE_PROXY_HOST", "") or "backend").strip()
        port = (os.environ.get("MITM_PORT", "") or "8080").strip()
        url = f"http://{host}:{port}"
    return url if _reachable(url) else ""


def _reachable(url: str, timeout: float = 1.5) -> bool:
    """A TCP connect. Adding a proxy flag for a port nothing listens on would
    make every crawl fail - which is the failure mode this whole session has
    been chasing, so it is checked rather than assumed."""
    try:
        rest = url.split("://", 1)[1]
        host, _, port = rest.partition(":")
        with socket.create_connection((host, int(port or 8080)), timeout):
            return True
    except Exception:  # noqa: BLE001 - unreachable is a normal state
        return False
