"""Route scan traffic through a VPN or proxy, and refuse to scan when the exit
IP is still your own.

Three mechanisms, all optional:

  SOCKS5 / HTTP proxy   No privileges. Exported to the tool subprocesses as
                        HTTP_PROXY/HTTPS_PROXY plus per-tool flags, and works
                        with Tor out of the box (socks5://127.0.0.1:9050).

  WireGuard             `wg-quick up <config>`. The backend container already
                        has cap_add: NET_ADMIN, so this works in compose; the
                        worker and orchestrator containers do not, which is
                        why the tunnel is brought up host- or backend-side and
                        the kill switch is what protects the workers.

  OpenVPN               `openvpn --config <file> --daemon`. Same caveat.

The part that actually matters is the kill switch. verify_exit_ip() compares
the current public IP against the one recorded before the tunnel came up. If
they match, traffic is not going through the tunnel and submit() refuses to
queue the job. A tunnel that drops silently mid-engagement is the failure mode
this exists to catch.

On "free VPN": most free providers log, share exit IPs between users, and get
their ranges blocklisted. That last one is not just a privacy problem - the
target blocks the range before your payload lands and you record a false
negative. Bring a WireGuard config you trust; any provider's works, including
ProtonVPN's free tier.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
import shutil
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings

app_settings = settings   # alias used by the config-path helpers below

logger = logging.getLogger("syphax.network.privacy")

# Several services, because any single one can be down or blocked from the
# exit node. First usable answer wins.
IP_CHECK_URLS = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/all.json",
    "https://icanhazip.com",
]

MODE_OFF = "off"
MODE_PROXY = "proxy"
MODE_WIREGUARD = "wireguard"
MODE_OPENVPN = "openvpn"

_VALID_PROXY_SCHEMES = ("socks5://", "socks5h://", "socks4://", "http://", "https://")

# Where prepared configs land. tmpfs in compose, so a config carrying a private
# key never lands on a disk that outlives the container.
PREPARED_DIR = "/tmp/syphax-wg"

# wg-quick derives the interface name from the filename, and the kernel caps it.
WG_IFACE_MAX = 15


def config_roots() -> list:
    """Directories a VPN config may be read from.

    config_path arrives in an API request body and is handed to wg-quick, so it
    is confined to the operator's own data dir (and whatever VPN_CONFIG_PATH
    points at, which the operator set themselves in .env).
    """
    roots = [str(Path(app_settings.data_dir).resolve())]
    configured = (app_settings.vpn_config_path or "").strip()
    if configured:
        roots.append(str(Path(configured).resolve().parent))
    return roots


def config_path_allowed(config_path: str, roots: Optional[list] = None) -> bool:
    """True if config_path resolves inside one of the allowed roots.

    Resolving first defeats ../ traversal and symlinks that point elsewhere.
    """
    if not config_path:
        return False
    try:
        target = Path(config_path).resolve()
    except (OSError, RuntimeError):
        return False
    for root in (roots if roots is not None else config_roots()):
        try:
            target.relative_to(Path(root).resolve())
            return True
        except (ValueError, OSError):
            continue
    return False


def prepare_wg_config(config_path: str, *, dest_dir: str = PREPARED_DIR) -> str:
    """Rewrite a provider's WireGuard config into one a container can use.

    Two things in a stock provider config break inside Docker, and both fail in
    ways that point at the wrong culprit.

    1. `DNS = 10.2.0.1`. wg-quick applies it, replacing the container's resolver
       (127.0.0.11, Docker's embedded DNS). The backend then cannot resolve
       `postgres` or `redis` by name, so the whole application falls over the
       moment the tunnel comes up - and it looks like a database outage, not a
       VPN problem. The line is dropped: name resolution stays on Docker's
       resolver, while traffic still exits through the tunnel.

    2. The filename becomes the interface name, and the kernel refuses anything
       over 15 characters or containing a dot. ProtonVPN ships files like
       `ch-fr-01.protonvpn.udp.conf`, which wg-quick rejects with "invalid
       interface name" - easy to read as a malformed config. The copy is named
       `wg0.conf`.

    Returns the path to the prepared copy; the original is never modified.
    """
    import re as _re

    with open(config_path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()

    # wg-quick runs PreUp/PostUp/PreDown/PostDown as root, and Table can reroute
    # everything. A config path reaches us from an API request body, so these are
    # refused outright rather than copied through: a tunnel definition has no
    # business executing commands.
    hooks = [ln.strip() for ln in lines
             if _re.match(r"^\s*(PreUp|PostUp|PreDown|PostDown|Table)\s*=", ln, _re.I)]
    if hooks:
        raise ValueError(
            "refusing this WireGuard config: it defines "
            + ", ".join(sorted({h.split("=")[0].strip() for h in hooks}))
            + " which wg-quick executes as root. Remove those lines."
        )

    kept, dropped = [], []
    for line in lines:
        if _re.match(r"^\s*DNS\s*=", line, _re.I):
            dropped.append(line.strip())
            continue
        kept.append(line)

    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    dest = os.path.join(dest_dir, "wg0.conf")
    header = [
        "# Prepared by Syphax from " + os.path.basename(config_path),
        "# DNS lines removed so Docker's resolver keeps working; traffic still",
        "# exits through the tunnel. Original left untouched.",
    ]
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write("\n".join(header + kept) + "\n")
    os.chmod(dest, 0o600)   # carries a private key

    if dropped:
        logger.info("prepared %s: dropped %d DNS line(s)", config_path, len(dropped))
    return dest


@dataclass
class NetworkState:
    mode: str = MODE_OFF
    connected: bool = False
    baseline_ip: Optional[str] = None   # real IP, recorded before any tunnel
    current_ip: Optional[str] = None
    proxy_url: Optional[str] = None
    config_path: Optional[str] = None
    last_error: Optional[str] = None
    checked_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "connected": self.connected,
            "baseline_ip": self.baseline_ip,
            "current_ip": self.current_ip,
            "ip_changed": bool(
                self.baseline_ip and self.current_ip and self.baseline_ip != self.current_ip
            ),
            "proxy_url": self.redacted_proxy(),
            "config_path": self.config_path,
            "last_error": self.last_error,
            "checked_at": self.checked_at,
        }

    def redacted_proxy(self) -> Optional[str]:
        """Never echo proxy credentials back to the API"""
        if not self.proxy_url:
            return None
        if "@" in self.proxy_url:
            scheme, _, rest = self.proxy_url.partition("://")
            _, _, host = rest.rpartition("@")
            return f"{scheme}://***@{host}"
        return self.proxy_url


class NetworkPrivacyManager:
    def __init__(self) -> None:
        self.state = NetworkState()
        if settings.scan_proxy:
            # Configured in .env: adopt it without waiting for an API call.
            self.state.mode = MODE_PROXY
            self.state.proxy_url = settings.scan_proxy

    # ---- Public IP ----

    async def get_public_ip(self, through_proxy: bool = True) -> Optional[str]:
        proxy = self.state.proxy_url if (through_proxy and self.state.mode == MODE_PROXY) else None
        try:
            async with httpx.AsyncClient(timeout=15.0, proxy=proxy) as client:
                for url in IP_CHECK_URLS:
                    try:
                        resp = await client.get(url)
                        if resp.status_code != 200:
                            continue
                        text = resp.text.strip()
                        if text.startswith("{"):
                            data = json.loads(text)
                            ip = data.get("ip") or data.get("ip_addr")
                            if ip:
                                return str(ip).strip()
                        elif text:
                            return text
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("ip check via %s failed: %s", url, exc)
                        continue
        except Exception as exc:  # noqa: BLE001 - bad proxy URL, unreachable, ...
            logger.warning("ip check client failed: %s", exc)
        return None

    async def record_baseline(self) -> Optional[str]:
        """Record the real IP, bypassing any proxy, to compare against later"""
        ip = await self.get_public_ip(through_proxy=False)
        self.state.baseline_ip = ip
        logger.info("baseline IP recorded: %s", ip)
        return ip

    async def verify_exit_ip(self) -> Dict[str, Any]:
        """Kill switch check: is traffic really leaving through the tunnel?"""
        current = await self.get_public_ip()
        self.state.current_ip = current
        self.state.checked_at = time.time()

        if self.state.mode == MODE_OFF:
            return {
                "safe": True,
                "reason": "no VPN requested, scanning from the local IP",
                "current_ip": current,
            }

        if not current:
            self.state.last_error = "could not determine the public IP"
            return {
                "safe": False,
                "reason": "public IP unreadable, cannot confirm the tunnel is up",
                "current_ip": None,
            }

        if not self.state.baseline_ip:
            # Without a pre-VPN reading there is nothing to compare against, so
            # we cannot show the tunnel changed anything. record_baseline() is
            # best-effort at startup; a silent failure there used to make this
            # return safe=True and let REQUIRE_VPN scans through unverified.
            self.state.last_error = "no pre-VPN baseline recorded"
            return {
                "safe": False,
                "reason": "no pre-VPN baseline to compare against; cannot confirm "
                          "the tunnel changed the exit IP",
                "current_ip": current,
                "baseline_ip": None,
            }

        if current == self.state.baseline_ip:
            self.state.last_error = "exit IP equals the pre-VPN IP"
            return {
                "safe": False,
                "reason": f"traffic is NOT going through the tunnel (still {current})",
                "current_ip": current,
                "baseline_ip": self.state.baseline_ip,
            }

        self.state.last_error = None
        return {
            "safe": True,
            "reason": f"traffic exits via {current}",
            "current_ip": current,
            "baseline_ip": self.state.baseline_ip,
        }

    # ---- Proxy ----

    async def set_proxy(self, proxy_url: str) -> Dict[str, Any]:
        proxy_url = (proxy_url or "").strip()
        if not proxy_url:
            return {"ok": False, "error": "empty proxy URL"}
        if not proxy_url.startswith(_VALID_PROXY_SCHEMES):
            return {
                "ok": False,
                "error": f"proxy must start with one of {', '.join(_VALID_PROXY_SCHEMES)}",
            }

        if not self.state.baseline_ip:
            await self.record_baseline()

        previous_mode, previous_proxy = self.state.mode, self.state.proxy_url
        self.state.mode = MODE_PROXY
        self.state.proxy_url = proxy_url

        check = await self.verify_exit_ip()
        self.state.connected = check["safe"]
        if not check["safe"]:
            self.state.mode, self.state.proxy_url = previous_mode, previous_proxy
            return {"ok": False, "error": check["reason"], **self.state.to_dict()}

        return {"ok": True, **self.state.to_dict()}

    # ---- VPN ----

    async def connect_vpn(self, config_path: str, mode: str = MODE_WIREGUARD) -> Dict[str, Any]:
        if not config_path_allowed(config_path):
            return {"ok": False, "error":
                    f"config must live under one of {config_roots()}; "
                    f"refusing {config_path}"}
        if not os.path.isfile(config_path):
            return {"ok": False, "error": f"config not found: {config_path}"}

        # Provider configs are written for a laptop, not a container. Prepare a
        # corrected copy rather than asking the operator to hand-edit the file
        # their provider generated. See prepare_wg_config for what and why.
        if mode == MODE_WIREGUARD:
            try:
                config_path = prepare_wg_config(config_path)
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": f"could not prepare the config: {exc}"}

        binary = "wg-quick" if mode == MODE_WIREGUARD else "openvpn"
        if not shutil.which(binary):
            return {
                "ok": False,
                "error": f"{binary} is not installed in this container. "
                         f"Use proxy mode, which needs no privileges, or bring the "
                         f"tunnel up on the host.",
            }

        if not self.state.baseline_ip:
            await self.record_baseline()

        cmd: List[str] = (
            ["wg-quick", "up", config_path] if mode == MODE_WIREGUARD
            else ["openvpn", "--config", config_path, "--daemon"]
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
            if proc.returncode != 0:
                err = (stderr or b"").decode(errors="replace")[:300]
                self.state.last_error = err
                return {"ok": False, "error": f"{binary} failed: {err}"}
        except asyncio.TimeoutError:
            return {"ok": False, "error": f"{binary} timed out after 45s"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

        self.state.mode = mode
        self.state.config_path = config_path

        # Let the tunnel settle before reading the exit IP
        await asyncio.sleep(3)
        check = await self.verify_exit_ip()
        self.state.connected = check["safe"]
        if not check["safe"]:
            return {"ok": False, "error": check["reason"], **self.state.to_dict()}

        return {"ok": True, **self.state.to_dict()}

    async def disconnect(self) -> Dict[str, Any]:
        if self.state.mode == MODE_WIREGUARD and self.state.config_path:
            await self._run_quiet(["wg-quick", "down", self.state.config_path], 30)
        elif self.state.mode == MODE_OPENVPN:
            await self._run_quiet(["pkill", "-f", "openvpn --config"], 15)

        baseline = self.state.baseline_ip
        self.state = NetworkState(baseline_ip=baseline)
        self.state.current_ip = await self.get_public_ip(through_proxy=False)
        return {"ok": True, **self.state.to_dict()}

    @staticmethod
    async def _run_quiet(cmd: List[str], timeout: int) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            logger.warning("%s failed: %s", cmd[0], exc)

    # ---- Used by the scan path ----

    def proxy_for_tools(self) -> Optional[str]:
        """Proxy URL to hand to tool subprocesses, or None"""
        if self.state.mode == MODE_PROXY and self.state.proxy_url:
            return self.state.proxy_url
        return None

    async def guard_scan(self) -> Dict[str, Any]:
        """
        Called before any job is queued.

        With require_vpn on, a scan is refused unless the exit IP is confirmed
        different from the baseline. This is what stops a dropped tunnel from
        silently leaking the real IP in the middle of an engagement.
        """
        if not settings.require_vpn:
            return {"allowed": True, "reason": "require_vpn is off"}

        if self.state.mode == MODE_OFF:
            return {
                "allowed": False,
                "reason": "REQUIRE_VPN is on but no VPN or proxy is configured",
            }

        check = await self.verify_exit_ip()
        return {
            "allowed": check["safe"],
            "reason": check["reason"],
            "current_ip": check.get("current_ip"),
        }


_manager: Optional[NetworkPrivacyManager] = None


def get_network_manager() -> NetworkPrivacyManager:
    global _manager
    if _manager is None:
        _manager = NetworkPrivacyManager()
    return _manager
