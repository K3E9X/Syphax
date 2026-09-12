"""wpscan: WordPress-specific scanner (plugins, themes, users, CVEs).

Without a WPScan API token the scanner still detects installed plugins /
themes / users, enumerates the WP version, and flags common misconfigs,
but the CVE database lookup is skipped. Users can set WPSCAN_API_TOKEN
in .env (25 free requests/day per address on wpscan.com) to enable it.
"""
from __future__ import annotations

import json
import os
from typing import List, Sequence

from app.cve_refs import normalize_cve
from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


class WpscanWrapper(BaseWrapper):
    name = "wpscan"
    binary = "wpscan"
    description = "WordPress scanner: plugins, themes, users, vulnerabilities."
    category = "cms"
    timeout_seconds = 30 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "--url", target,
            "--format", "json",
            "--no-banner",
            "--disable-tls-checks",
            # vulnerable plugins/themes, timthumbs, config backups, DB exports,
            # users, media - the full high-value enumeration set.
            "--enumerate", "vp,vt,tt,cb,dbe,u,m",
            "--plugins-detection", "mixed",
        ]
        token = os.environ.get("WPSCAN_API_TOKEN")
        if token:
            cmd.extend(["--api-token", token])
        # In rotate mode let wpscan do its own per-request rotation; in fixed
        # mode identity_args() supplies an explicit --user-agent instead. Both
        # flags together conflict, so it is one or the other.
        from app.scans.identity import MODE_ROTATE
        from app.config import settings as _settings
        if (_settings.user_agent_mode or "").strip().lower() == MODE_ROTATE:
            cmd.append("--random-user-agent")
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        text = stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return ToolResult(findings=findings)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ToolResult(findings=findings)

        if not isinstance(data, dict):
            return ToolResult(findings=findings)

        # WP core version + its vulns
        wp = data.get("version") or {}
        wp_version = wp.get("number")
        if wp_version:
            for vuln in wp.get("vulnerabilities") or []:
                findings.append(_wp_vuln_finding(vuln, target, f"WordPress core {wp_version}"))

        # Plugins
        for name, plugin in (data.get("plugins") or {}).items():
            version = (plugin.get("version") or {}).get("number") or "unknown"
            # One finding per plugin (info), plus one per vuln on that plugin.
            findings.append(
                Finding(
                    severity="info",
                    title=f"Plugin installed: {name} {version}",
                    description=plugin.get("location") or "",
                    target=target,
                    evidence=f"plugin={name} version={version}",
                    metadata={
                        "plugin": name,
                        "version": version,
                        "outdated": plugin.get("outdated"),
                    },
                )
            )
            for vuln in plugin.get("vulnerabilities") or []:
                findings.append(_wp_vuln_finding(vuln, target, f"Plugin {name} {version}"))

        # Themes
        for name, theme in (data.get("themes") or {}).items():
            version = (theme.get("version") or {}).get("number") or "unknown"
            findings.append(
                Finding(
                    severity="info",
                    title=f"Theme installed: {name} {version}",
                    description=theme.get("location") or "",
                    target=target,
                    evidence=f"theme={name} version={version}",
                    metadata={"theme": name, "version": version},
                )
            )
            for vuln in theme.get("vulnerabilities") or []:
                findings.append(_wp_vuln_finding(vuln, target, f"Theme {name} {version}"))

        # Enumerated users
        for login, user in (data.get("users") or {}).items():
            findings.append(
                Finding(
                    severity="low",
                    title=f"WordPress user enumerated: {login}",
                    description="Username disclosed by the WordPress installation.",
                    target=target,
                    evidence=f"login={login}",
                    metadata={"login": login, "id": user.get("id")},
                )
            )

        # Exposed config backups (wp-config.php~ / .bak): frequently leak DB
        # credentials and secret keys -> treat as high-value exposures.
        for url in (data.get("config_backups") or {}):
            findings.append(
                Finding(
                    severity="high",
                    title="WordPress config backup exposed",
                    description="A wp-config backup is publicly readable and may leak "
                                "database credentials and secret keys.",
                    target=url,
                    evidence=f"config backup: {url}",
                    metadata={"vuln_class": "exposed_resource", "url": url},
                )
            )

        # Exposed database exports (.sql dumps): direct data breach.
        for url in (data.get("db_exports") or {}):
            findings.append(
                Finding(
                    severity="high",
                    title="WordPress database export exposed",
                    description="A database export (SQL dump) is publicly readable, "
                                "exposing application data directly.",
                    target=url,
                    evidence=f"db export: {url}",
                    metadata={"vuln_class": "exposed_resource", "url": url},
                )
            )

        return ToolResult(findings=findings)


def _first_cve_id(cves) -> "str | None":
    """wpscan lists CVEs bare ("2021-24741"); normalize_cve wants the full id."""
    for c in cves or []:
        raw = str(c).strip()
        got = normalize_cve(raw if raw.upper().startswith("CVE-") else f"CVE-{raw}")
        if got:
            return got
    return None


def _wp_vuln_finding(vuln: dict, target: str, component: str) -> Finding:
    title = vuln.get("title") or "WordPress vulnerability"
    refs = vuln.get("references") or {}
    cves = refs.get("cve") or []
    url_refs = refs.get("url") or []
    fixed_in = vuln.get("fixed_in")
    # wpscan does not always set a severity; default to high for a known CVE,
    # medium otherwise. Users can re-prioritize in the UI.
    severity = "high" if cves else "medium"
    return Finding(
        severity=severity,
        title=f"{component}: {title}",
        description=vuln.get("description") or "",
        target=target,
        evidence=(
            f"cve={','.join(cves)} fixed_in={fixed_in or 'n/a'} "
            f"refs={','.join(url_refs[:3])}"
        ),
        metadata={
            "component": component,
            "cve": cves,
            # Consumers (analysis/public_exploits.py, exploit/known.py) read
            # "cve_id" as a normalised string, like nuclei and nmap emit. Without
            # it every CVE wpscan finds was silently skipped for enrichment.
            **({"cve_id": _first_cve_id(cves)} if _first_cve_id(cves) else {}),
            "fixed_in": fixed_in,
            "references": url_refs,
            "wpvulndb_id": vuln.get("id"),
        },
    )
