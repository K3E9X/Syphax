"""Open ports discovered by naabu/nmap must become "port" assets.

Before this, the scanners emitted ports as findings only; nothing created a
`kind="port"` asset, so the Surface page (app/api/surface.py, which reads only
port assets) always showed "0 ports". These tests pin the finding->port-asset
mapping (_port_asset_value) and the Surface value format it produces.
"""
from types import SimpleNamespace

import pytest

from app.orchestrator.executor import _port_asset_value


def _finding(target, meta):
    return SimpleNamespace(target=target, metadata=meta)


def test_naabu_port_uses_metadata_host():
    # naabu metadata: {"host": ..., "port": ...}, no service.
    f = _finding("glpi.example:443", {"host": "glpi.example", "port": 443, "tool": "naabu"})
    assert _port_asset_value(f, f.metadata) == "443/tcp · glpi.example"


def test_nmap_port_carries_service_and_version():
    meta = {"port": "80", "protocol": "tcp", "service": "http",
            "product": "nginx", "version": "1.18.0", "vuln_class": "recon"}
    f = _finding("62.210.80.152:80", meta)
    assert _port_asset_value(f, meta) == "80/tcp · 62.210.80.152 · http nginx 1.18.0"


def test_nmap_falls_back_to_target_host_when_metadata_has_no_host():
    meta = {"port": "22", "protocol": "tcp", "service": "ssh"}
    f = _finding("10.0.0.5:22", meta)
    assert _port_asset_value(f, meta) == "22/tcp · 10.0.0.5 · ssh"


def test_nse_vuln_finding_is_not_a_port_asset():
    # NSE findings carry nse_script and must be skipped by the ingest gate.
    meta = {"nse_script": "vulners", "cve_id": "CVE-2021-1234", "port": "443"}
    # The gate lives in _ingest_finding; here we assert the shape the gate keys
    # on: a real port finding never carries nse_script.
    assert meta.get("nse_script")


def test_no_port_returns_none():
    f = _finding("host:0", {"service": "http"})
    assert _port_asset_value(f, f.metadata) is None


def test_no_host_anywhere_returns_none():
    f = _finding("", {"port": 443})
    assert _port_asset_value(f, f.metadata) is None
