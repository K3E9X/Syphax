"""Threat-intel providers: parse Shodan / Censys / VirusTotal responses.

The provider functions take an httpx client, so we drive them with a
MockTransport returning canned JSON in the documented API shape - no network.
"""
import httpx
import pytest

from app import intel
from app.config import settings


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_shodan_ports_and_cves(monkeypatch):
    monkeypatch.setattr(settings, "shodan_api_key", "k", raising=False)

    def handler(request):
        return httpx.Response(200, json={"data": [
            {"port": 443, "transport": "tcp", "product": "nginx",
             "version": "1.18.0", "data": "HTTP/1.1 200", "vulns": {"CVE-2021-23017": {}},
             "_shodan": {"module": "https"}},
            {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.2"},
        ]})

    async with _client(handler) as c:
        findings = await intel._shodan(c, "acme.com", "1.2.3.4")

    ports = [f for f in findings if f.metadata.get("vuln_class") == "recon"]
    cves = [f for f in findings if f.metadata.get("vuln_class") == "cve"]
    assert {f.metadata["port"] for f in ports} == {443, 22}
    assert cves and cves[0].metadata["cve_id"] == "CVE-2021-23017"
    assert cves[0].severity == "high"


@pytest.mark.asyncio
async def test_censys_services(monkeypatch):
    monkeypatch.setattr(settings, "censys_api_id", "id", raising=False)
    monkeypatch.setattr(settings, "censys_api_secret", "sec", raising=False)

    def handler(request):
        return httpx.Response(200, json={"result": {"services": [
            {"port": 80, "transport_protocol": "TCP", "service_name": "HTTP",
             "software": [{"product": "Apache", "version": "2.4.52"}]},
        ]}})

    async with _client(handler) as c:
        findings = await intel._censys(c, "acme.com", "1.2.3.4")

    assert len(findings) == 1
    assert findings[0].metadata["port"] == 80
    assert "Apache" in findings[0].metadata["service"]


@pytest.mark.asyncio
async def test_virustotal_flags_malicious(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "k", raising=False)

    def handler(request):
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 3, "suspicious": 1},
            "reputation": -5,
        }}})

    async with _client(handler) as c:
        findings = await intel._virustotal(c, "acme.com", "1.2.3.4")

    assert len(findings) == 1
    assert findings[0].metadata["malicious"] == 3
    assert findings[0].severity == "medium"


@pytest.mark.asyncio
async def test_virustotal_clean_domain_is_empty(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "k", raising=False)

    def handler(request):
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0},
        }}})

    async with _client(handler) as c:
        assert await intel._virustotal(c, "acme.com", "1.2.3.4") == []


@pytest.mark.asyncio
async def test_provider_http_error_degrades_to_empty(monkeypatch):
    monkeypatch.setattr(settings, "shodan_api_key", "k", raising=False)

    def handler(request):
        return httpx.Response(401, json={"error": "no"})

    async with _client(handler) as c:
        assert await intel._shodan(c, "acme.com", "1.2.3.4") == []
