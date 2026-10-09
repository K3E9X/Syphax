"""Registry of available CLI tool wrappers."""
from __future__ import annotations

from typing import Dict, List

from app.scans.wrappers.arjun import ArjunWrapper
from app.scans.wrappers.base import BaseWrapper
from app.scans.wrappers.cloud_enum import CloudEnumWrapper
from app.scans.wrappers.commix import CommixWrapper
from app.scans.wrappers.dalfox import DalfoxWrapper
from app.scans.wrappers.dnsx import DnsxWrapper
from app.scans.wrappers.ffuf import FfufWrapper
from app.scans.wrappers.gau import GauWrapper
from app.scans.wrappers.gitdumper import GitDumperWrapper
from app.scans.wrappers.httpx import HttpxWrapper
from app.scans.wrappers.jsluice import JsluiceWrapper
from app.scans.wrappers.katana import KatanaWrapper
from app.scans.wrappers.kiterunner import KiterunnerWrapper
from app.scans.wrappers.naabu import NaabuWrapper
from app.scans.wrappers.nosqli import NoSqliWrapper
from app.scans.wrappers.nikto import NiktoWrapper
from app.scans.wrappers.nmap import NmapWrapper
from app.scans.wrappers.nuclei import NucleiWrapper
from app.scans.wrappers.retirejs import RetireJsWrapper
from app.scans.wrappers.schemathesis import SchemathesisWrapper
from app.scans.wrappers.sqlmap import SqlmapWrapper
from app.scans.wrappers.subfinder import SubfinderWrapper
from app.scans.wrappers.testssl import TestsslWrapper
from app.scans.wrappers.trufflehog import TruffleHogWrapper
from app.scans.wrappers.wafw00f import Wafw00fWrapper
from app.scans.wrappers.whatweb import WhatwebWrapper
from app.scans.wrappers.wpscan import WpscanWrapper

_WRAPPERS: Dict[str, BaseWrapper] = {
    "nuclei": NucleiWrapper(),
    "sqlmap": SqlmapWrapper(),
    "ffuf": FfufWrapper(),
    "dalfox": DalfoxWrapper(),
    "nmap": NmapWrapper(),
    "subfinder": SubfinderWrapper(),
    "httpx": HttpxWrapper(),
    "katana": KatanaWrapper(),
    "testssl": TestsslWrapper(),
    "wpscan": WpscanWrapper(),
    "commix": CommixWrapper(),
    "wafw00f": Wafw00fWrapper(),
    "whatweb": WhatwebWrapper(),
    "nikto": NiktoWrapper(),
    "naabu": NaabuWrapper(),
    "dnsx": DnsxWrapper(),
    "gau": GauWrapper(),
    # Parameter discovery: adds injection points, which is what unblocks every
    # injection test on an endpoint whose real parameters are undocumented.
    "arjun": ArjunWrapper(),
    # The API's own contract as the oracle.
    "schemathesis": SchemathesisWrapper(),
    # Client-side coverage: the libraries the browser actually loads.
    "retirejs": RetireJsWrapper(),
    "jsluice": JsluiceWrapper(),
    # Act on an exposed .git, then prove which of the recovered secrets is live.
    "gitdumper": GitDumperWrapper(),
    "trufflehog": TruffleHogWrapper(),
    # Public cloud storage (S3/Azure/GCP) enumerated from the brand keyword -
    # buckets never linked from the target but owned by the same org.
    "cloud_enum": CloudEnumWrapper(),
    # NoSQL operator injection (MongoDB-style), which sqlmap does not cover.
    "nosqli": NoSqliWrapper(),
    # API route discovery: the hidden/undocumented endpoints that feed auth,
    # BOLA and injection testing.
    "kiterunner": KiterunnerWrapper(),
}


def get_wrapper(name: str) -> BaseWrapper:
    if name not in _WRAPPERS:
        raise KeyError(f"unknown tool: {name}")
    return _WRAPPERS[name]


def available_wrappers() -> List[Dict[str, object]]:
    """List of tools with availability info. Used by /api/scans/tools."""
    return [
        {
            "name": w.name,
            "binary": w.binary,
            "available": w.is_available(),
            "ready": w.readiness().ready,
            "not_ready_because": w.readiness().reason,
            "description": w.description,
            "category": w.category,
        }
        for w in _WRAPPERS.values()
    ]


def preflight() -> List[Dict[str, object]]:
    """Every tool's real state: installed, and able to find anything.

    The distinction is the whole point. "Installed" is `which nuclei`; "ready"
    is whether it has its templates. A nuclei with an empty template set runs,
    exits 0, prints nothing - and a target full of known CVEs comes back clean.
    The same is true of ffuf without its wordlist and kiterunner without its
    route database. From the operator's seat all three are indistinguishable
    from a target that simply has nothing wrong with it, which is how a run on
    a deliberately vulnerable site can report only "info" findings.
    """
    return [w.readiness().to_dict() | {"category": w.category,
                                       "binary": w.binary,
                                       "description": w.description}
            for w in _WRAPPERS.values()]


def not_ready() -> List[Dict[str, object]]:
    """Only the tools that cannot do their job, for the limits panel."""
    return [r for r in preflight() if not r["ready"]]


__all__ = ["BaseWrapper", "get_wrapper", "available_wrappers", "preflight",
           "not_ready"]
