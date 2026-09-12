"""Registry of available CLI tool wrappers."""
from __future__ import annotations

from typing import Dict, List

from app.scans.wrappers.arjun import ArjunWrapper
from app.scans.wrappers.base import BaseWrapper
from app.scans.wrappers.commix import CommixWrapper
from app.scans.wrappers.dalfox import DalfoxWrapper
from app.scans.wrappers.dnsx import DnsxWrapper
from app.scans.wrappers.ffuf import FfufWrapper
from app.scans.wrappers.gau import GauWrapper
from app.scans.wrappers.gitdumper import GitDumperWrapper
from app.scans.wrappers.httpx import HttpxWrapper
from app.scans.wrappers.jsluice import JsluiceWrapper
from app.scans.wrappers.katana import KatanaWrapper
from app.scans.wrappers.naabu import NaabuWrapper
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
            "description": w.description,
            "category": w.category,
        }
        for w in _WRAPPERS.values()
    ]


__all__ = ["BaseWrapper", "get_wrapper", "available_wrappers"]
