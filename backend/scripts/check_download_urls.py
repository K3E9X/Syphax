#!/usr/bin/env python3
"""Verify every pinned tool download still exists, on both architectures.

The multi-arch image build takes ~20 minutes under QEMU and fails at whichever
step 404s, so a yanked or missing release is discovered late and expensively.
This resolves the same URLs the Dockerfile builds - reading the ARG defaults so
the versions cannot drift apart - and HEAD-checks each one in a few seconds.

It found the real case it was written for: naabu links libpcap and publishes no
linux/arm64 asset at any version, while every other ProjectDiscovery tool does,
so the arm64 image had never been buildable.

Exit code 1 if any required URL is missing. Tools listed in OPTIONAL may be
absent on an architecture: the wrapper reports them unavailable and the
orchestrator skips their catalog item, which is the documented degradation.

    python3 scripts/check_download_urls.py [--dockerfile backend/Dockerfile]
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request

ARCHES = ("amd64", "arm64")

# name -> why it is allowed to be missing on an architecture.
OPTIONAL = {
    "naabu": "links libpcap; no linux/arm64 asset. nmap covers port scanning.",
}

URL_RE = re.compile(r'"(https://github\.com/[^"]*/releases/download/[^"]+)"')
ARG_RE = re.compile(r"^ARG\s+([A-Z0-9_]+)=(\S+)\s*$", re.M)


def arg_defaults(text: str) -> dict:
    return {m.group(1): m.group(2) for m in ARG_RE.finditer(text)}


def expand(url: str, args: dict, arch: str) -> str:
    out = url.replace("${ARCH_SUFFIX}", arch).replace("${TARGETARCH}", arch)
    for name, value in args.items():
        out = out.replace("${" + name + "}", value)
    return out


def tool_name(url: str) -> str:
    # .../<owner>/<tool>/releases/download/...
    parts = url.split("/releases/download/")[0].rstrip("/").split("/")
    return parts[-1] if parts else url


def reachable(url: str, timeout: float = 30.0) -> int:
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:  # noqa: BLE001 - a DNS/TLS failure is not a 404
        return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dockerfile", default="backend/Dockerfile")
    opts = ap.parse_args()

    text = open(opts.dockerfile, encoding="utf-8").read()
    args = arg_defaults(text)
    urls = sorted(set(URL_RE.findall(text)))
    if not urls:
        print(f"no release URLs found in {opts.dockerfile}", file=sys.stderr)
        return 1

    failures, skipped = [], []
    for template in urls:
        for arch in ARCHES:
            url = expand(template, args, arch)
            if "${" in url:
                failures.append((url, arch, "unresolved variable"))
                continue
            status = reachable(url)
            name = tool_name(url)
            ok = 200 <= status < 400
            mark = "ok " if ok else "MISS"
            print(f"  {mark} {name:<12} {arch:<6} {status}  {url}")
            if ok:
                continue
            if name in OPTIONAL:
                skipped.append((name, arch))
            else:
                failures.append((url, arch, str(status)))

    print()
    for name, arch in skipped:
        print(f"note: {name} has no {arch} build - {OPTIONAL[name]}")
    if failures:
        print(f"\n{len(failures)} download(s) unreachable:", file=sys.stderr)
        for url, arch, why in failures:
            print(f"  [{arch}] {why}: {url}", file=sys.stderr)
        return 1
    print(f"all {len(urls)} pinned download(s) reachable on {', '.join(ARCHES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
