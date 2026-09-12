# syntax=docker/dockerfile:1.6
# Multi-arch image: linux/amd64 (Intel/AMD) and linux/arm64 (Apple Silicon M1/M2/M3).
#
# Bundled pentest tools:
#   - nuclei     (ProjectDiscovery, Go binary)
#   - ffuf       (Go binary)
#   - dalfox     (Go binary)
#   - subfinder  (ProjectDiscovery, Go binary)
#   - httpx      (ProjectDiscovery, Go binary)
#   - katana     (ProjectDiscovery, Go binary)
#   - testssl.sh (git clone - bash + openssl)
#   - wpscan     (gem install - ruby)
#   - nikto      (git clone - perl)
#   - whatweb    (git clone - ruby)
#   - nmap       (apt)
#   - sqlmap     (apt)
#   - mitmproxy  (pip)
#   - trufflehog (Go binary)  secrets, VERIFIED against the provider
#   - jsluice    (Go binary)  URLs/secrets from JS via a real parser
#   - retire.js  (npm)        known-vulnerable client-side libraries
#   - schemathesis (pip)      property-tests an API against its own OpenAPI
#   - arjun      (pip)        hidden HTTP parameter discovery
#   - git-dumper (pip)        recover source from an exposed .git
# Python app runs FastAPI backend.

# --- jsluice builder -------------------------------------------------------
# jsluice publishes no prebuilt linux archive, and `go install` is its
# documented install path. Built here and copied in, so the Go toolchain
# (~600 MB) never lands in the shipped image. bookworm matches the runtime
# base, because jsluice links tree-sitter through CGO and the binary is
# therefore dynamically linked against libc.
FROM golang:1.23-bookworm AS jsluice-build
# jsluice publishes no git tags, only pseudo-versions, so the pin is the
# module proxy's content-addressed version - reproducible, and it is what
# `go install` can actually resolve.
ARG JSLUICE_VERSION=v0.0.0-20240110145140-0ddfab153e06
ENV CGO_ENABLED=1
RUN mkdir -p /out \
    && (go install "github.com/BishopFox/jsluice/cmd/jsluice@${JSLUICE_VERSION}" \
        && install -m 0755 /go/bin/jsluice /out/jsluice) || true


# Pinned to bookworm (Debian 12): the default `slim` tag now tracks trixie
# (Debian 13), which dropped `nikto` and `whatweb` from its apt repos.
FROM python:3.12-slim-bookworm AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        git \
        unzip \
        nmap \
        sqlmap \
        libssl-dev \
        openssl \
        bsdmainutils \
        procps \
        dnsutils \
        perl \
        # POST /api/network/vpn/connect shells out to these. Without them the
        # endpoint could only ever answer "wg-quick is not installed", so the
        # feature shipped dead. wireguard-tools pulls wireguard-go, the
        # userspace implementation, which is what actually works inside a
        # container when the host kernel module is not exposed - the usual case
        # on Docker Desktop.
        wireguard-tools \
        openvpn \
        iproute2 \
        libnet-ssleay-perl \
        libio-socket-ssl-perl \
    && rm -rf /var/lib/apt/lists/*

# nikto (Perl) and whatweb (Ruby) are not in the slim apt repos, so install
# them from source. Non-fatal: if a clone fails the wrapper simply reports the
# tool as unavailable and the orchestrator skips it - the build never breaks.
RUN set -eux; \
    git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto || true; \
    if [ -f /opt/nikto/program/nikto.pl ]; then \
        printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto; \
        chmod +x /usr/local/bin/nikto; \
    fi; \
    git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb || true; \
    if [ -f /opt/whatweb/whatweb ]; then \
        ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb; \
    fi; \
    git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb || true; \
    if [ -f /opt/exploitdb/searchsploit ]; then \
        ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit; \
    fi

# wafw00f (pip) - WAF fingerprinting.
RUN pip install --no-cache-dir wafw00f==2.3.1

# Python-based tools, installed into the base layer so both images have them.
#   arjun        - hidden HTTP parameter discovery (adds injection points)
#   git-dumper   - rebuild the source tree from an exposed .git
#   schemathesis - property-based testing against a published OpenAPI schema
# Pinned: arjun's console output and schemathesis' NDJSON event schema are
# what the wrappers parse, so an unpinned major could change both silently.
RUN pip install --no-cache-dir \
        arjun==2.2.7 \
        git-dumper==1.0.9 \
        schemathesis==4.27.0

# commix (git checkout) - command injection. The repo ships commix.py with a
# python3 shebang; symlink it onto PATH as 'commix'.
RUN set -eux; \
    git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix; \
    ln -sf /opt/commix/commix.py /usr/local/bin/commix; \
    chmod +x /opt/commix/commix.py; \
    commix --version >/dev/null 2>&1 || true

# Pinned versions (updated manually). Matches the official release naming.
ARG NUCLEI_VERSION=3.3.5
ARG FFUF_VERSION=2.1.0
ARG DALFOX_VERSION=2.9.2
ARG SUBFINDER_VERSION=2.6.7
ARG HTTPX_VERSION=1.6.9
ARG KATANA_VERSION=1.1.2
ARG NAABU_VERSION=2.3.3
ARG DNSX_VERSION=1.2.1
ARG GAU_VERSION=2.2.4
ARG TRUFFLEHOG_VERSION=3.90.10

# Map Docker TARGETARCH to the suffix each project uses in its release archive.
#   amd64 -> amd64
#   arm64 -> arm64
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) ARCH_SUFFIX=amd64 ;; \
        arm64) ARCH_SUFFIX=arm64 ;; \
        *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    \
    # nuclei
    curl -fsSL -o nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH_SUFFIX}.zip"; \
    unzip -q nuclei.zip; \
    install -m 0755 nuclei /usr/local/bin/nuclei; \
    rm -f nuclei nuclei.zip LICENSE.md README*.md; \
    \
    # ffuf
    curl -fsSL -o ffuf.tar.gz \
        "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ARCH_SUFFIX}.tar.gz"; \
    tar -xzf ffuf.tar.gz; \
    install -m 0755 ffuf /usr/local/bin/ffuf; \
    rm -f ffuf ffuf.tar.gz LICENSE; \
    \
    # dalfox
    curl -fsSL -o dalfox.tar.gz \
        "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox_${DALFOX_VERSION}_linux_${ARCH_SUFFIX}.tar.gz"; \
    tar -xzf dalfox.tar.gz; \
    install -m 0755 dalfox /usr/local/bin/dalfox; \
    rm -f dalfox dalfox.tar.gz LICENSE README*.md; \
    \
    # subfinder
    curl -fsSL -o subfinder.zip \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${ARCH_SUFFIX}.zip"; \
    unzip -q subfinder.zip; \
    install -m 0755 subfinder /usr/local/bin/subfinder; \
    rm -f subfinder subfinder.zip LICENSE.md README*.md; \
    \
    # httpx (ProjectDiscovery - not to be confused with the Python httpx library)
    curl -fsSL -o httpx.zip \
        "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${ARCH_SUFFIX}.zip"; \
    unzip -q httpx.zip; \
    install -m 0755 httpx /usr/local/bin/httpx; \
    rm -f httpx httpx.zip LICENSE.md README*.md; \
    \
    # katana
    curl -fsSL -o katana.zip \
        "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${ARCH_SUFFIX}.zip"; \
    unzip -q katana.zip; \
    install -m 0755 katana /usr/local/bin/katana; \
    rm -f katana katana.zip LICENSE.md README*.md; \
    \
    # naabu (port scanner). We use connect-scan mode at runtime so no libpcap
    # / NET_RAW capability is required.
    #
    # The ONE download allowed to fail. naabu links libpcap and publishes no
    # linux/arm64 asset at any version - every other ProjectDiscovery tool
    # here does - so a hard `curl -f` broke the whole arm64 image build on a
    # 404. Degrade the way nikto and whatweb already do: the wrapper reports
    # the tool as unavailable, the orchestrator skips RECON-PORTS, and
    # RECON-NMAP-SERVICES still covers port and service detection.
    if curl -fsSL -o naabu.zip \
        "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${ARCH_SUFFIX}.zip"; \
    then \
        unzip -q naabu.zip; \
        install -m 0755 naabu /usr/local/bin/naabu; \
    else \
        echo "naabu: no linux/${ARCH_SUFFIX} release; skipping (nmap covers port scanning)" >&2; \
    fi; \
    rm -f naabu naabu.zip LICENSE.md README*.md; \
    \
    # dnsx (DNS toolkit)
    curl -fsSL -o dnsx.zip \
        "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${ARCH_SUFFIX}.zip"; \
    unzip -q dnsx.zip; \
    install -m 0755 dnsx /usr/local/bin/dnsx; \
    rm -f dnsx dnsx.zip LICENSE.md README*.md; \
    \
    # gau (GetAllUrls - historical URLs from wayback/commoncrawl/otx)
    curl -fsSL -o gau.tar.gz \
        "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${ARCH_SUFFIX}.tar.gz"; \
    tar -xzf gau.tar.gz; \
    install -m 0755 gau /usr/local/bin/gau; \
    rm -f gau gau.tar.gz LICENSE README*.md; \
    \
    # trufflehog - secret detection with provider VERIFICATION. The verified
    # mode is the whole reason it is here: it authenticates each candidate, so
    # a hit is a live credential rather than a matching regex.
    curl -fsSL -o trufflehog.tar.gz \
        "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH_SUFFIX}.tar.gz"; \
    tar -xzf trufflehog.tar.gz trufflehog; \
    install -m 0755 trufflehog /usr/local/bin/trufflehog; \
    rm -f trufflehog trufflehog.tar.gz

# Pre-download nuclei templates so first scan is fast.
RUN nuclei -update-templates -silent || true

# jsluice - URLs, parameters and secrets out of a real JavaScript AST, which is
# what a regex pass over a minified bundle cannot do. Built in the stage above.
# Copied as a directory, not a file: if the build stage failed the directory
# is empty, nothing is installed, and the wrapper reports the tool as
# unavailable - the same non-fatal degradation as nikto and whatweb, rather
# than a broken image build.
COPY --from=jsluice-build /out/ /usr/local/bin/

# retire.js (npm) - rates the CLIENT-side libraries the browser loads, which
# nothing else in the image looks at: httpx/whatweb fingerprint the server,
# nuclei matches server-side CVEs. A page shipping jQuery 1.7.2 was invisible.
# Non-fatal like nikto/whatweb: if npm or the registry is unreachable the
# wrapper reports the tool as unavailable and the orchestrator skips it.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends nodejs npm; \
    npm install -g --no-audit --no-fund retire@5.7.0 || true; \
    rm -rf /var/lib/apt/lists/* /root/.npm; \
    retire --version >/dev/null 2>&1 || true

# testssl.sh (bash script + openssl). Pin to v3.2 (last stable).
ARG TESTSSL_VERSION=3.2
RUN set -eux; \
    git clone --depth 1 --branch ${TESTSSL_VERSION} https://github.com/drwetter/testssl.sh.git /opt/testssl.sh; \
    ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh; \
    testssl.sh --help >/dev/null 2>&1 || true

# wpscan (Ruby gem). We install ruby + the build deps, install the gem,
# then purge the build deps to keep the image smaller. Runtime keeps
# ruby, libcurl and libxml2 which are needed for wpscan's gems at runtime.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ruby ruby-dev \
        build-essential \
        libcurl4-openssl-dev \
        libxml2-dev libxslt-dev zlib1g-dev; \
    gem install --no-document wpscan; \
    apt-get purge -y --auto-remove \
        build-essential \
        ruby-dev \
        libxml2-dev libxslt-dev zlib1g-dev; \
    apt-get install -y --no-install-recommends libcurl4 libxml2 libxslt1.1; \
    rm -rf /var/lib/apt/lists/*; \
    wpscan --version >/dev/null 2>&1 || true

# Bundle a small, sane default wordlist for ffuf (dirb's classic common.txt,
# ~4600 entries). Users can override via the FFUF_WORDLIST env var and
# mounting their own list into the container. We try a few well-known
# mirrors and fall back to a tiny built-in list if none are reachable,
# so the build never fails because of a wordlist CDN hiccup.
RUN set -eux; \
    mkdir -p /opt/wordlists; \
    for url in \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        "https://raw.githubusercontent.com/3ndG4me/KaliLists/master/dirb/common.txt" \
        "https://raw.githubusercontent.com/daviddias/node-dirbuster/master/lists/directory-list-2.3-small.txt" \
    ; do \
        if curl -fsSL --max-time 45 "$url" -o /opt/wordlists/common.txt; then \
            echo "wordlist: downloaded from $url"; break; \
        fi; \
        echo "wordlist: failed $url"; \
        rm -f /opt/wordlists/common.txt; \
    done; \
    if [ ! -s /opt/wordlists/common.txt ]; then \
        echo "wordlist: all mirrors failed, writing minimal built-in list"; \
        printf '%s\n' \
            admin administrator api backup backups bin cgi-bin config console \
            data db debug dev docs download downloads env files images img \
            includes install js log login logout logs old phpmyadmin private \
            public repo robots.txt sitemap.xml static stats status test tests \
            tmp upload uploads user users v1 v2 wp-admin wp-content wp-login.php \
            > /opt/wordlists/common.txt; \
    fi; \
    wc -l /opt/wordlists/common.txt

WORKDIR /app

# Code and entrypoints, but no Python dependencies yet: the two images below
# need different ones. mitmproxy pins cryptography<44.1, and while it shared an
# environment with the API that pin held the whole stack seven majors back.
COPY requirements.txt requirements-proxy.txt ./
COPY app ./app
COPY entrypoint.sh entrypoint-proxy.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/entrypoint-proxy.sh


# --- proxy image: mitmproxy only (docker build --target proxy) ---------------
FROM base AS proxy
RUN pip install --no-cache-dir -r requirements-proxy.txt
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint-proxy.sh"]


# --- app image: API, worker, orchestrator. LAST, so it is the default target -
FROM base AS app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
