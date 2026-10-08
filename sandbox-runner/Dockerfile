# syntax=docker/dockerfile:1.6
# Isolated runner for untrusted third-party PoCs.
#
# Multi-arch: linux/amd64 and linux/arm64 (Apple Silicon). Nothing here is
# architecture-specific - the base image is multi-arch, apt resolves per-arch,
# and every pinned wheel publishes an aarch64 build, so no compiler is needed.
#
# Kept minimal on purpose: every extra tool in here is a tool a trojaned PoC
# gets to use. No git, no ssh client, no package manager at runtime.
#
# An HTTP client IS here, deliberately. The containment in this image is the
# egress jail - the PoC can only reach the engagement scope, and it cannot
# alter the rules that say so - not the absence of a client library. Without
# one, nothing could be proven: `requests` is what app/exploit/authoring.py
# promises the model ("use only the standard library plus requests"), and curl
# is what every published bash PoC uses. The image shipped with neither, so
# every authored exploit died on ModuleNotFoundError and every bash PoC on
# "curl: not found" - and the operator was told the exploit had failed.
FROM python:3.12-slim

# iptables to pin egress, gosu to drop privileges before running a PoC, curl
# for bash PoCs, nodejs for JavaScript ones.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables gosu nodejs curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.32.0 pydantic==2.10.2 \
        requests==2.32.3

# The account the PoC runs as. No shell, no home worth reading, and crucially
# no CAP_NET_ADMIN, so it cannot alter the egress rules that contain it.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin poc

WORKDIR /app
COPY runner.py /app/runner.py
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# /work is a tmpfs at runtime: staged code never touches a disk that survives.
RUN mkdir -p /work && chown poc:poc /work

EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "runner:app", "--host", "0.0.0.0", "--port", "8090"]
