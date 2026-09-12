# Syphax

[![CI](https://github.com/K3E9X/Syphax/actions/workflows/ci.yml/badge.svg)](https://github.com/K3E9X/Syphax/actions/workflows/ci.yml)

An autonomous web-application penetration tester you self-host. You authorize a
target, the agent walks an OWASP-WSTG × MITRE-ATT&CK methodology end to end,
every finding is confirmed with a **safe** proof-of-exploit, findings are linked
into kill-chains, and you ship a client report.

It orchestrates mature CLI tools — nuclei, sqlmap, ffuf, dalfox, nmap and a
dozen more — rather than reinventing scanners, and uses an LLM to plan, reorder
and judge. **The whole loop also runs with no LLM at all**: the methodology
engine is deterministic; the model only adds judgement on top.

> For authorized testing only. Use it on systems you own or have written
> permission to test.

---

## Quick start

**Requirements:** Docker with the Compose plugin. Nothing else — no Python, no
Node, no tools to install on the host.

| Host | Notes |
| --- | --- |
| Linux | `docker-ce` + `docker-compose-plugin` |
| macOS (Intel or Apple Silicon) | Docker Desktop or OrbStack |
| Windows | Inside **WSL2** — clone into the WSL filesystem, not `/mnt/c` |

Images are multi-arch (`amd64` + `arm64`); every Python pin ships an aarch64
wheel, so Apple Silicon needs no compiler.

```bash
git clone https://github.com/K3E9X/Syphax && cd Syphax

cp .env.example .env       # then edit it — see below
./install.sh               # checks Docker, then `docker compose build`
./start.sh                 # `docker compose up -d`  (also: stop | restart | --logs)
```

`install.sh` and `start.sh` are thin guarded wrappers; `docker compose build`
and `docker compose up -d` work just as well.

| Service | URL |
| --- | --- |
| UI | http://localhost:3000 |
| API | http://localhost:8000 |
| API docs | http://localhost:8000/docs |
| MITM proxy | http://localhost:8080 (loopback only by default) |

### What to put in `.env`

It runs with the file untouched. Three things are worth setting:

```bash
# 1. LLM — optional. Without a key the deterministic engine still runs.
#    The default splits the roles: reasoning where the decisions are made,
#    speed where the volume is.
PLANNER_BASE_URL=https://api.moonshot.ai/v1     # Kimi K3
PLANNER_API_KEY=sk-...
EXECUTOR_BASE_URL=https://api.z.ai/api/paas/v4  # GLM 5.2
EXECUTOR_API_KEY=...
VALIDATOR_BASE_URL=https://api.z.ai/api/paas/v4
VALIDATOR_API_KEY=...

# 2. Cost. WITHOUT THIS the dashboard shows real tokens against $0.00 spend,
#    because a model that is not listed is costed at zero.
LLM_PRICING=kimi-k3=3.0/15.0,glm-5.2=1.4/4.4

# 3. API key — optional, and empty is fine while the API is bound to 127.0.0.1
#    (the compose default). Set it before exposing :8000 or the proxy :8080 to
#    anything else: the API can read captured sessions and bring up a VPN.
#    Then paste the same value into Settings -> API key in the UI.
SYPHAX_API_KEY=

# 4. Where your traffic exits. Empty = your own IP.
REQUIRE_VPN=false          # true refuses to scan unless the exit IP changed
SCAN_PROXY=                # socks5://127.0.0.1:9050 for Tor — no privileges
VPN_CONFIG_PATH=           # /data/vpn/wg0.conf for WireGuard/OpenVPN
```

Leave every LLM key blank and it falls back to OpenRouter's free models.

### First engagement

1. **Engagements** → enter the target, tick the authorization attestation,
   create. Scope is enforced on every request; out-of-scope hosts are refused
   and audited.
2. **Live** → *Run*. Recon, mapping, vulnerability analysis and exploitation
   advance one phase at a time, streamed to the console as they happen.
3. **Findings** / **Reports** → confirmed findings, kill-chains, and an export
   (Markdown, PDF, JSON, SARIF).

Exploitation is gated twice: `allow_active_exploit` on the engagement, and an
approval checkpoint in the live view.

Day-to-day usage, authenticated testing, proof of impact, VPN setup (ProtonVPN
included) and wiping state: **[docs/OPERATING.md](docs/OPERATING.md)**.

---

## Architecture

```
      Frontend (React, nginx)                    :3000
              │  REST + WebSocket
      API (FastAPI)                              :8000
       │        │              │
  Engagements  Orchestrator   Proxy capture      :8080
  + authz gate  (the brain)   (own image: mitmproxy → Postgres)
                    │
      Planner ──> Executor ──> Validator
      (catalog)   (arq worker)  (safe-PoC)
                    │
      Postgres  +  Redis (arq queue)
                    │
      Tool arsenal (worker image)

      sandbox-runner  ── isolated network, no secrets, pinned egress
```

Six app containers — `backend`, `proxy`, `worker`, `orchestrator`, `frontend`,
`sandbox-runner` — plus Postgres and Redis. Three details are load-bearing:

- The orchestrator has **its own arq queue**. A long autonomous run holds a
  worker slot for its whole life, so sharing one pool let a run starve the
  scans it was itself waiting on.
- `worker` and `orchestrator` run on **`network_mode: "service:backend"`**.
  Only `backend` has `NET_ADMIN` + `/dev/net/tun`, so it is the only namespace
  `wg-quick` can route — without sharing it the tools egressed directly while
  the UI reported a healthy tunnel. Changing this needs a full
  `docker compose down`, not a restart.
- `proxy` is a **separate image** (`--target proxy`). mitmproxy pins
  `cryptography<44.1`; while it shared an environment with the API that pin
  applied to the whole stack.

`sandbox-runner` sits on a separate Docker network with no route to Postgres,
Redis or the backend's secrets. It is where untrusted third-party PoCs run,
after a human has read them.

## How it works

- **Authorization gate** — every scan is tied to an authorized engagement whose
  scope covers the host. Enforced in `Runner.submit()`, the single chokepoint
  every caller passes through, so the autonomous and manual paths are covered
  by the same check.
- **Methodology engine** — a declarative catalog maps each OWASP WSTG test to
  its MITRE ATT&CK technique and the tool that runs it, gated by what has been
  discovered so far.
- **Agent loop** — the planner builds the next batch from the catalog filtered
  by live state; the executor runs each task through the queue and folds the
  results back in, expanding the surface as it learns. The LLM may reorder a
  batch and propose targeted hunts — it never invents a target.
- **Correlation** — when vulnerability analysis starts, the planner gets the
  whole picture at once (assets, fingerprints, WAF, findings so far, captured
  traffic) and joins signals no single tool sees together.
- **Validation** — tool-confirmed where possible, otherwise re-checked with one
  in-scope read-only request and a benign marker. An LLM judge kills false
  positives and proposes a replayable proof. Status is confirmed / likely /
  unconfirmed / false_positive.
- **Kill-chains** — confirmed findings are linked into multi-step attack paths.
- **Live view** — the loop emits typed events to Postgres; a WebSocket tails
  them, so the console, phase timeline and findings update in real time.

Nothing a model produces reaches a target unfiltered: proposals are matched
against assets that already exist, tool flags against per-tool allowlists, and
proofs against a read-only policy.

## Tests

```bash
cd backend && pytest -q          # no network, no database needed
cd frontend && npm run build
```

CI runs on every push. A nightly additionally builds every image for `amd64`
and `arm64`, re-runs the suite against the latest dependency releases, and
checks that each test module still imports with only the CI dependency set.

## License

MIT.
