# Operating guide

What the README leaves out: running an engagement day to day, authenticated
testing, proof of impact, platform specifics, and wiping state.

## Signing in

There is no anonymous mode. The first visit creates the operator account, and
the setup page closes permanently once it exists — an open one is a backdoor,
not a setup page.

* Sessions last 8 hours, slide while you use them, and cap at 7 days. The token
  is an httpOnly cookie; only its SHA-256 is stored, so a database dump
  contains nothing replayable.
* Failed logins back off per (username, source address) **together**: per
  username alone would let someone lock you out of your own tool, per address
  alone is defeated by a proxy list. The delay is capped.
* **Settings -> Account** changes the password (which ends every other
  session), lists the sessions that are live, and signs out everywhere.
* **Settings -> Operators** (admin only) adds and removes accounts. A VM shared
  by two or three testers is the case this is for: each gets their own password
  and their own line in the audit log, because "who ran this scan" is not a
  question a shared account can answer. Roles are `admin` (everything) and
  `operator` (runs engagements, cannot manage accounts). The last account cannot
  be deleted, and neither can the one you are signed in as.
* `SYPHAX_API_KEY` is a machine credential for scripts and CI. It is an
  alternative to a session, not a way to skip having an account: with no
  account, it authorises nothing.

Forgotten the password on a host you control? There is no reset link. Delete
the row and let setup run again:

```bash
docker compose exec postgres psql -U syphax -d syphax \
    -c 'DELETE FROM user_sessions; DELETE FROM users;'
```

## Connecting a model

The tool will not run without one, and there is no variable that disables the
requirement. Three roles need a provider:

| Role | What it does | What to put there |
| --- | --- | --- |
| planner | decides the next move | the strongest model you are willing to pay for; it runs least often |
| executor | drives the tools, reads their output | the cheapest fast one; it runs constantly |
| validator | confirms or kills each finding | accuracy — this is what keeps false positives out of the report |

Offered out of the box: **Z.ai (GLM)**, **Moonshot (Kimi)**, **DeepSeek**,
**Qwen (DashScope)**, **OpenRouter**, and "Other" for anything else that speaks
`/v1/chat/completions` — a self-hosted vLLM or Ollama, an in-house gateway.

The model name is free text. Nothing validates against the suggestions, which
will lag the provider; if a model string is wrong, the provider says so and the
per-role **Test** button in Settings shows you exactly what it said.

Keys are encrypted with `SYPHAX_SECRET_KEY` before they are written and are
never returned to the browser — the UI can only ask whether one is stored.

**Recon is the one exception, and it is not a loophole.** That page reads DNS,
the registries, a certificate and one HTTP response, and every conclusion it
draws is a pure function over those — it never calls a model, so holding it
behind one would be the tool refusing to do something it is perfectly capable
of. It stays reachable before a provider is configured, with a banner saying the
rest is not. Everything else — engagements, runs, validation, reports — is
blocked, and the API refuses a run with a 409 regardless of what the UI allows.

## Recon, before the engagement

**Recon** sits between Home and Engagements because that is where the step
belongs: you arrive with a URL on a scoping document and four questions.

    where does this actually live      addresses, reverse DNS, the redirect chain
    whose network is that              ASN via Team Cymru, the netblock via RDAP
    what is it built out of            frontend / backend / infrastructure
    what else carries this name        the certificate's SANs, and CT logs

Paste a hostname, a URL or an IP and press Run. It takes about a second without
CT logs, a few with.

### What it sends, and why that list is short

An engagement is what authorizes testing: the operator attests, the scope gate
enforces, the audit log records. Recon runs *before* one exists — it is how you
decide whether to open one — so it has no scope to check against and cannot be
given one. The line is therefore a list, not a judgement call
(`backend/app/recon/budget.py`):

* **Asks public infrastructure about the target.** DNS, RDAP, Certificate
  Transparency. None of this reaches the target at all.
* **Does what a browser does.** One TLS handshake, one `GET /`.
* **Reads the three files the web agreed are public.** `robots.txt`,
  `sitemap.xml`, `.well-known/security.txt`.

That is the whole list. No port scan, no directory or subdomain brute force, no
vulnerability templates, no authentication attempts, GET and HEAD only, at most
six requests. The UI shows the same list next to the button — served from the
backend, so the page cannot promise less than the backend enforces.

Every run is written to the audit log with the operator's name on it. That
matters more here than anywhere else: it is the one lookup no engagement covers.

### The three technology layers

Split deliberately, because they answer three different questions:

| Layer | Question it answers |
| --- | --- |
| frontend | is DOM XSS on the table, and which bundles are worth pulling apart |
| backend | which injection families are plausible, which CVE feeds to read |
| infrastructure | what sits in front — and a WAF changes how everything else is approached |

That last distinction is the one people skip and then misread their own
results. `Server: cloudflare` says nothing whatsoever about the application.

Each detection carries the evidence that produced it (hover it), and a coarse
confidence: `certain` for a header or cookie only that software emits, `likely`
for a body pattern someone could have written by hand. A wrong one can be
dismissed by looking at it rather than by trusting the signature table.

### Certificate Transparency is the productive part

Every publicly-trusted certificate issued since 2018 is in a public log. Reading
it is not enumeration — the target is never contacted — and in practice it is
the single best source of scope before an engagement: staging hosts, admin
panels, internal tools and the vendor SaaS nobody mentioned all end up with
certificates. Names that are not on the scoping document are the conversation to
have on the call, not in week two.

crt.sh is one free service run by one CA. When it is slow or down, the panel
says so — "crt.sh unreachable" and "this domain has no certificates" are
different facts and conflating them would quietly shrink the scope.

### Carrying it into an engagement

**Create an engagement with this target** prefills the target URL and suggests a
scope list built from the certificate's names and the CT names. They are
suggestions. Keep only what you are authorized to test — the engagement form is
where the attestation is, and it is still yours to make.

### When a source does not answer

Every section is an independent lookup against an independent service, so each
one fails on its own and the page renders what came back. A list of what did not
answer appears above the panels rather than replacing them.

One thing it will not do: report six missing security headers when nothing
answered at all. That reads as a finding about the target when it is a finding
about the connection.

## Run an engagement

1. **Engagements** -> enter a target you own, tick the authorization box,
   create. Attestation authorizes it immediately; the scope list bounds what
   gets touched.
2. Open its **live view** -> **Run**. Watch recon -> mapping -> vuln ->
   exploitation -> validation stream in the agent console; if you enabled
   "require approval before exploitation", approve the checkpoint.
3. Download the **report** (`.md` or printable HTML) once findings are
   validated and chains are built.

You can also drive tools manually: browse the target through the MITM proxy
(install its CA from the Proxy page), inspect captured requests, and launch
individual scans from the Scans page.

### Authenticated, traffic-driven testing

For real coverage, run it authenticated:

- **Authenticated scan** - paste the primary identity's headers (Cookie /
  Authorization) in the engagement form. They're injected into every scanner
  (nuclei/sqlmap/ffuf/dalfox/katana/...) so it tests *behind the login*.
- **Real surface from the proxy** - browse the app through the MITM proxy
  while logged in; the autonomous run seeds those captured (parameterized)
  requests as scan targets, so sqlmap/dalfox/nuclei-dast hit the endpoints
  you actually exercised.
- **Grey-box IDOR/BOLA/BFLA** - add a *second* (low-privilege) identity's
  headers; the analysis replays captured requests as the other user to prove
  broken object-level authorization and privilege escalation (BFLA).
- **Out-of-band (blind) confirmation** - nuclei confirms blind SSRF/XXE/RCE
  via interactsh. By default it uses ProjectDiscovery's free public servers
  (no infra); set `INTERACTSH_SERVER` in `.env` to self-host.

The **deep analysis** pass (autorun in the validation phase, or on demand via
*Deep analysis* on the live view) mines everything captured through the proxy:

- **Secret & endpoint mining** - scans every captured text response (JS
  bundles, HTML, JSON, source maps) for secrets (cloud keys, tokens, private
  keys, JWTs) and pulls hidden API endpoints out of client code; discovered
  endpoints are seeded as new scan targets.
- **JWT analysis** - flags `alg=none`, cracks weak/known HMAC secrets offline,
  spots `kid`/`jku` injection surface, missing `exp`, and authz claims.
- **Access control in depth** - replays authenticated GETs anonymously to find
  missing-auth/broken-access-control, and flags method-tampering and
  mass-assignment candidates for manual review (writes are never executed).

Findings are partitioned into homogeneous categories (recon, enumeration,
access control, injection, auth & secrets, server & config) in both the live
view and the report.

### Proof of impact (opt-in)

Detection isn't proof. With **"Prove impact"** enabled on the engagement, after
a tool *confirms* an injection the agent demonstrates real impact by running a
**benign, read-only** command through it:

- **RCE / command injection** - re-runs commix with `--os-cmd` executing a
  read-only post-exploitation enumeration in one shot (privilege context,
  host/container detection, listening services & routes, scheduled tasks, SUID
  binaries, users). The output proves execution and maps the blast radius. It
  also **detects (never exploits) local privilege-escalation vectors** -
  passwordless `sudo` and GTFOBins-known SUID binaries - which feed an
  RCE → root kill-chain.
- **SQLi** - re-runs sqlmap in read-only context mode (`--current-user`,
  `--is-dba`, `--banner`, ...); OS command execution through the DB is a
  separate sub-opt-in.
- **Data-breach proof** (separate sub-opt-in) - retrieves a small, **bounded
  sample (≤3 rows)** of likely-sensitive tables via a confirmed SQLi to prove a
  real data exposure - far from a mass exfiltration.

It is **double-gated** (the opt-in flag *and* the exploitation approval
checkpoint), in-scope only, and strictly non-destructive: no writes, deletes,
persistence or lateral movement. The exact command and its raw output are
visible in the Jobs tab.

- **Known-CVE exploitation** - from the fingerprinted stack (WordPress,
  Atlassian, GitLab, Jenkins, Tomcat, Struts, ...) the agent runs the matching
  nuclei CVE templates (vetted public PoCs, out-of-band confirmed). Gated by the
  same `allow_active_exploit` opt-in.
- **Targeted CVE checks** - a curated set of high-value, actively-exploited CVEs
  (Apache 2.4.49/50 path traversal, Citrix, F5 BIG-IP, Pulse Secure, FortiOS file
  read) confirmed with a single read-only in-scope GET and a high-confidence file
  signature - near-zero false positives, no OOB infra. On a hit the CVE is
  reported with a redacted proof snippet.
- **Public-exploit aggregation (all sources)** - for every detected CVE the
  agent gathers the public PoCs that exist across sources - Exploit-DB (offline
  via `searchsploit`), Metasploit, GitHub, NVD, Vulners, Packet Storm - and
  shows them per finding with a runnable tier: `auto` (vetted, run in-scope:
  nuclei / Metasploit check), `sandbox` (raw scripts fetched and staged for an
  approved run in the isolated sandbox), `reference` (links). Raw public code is
  never auto-run - it is reviewed/run only via the approved sandbox.

Confirmed findings are then linked into **kill-chains** automatically:
leaked-secret → server compromise, broken-access-control → bulk data exposure,
weak-JWT → account takeover, SSRF → cloud credential theft, subdomain takeover
→ session theft, GraphQL introspection → authorization abuse (plus an optional
LLM pass for additional chains).

## Installing on a VM

The difference between a laptop install and a VM install is one flag.

```bash
git clone https://github.com/K3E9X/Syphax && cd Syphax
./install.sh --bind 0.0.0.0
./start.sh
```

`install.sh` generates `POSTGRES_PASSWORD` and `SYPHAX_SECRET_KEY` into `.env`
and `chmod 600`s it. It does not ship a working default for either: a default
that requires a human step is a default that survives into production.

### The two bind addresses, and why they are two

| Variable | Default | What it publishes |
| --- | --- | --- |
| `BIND_ADDRESS` | `127.0.0.1` | UI (3000) and API (8000) |
| `PROXY_BIND_ADDRESS` | `127.0.0.1` | mitmproxy (8080) |

They used to be one. An operator setting it to `0.0.0.0` wanted the UI
reachable from their laptop; they would also have published an HTTPS-
intercepting proxy that has **no authentication of its own**, will relay for
anyone who can reach it, and has a CA their devices trust. That is an open
relay acquired as a side effect. Two variables so it cannot happen by accident.

To use the proxy from another device, prefer an SSH tunnel:

```bash
ssh -N -L 8080:127.0.0.1:8080 operator@your-vm
```

### There is no TLS in this stack

The login page protects the API. It does not encrypt it. A password sent to
`http://your-vm:3000` is a password on the wire, and so is every captured
session the UI renders afterwards. Before exposing anything:

* put a reverse proxy with a certificate in front of 3000 and 8000 (caddy,
  nginx, traefik — any of them), **or**
* keep `BIND_ADDRESS=127.0.0.1` and reach the UI over an SSH tunnel:
  `ssh -N -L 3000:127.0.0.1:3000 -L 8000:127.0.0.1:8000 operator@your-vm`.

Behind a TLS terminator, forward `X-Forwarded-Proto: https` — the session
cookie sets its `Secure` flag from that header. Without it the cookie is issued
without `Secure` and a downgrade would send it in the clear.

Also set `CORS_ORIGINS` to the origin you actually serve the UI from; it still
lists `http://localhost:3000`.

### Unattended provisioning

```bash
./install.sh --yes --bind 0.0.0.0 \
    --admin-user operator \
    --admin-password "$(cat /run/secrets/syphax-admin)"
```

That writes `SYPHAX_ADMIN_USER` / `SYPHAX_ADMIN_PASSWORD` into `.env`, and the
first start creates the account from them. They are read **only when no account
exists**, so they can never reset an existing operator's password — but the
password is sitting in `.env` in plaintext until you remove those two lines,
which you should.

`--skip-build` writes `.env` and `./data` without needing Docker installed yet,
for the usual provisioning order of "lay down the config, then the runtime".

### Sizing

The backend image carries around twenty scanner binaries. Budget **12 GB of
free disk** for the build and 4 GB of RAM to run the stack; the installer warns
if the disk is short, because the error Docker prints when it runs out
mid-build is about a layer, not about disk.

`/dev/net/tun` must exist for the VPN endpoints (`modprobe tun`). Everything
else works without it.

## Platform specifics


Everything runs in containers, so the tool behaves the same everywhere. Three
things do differ, and all three are about talking to the host's network stack:

| | Linux | macOS (Docker Desktop / OrbStack) | Windows (WSL2) |
| --- | --- | --- | --- |
| Scans, proxy mode, sandbox runner | yes | yes | yes |
| VPN from the UI (`wg-quick` in the container) | yes | usually — userspace WireGuard via `/dev/net/tun` | usually — same |
| VPN on the host instead | yes | yes | yes |

The container ships `wireguard-tools` and `openvpn` and is given
`/dev/net/tun`, which is what the userspace implementation needs when the host
does not expose the kernel module — the normal situation on Docker Desktop. If
`POST /api/network/vpn/connect` fails on your machine, bring the tunnel up on
the host instead and leave the tool in `off` mode: the kill switch compares
exit IPs, so it protects the scan whoever owns the tunnel.

### Windows (WSL2)

The tool is Linux/Docker only, so on Windows run it inside WSL2:

1. Install WSL2 with a distro: `wsl --install` (PowerShell, admin), reboot.
2. Either install Docker Desktop and enable **Settings -> Resources -> WSL
   integration** for your distro, or install `docker-ce` directly inside the
   WSL distro.
3. Open the WSL shell (Ubuntu), `git clone` the repo **inside** the WSL
   filesystem (e.g. `~/syphax`, not `/mnt/c/...` - native FS is much faster),
   then run `./install.sh` / `./start.sh` exactly as on Linux.
4. Browse to http://localhost:3000 from Windows - WSL2 forwards localhost.

### ProtonVPN

A paid or free Proton account both work — you need a **WireGuard** config, not
the desktop app:

1. account.protonvpn.com -> **Downloads** -> **WireGuard configuration**
2. Name the key, pick a server, download the `.conf`
3. `mkdir -p data/vpn` and drop it there — `./data` is already bind-mounted
   into the backend as `/data`, and is gitignored so the key never gets committed
4. `.env`: `VPN_CONFIG_PATH=/data/vpn/<file>.conf`, then Connect from the Home
   card — or set `REQUIRE_VPN=true` first so no scan can start without it

Two things in a stock Proton config break inside a container, and the tool
rewrites a corrected copy rather than making you hand-edit the provider's file:

- `DNS = 10.2.0.1` would replace Docker's resolver, and the backend would stop
  resolving `postgres` — an outage that looks like a database problem, not a VPN
  one. The line is dropped; traffic still exits through the tunnel.
- The filename becomes the interface name, and `ch-fr-01.protonvpn.udp` is over
  the kernel's 15-character limit and contains dots. wg-quick rejects it with
  "invalid interface name", which reads like a malformed config. The copy is
  named `wg0.conf`.

Your original file is never modified. After connecting, hit **Check IP** — the
two IPs on the card must differ, and the Proton exit should show a Proton
netblock. `NAT-PMP (port forwarding)` and `NetShield` do not matter here;
NetShield's DNS filtering is irrelevant once the DNS line is dropped.

`wipe.sh` is a bash script. On Windows run it from the WSL shell, like the rest.

Shell scripts are pinned to LF by `.gitattributes`. If you clone with Git for
Windows and `core.autocrlf=true`, a CRLF shebang would make Docker report
`exec /usr/local/bin/entrypoint.sh: no such file or directory` for a file that
plainly exists.

## Tools bundled in the worker image

Recon: `nmap`, `naabu`, `subfinder`, `dnsx`, `httpx`, `katana`, `gau`.
Fingerprint / WAF: `whatweb`, `httpx`, `wafw00f`.
Content discovery: `ffuf`.
Parameter discovery: `arjun`, `jsluice`.
Vuln / CMS / server: `nuclei`, `nikto`, `wpscan`.
API: `schemathesis`. Client-side: `retire.js`.
Secrets / source: `trufflehog` (verified), `git-dumper`.
Injection: `sqlmap` (SQLi), `commix` (command).
XSS: `dalfox`. TLS: `testssl.sh`. Capture: `mitmproxy`.

`GET /api/scans/tools` reports each tool's category and whether its binary is
present. WordPress CVE correlation needs `WPSCAN_API_TOKEN` (free, optional).

### The six that need a word of explanation

- **`arjun`** (mapping) discovers undocumented HTTP parameters by differential
  response analysis. It produces **injection points, not findings**: every
  injection test can only decide things that have parameters, and `?debug=1`
  is in neither the HTML nor the JS. Discovered parameters are attached to the
  endpoint so the later phases pick them up.
- **`schemathesis`** (vuln) property-tests a published OpenAPI schema against
  the API's **own contract** — unhandled 500s, responses that violate the
  schema the API publishes, undocumented status codes, an operation that
  ignores the auth it declares. Runs only on an asset whose URL looks like a
  schema (`openapi`, `swagger`, `api-docs`), and only the fuzzing/examples
  phases: the coverage phase sends PUT/DELETE/TRACE to every operation, which
  is a write against a live target. Add `--phases=coverage` per scan if you
  want it.
- **`retire.js`** (vuln) rates the **client-side** libraries. Nothing else in
  the image looks at them: httpx and whatweb fingerprint the server, nuclei
  matches server-side CVEs. A page shipping jQuery 1.7.2 was invisible.
- **`jsluice`** (mapping) extracts URLs, parameters and secrets from a real
  JavaScript AST, so it sees endpoints built by string concatenation that a
  regex pass cannot, and reports the method and parameter names with them.
- **`git-dumper`** (vuln) **acts** on an exposed `.git` instead of only
  reporting that the path is readable: it rebuilds the working tree into
  `{DATA_DIR}/artifacts/{host}/git/`.
- **`trufflehog`** (vuln) scans that recovered tree and the captured
  JavaScript in `--results=verified` mode: it **authenticates each candidate
  secret against its own provider**, so a hit is a credential that answered,
  not a pattern that matched. It is the only tool here whose verdict is
  `confirmed` without syphax touching the target — the provider decided.
  Verification is an outbound call to AWS/GitHub/Stripe, never to the target.

`retire.js`, `jsluice` and `trufflehog` read files, not URLs. The proxy's
captured JavaScript is written to `{DATA_DIR}/artifacts/{host}/js/` at the
mapping → vuln-analysis boundary, so those tasks have something to read.
A directory that was never produced yields zero findings, not an error.

## Full configuration reference

| Variable                       | Purpose                                            |
| ------------------------------ | -------------------------------------------------- |
| `PLANNER/EXECUTOR/VALIDATOR_BASE_URL` `_API_KEY` `_MODEL` | Per-role LLM, for unattended provisioning. **Anything set in the UI wins**, and the UI is the normal path — it stores the key encrypted rather than in a file. Default `.env` puts the planner on Kimi K3 and the executor + validator on Z.ai GLM. |
| `LLM_PRICING`                  | `model=IN/OUT` USD per 1M tokens. **Without it the dashboard shows real token counts against $0.00 spend** — every unlisted model costs 0. |
| `USER_AGENT_MODE`              | `rotate` (default) impersonates a different real browser per job, headers included. `fixed` pins `USER_AGENT`. |
| `REQUIRE_VPN` / `SCAN_PROXY` / `VPN_CONFIG_PATH` | Route scan traffic through a proxy or tunnel, and refuse to scan when the exit IP still matches your real one. |
| `RESET_ON_START`               | Wipe scan artefacts on every boot (default `true`). See **Full wipe** below for what it does *not* cover. |
| `OPENROUTER_API_KEY` / `_MODEL` / `_FALLBACK_MODELS` | **Optional** free fallback aggregator, used only for roles whose own key is blank. |
| `SYPHAX_API_KEY`               | **Optional machine credential** for scripts and CI — an alternative to signing in, not a way to skip having an account. With no account it authorises nothing. Enforced on `/api` and on the WebSocket (as `?key=`, since a browser cannot set headers on a WS handshake). `/api/health`, `/api/auth/status` and `/api/auth/login` stay open. |
| `SYPHAX_ADMIN_USER` / `_PASSWORD` | Seeds the operator account on first start, for a VM built by a script. Read **only when no account exists**, so they cannot reset an existing password. |
| `SYPHAX_SECRET_KEY`            | Encrypts the stored provider API keys at rest. Generated by `install.sh`. If left blank the backend mints one into `./data/.settings.key` — which works until `./data` is not durable, and then every stored key silently stops decrypting. |
| `BIND_ADDRESS`                 | Interface for the UI (3000) and API (8000). `127.0.0.1` by default; `0.0.0.0` for a VM, behind TLS. |
| `PROXY_BIND_ADDRESS`           | Interface for mitmproxy (8080). Separate from `BIND_ADDRESS` on purpose — it is an unauthenticated intercepting proxy, so exposing it must be a deliberate act. |
| `LLM_RECON_MAX_FLOWS` / `_BODY_CHARS` / `_BUDGET_CHARS` | How much captured traffic the LLM response analyst sees. Defaults suit ~128K context; raise to `200` / `600000` for a 262K model. Flows are ranked (server errors > auth/validation errors > parameterised > plain 200s > 404s) and added until either cap binds. |
| `POSTGRES_*`                   | Database credentials (defaults work out of the box). |
| `WPSCAN_API_TOKEN`             | Optional WordPress CVE lookups.                    |

An OpenRouter key still covers every role at once if you prefer one account.
What no longer works is *no* key anywhere: the run gate refuses, in one 409
that names the fix, instead of starting a run that can only print raw scanner
output.

### Full wipe

`RESET_ON_START=true` clears scan artefacts (jobs, findings, flows, events,
runs, LLM usage) and the queued jobs in Redis every time the backend starts.
Engagement scope and the audit log survive on purpose — one is what makes a
scan legal, the other is the record of what ran.

Three things live outside that and explain why a "from scratch" restart can
still feel like it remembers:

| What | Survives `down` | Survives `down -v` |
| ---- | --------------- | ------------------ |
| `postgres-data` (named volume) | yes | no |
| `redis-data` (named volume)    | yes | no |
| `./data` (**bind mount**: mitmproxy CA, settings key) | yes | **yes** |

The bind mount is the surprising one. To remove everything:

```bash
./wipe.sh              # asks first
./wipe.sh --yes        # no prompt
./wipe.sh --keep-ca    # keep the mitmproxy CA so clients stay trusted
```

Dropping the CA means every client you configured must trust the new one, and
stored provider API keys become undecryptable — `--keep-ca` avoids both.

## Repository layout

```
backend/         FastAPI app + arq worker (one image, two roles)
  app/
    api/          REST + WebSocket routers
    auth/         accounts, sessions, login throttle, the gate (pure policy)
    recon/        pre-engagement passive recon; budget.py bounds what it sends
    engagements/  authorization gate + scope + per-engagement purge
    methodology/  WSTG x ATT&CK test catalog
    orchestrator/ planner, executor, run loop, state, approvals
    llm/          per-role router, provider catalog, readiness, usage/cost
    scans/        wrappers (23 tools) + queue runner + job storage
    exploit/      payload generation with an oracle, safe probe client
    analysis/     JS/secret mining, JWT, access control, GraphQL, correlation
    validation/   safe-PoC validators, corroboration, kill-chaining
    reporting/    client report (Markdown / HTML / JSON / SARIF)
    proxy/        mitmproxy addon + flow storage
    sandbox/      staging + client for the isolated PoC runner
    network/      VPN/proxy control and the exit-IP kill switch
    events.py     live event stream
    db.py         Postgres pool
  ruff.toml       lint rules, and why the noisy ones are off
  Dockerfile      multi-arch, bundles all CLI tools
frontend/         React + plain CSS, served by nginx
sandbox-runner/   the isolated image untrusted PoCs run in
docker-compose.yml   postgres, redis, backend, proxy, worker, orchestrator,
                     frontend, sandbox-runner
install.sh / start.sh / wipe.sh
```

## Architecture notes

- Single Postgres holds everything (engagements, jobs, findings, proxy flows,
  events, audit log); Redis is the arq job queue.
- The backend never spawns tools; it enqueues and a separate **worker**
  container runs them. The autonomous run is itself a long-lived worker task
  that launches scan sub-tasks concurrently.
- The MITM addon writes flows via sync psycopg; everything else uses asyncpg.

## Retesting the same target

Two things make a second engagement on a target worth more than the first.

**Diff.** `GET /api/engagements/<new>/diff?against=<old>` answers the retest
question: what was fixed, what came back, what is new. Findings are matched on
(class, endpoint path, title) with the query string dropped, because `?id=1`
and `?id=7` are the same issue - keeping it would report every retest as
entirely new. Only `confirmed` and `likely` findings are compared: one the
judge killed was never real, so it is neither a fix nor a regression.

**Memory.** After each validation, the engagement's final verdicts are folded
into a shared store keyed on (normalised technology, vuln_class). The planner
then puts classes that held up on this stack first *within a phase* -
`GET /api/engagements/<id>/memory` shows what it learned and why, and the Live
view prints it as a strip above the tabs.

It is deliberately conservative. Only final verdicts count (a `likely` is an
opinion, and remembering opinions compounds them), a lesson needs at least two
observations and better than 50% precision before it steers anything, and it
never adds or drops a task or touches a gate. On a fresh install it is empty
and does nothing.

## When a run is interrupted

The loop writes a heartbeat every iteration. If the worker dies, the run stays
at `running` with nothing driving it - which used to make `POST .../run` refuse
every new run with a 409 that never cleared. Starting a run now reclaims
anything with no live loop first, and marks it `failed` with
`stop_reason: interrupted`. The Live view shows `no worker reporting` on such a
run.

Coverage rows are kept on purpose: the planner skips what already ran, so the
next run **continues** rather than redoing the work. Just press Run again.

## Verifying a finding by hand

When an LLM validator role is configured, the judge proposes a *proof* for each
finding it reviews: one read-only request, plus the exact substring that
settles the question. The Live view shows it under the finding, and **Verify
proof** replays it through SafePoC and reports whether it held.

The verdict is a substring test, not a second opinion - the judge already chose
the observable. No response at all is reported as `inconclusive`, never as a
refutation: the target may simply have been down.

## How a finding gets its verdict (and why the FP rate is what it is)

Validation runs in two passes, and the report separates what the passes could
prove from what they could not.

**Per-finding.** In order, first match wins:

1. **Provider-verified.** trufflehog authenticated a secret against its own
   provider → `confirmed`. The provider decided, not us.
2. **Tool-confirmed.** sqlmap/commix/dalfox actively proved their own finding.
3. **Safe-PoC re-check.** An exposed resource is fetched and must match a real
   content signature (a dotenv line, an `.htaccess` directive, `[core]`); a
   reflected-XSS candidate gets a benign unique marker in **every** parameter.
4. **Catch-all baseline.** Once per engagement, syphax asks the target for a
   few paths that cannot exist and remembers the shape of the answer. On a
   server that returns 200 for everything, every guessed path "exists", so a
   path-existence finding whose answer has that same shape is `false_positive`,
   not `likely`. An honest 404 costs no extra request; a failed calibration
   discards nothing.
5. **Surface inventory.** A live host, a banner, a discovered path is not a
   weakness — it cannot be "likely vulnerable", so it is filed as
   informational and stays out of the FP-rate denominator. Previously nine
   registered tools had no class at all and their output shipped as `likely`
   findings next to real ones.
6. **Heuristic.** The scanner's own match, scaled by severity. nikto's
   findings are now rated from the message it prints, so an exposed `.git` and
   an `X-Powered-By` header are no longer the same finding.

**Across findings.** The whole validated set is then arbitrated, grouped by
`(vuln_class, target-without-query)` so sqlmap's `?id=1`, nuclei's bare path
and nikto's `:443` land in the same group:

- independent agreement raises confidence, counted by **distinct tool** — one
  noisy tool firing five templates is still one voice;
- an oracle that looked at the target and **could not reproduce** the class
  demotes the pattern matches that claimed it;
- a guess inherits ground from a proven sibling at the same target;
- a lone unchecked pattern match loses confidence.

Nothing is ever promoted to `confirmed` by agreement: agreement between
guesses is not proof, so unproven findings are capped below the confirmed
band. The reasoning is stored on the finding and printed in the report.

**Widening the oracle.** The adaptive prober used to reach query parameters
only, so a finding on `POST /api/login` or `GET /api/users/1337` could never
be *decided*. It now addresses three channels — query, a field of a request
body we actually captured, and a path segment that looks like a value. The
body channel is never invented: no captured request, no body channel, because
POSTing a guessed form to a guessed endpoint creates orders and sends mail.

**The report** puts proven findings in section 3 with their proofs and
unverified ones in section 4 as leads for manual confirmation. `meta` carries
`proven_findings`, `unverified_findings` and the real `false_positive_rate_pct`.

## Why a finding stayed unverified

`0 confirmed` is the most confusing line this tool prints. It reads as "the
scanner is broken", and it usually means something far more ordinary: an oracle
existed but a switch was off, or the input that oracle needs was never
captured.

Both facts were already known and both were thrown away. `run_cve_checks`
returned `{"skipped": 1, "reason": "allow_active_exploit is off"}` into a dict
nobody rendered, and the file-reading tools scanned an empty directory and
reported nothing - which looks exactly like finding nothing.

The live console now names each limit once, and the report prints the same
list under section 4, from the same function, so it cannot claim a
thoroughness the run did not have:

- **`allow_active_exploit` is off** and something needed a crafted request to
  be decided (a known CVE, an injection). The safe-PoC checks and the adaptive
  prober never ran.
- **the run ended early** (`exploit_denied`, `stopped`, `cancelled`) before the
  active phase.
- **no JavaScript was captured** through the proxy, so retire.js, jsluice and
  trufflehog had no files to read. Browse the target through the MITM proxy
  once, then re-run the analysis.
- **a tool's binary is missing** from the image, so its catalog items were
  skipped rather than failing the run.

A limit that blocked nothing is not reported: with no finding that needed an
active check, the gate cost nothing, and listing it would train you to ignore
the panel.

## One engagement at a time

Every screen is scoped to a single active engagement, remembered across reloads
and shared between pages: picking one on Findings picks it on Surface,
Methodology and Reports too. Findings used to default to "all engagements
(deduped)", which merged a second target's results into the first - a stale
exposed `.git` from yesterday read as part of today's scan. Aggregating is
still there, as a deliberate choice rather than the landing state.

### Deleting an engagement

`Close` only flips a status; the findings stay. **Delete** (on the engagement
inspector, confirmed by typing the target host) removes the engagement and
everything it produced: findings, chains, coverage, assets, fingerprints, jobs,
events, approvals, staged PoCs, runs and its token accounting. Recovered source
and cached JavaScript under `{DATA_DIR}/artifacts/{host}/` go with it - unless
another engagement still targets that host, in which case they stay.

Two things survive on purpose:

- **the audit trail** — the record of what was authorised and what ran. For an
  offensive tool that record is the point, so the deletion is itself audited;
- **the cross-engagement memory** — lessons are learning about a *kind of
  stack*, not this engagement's data, and they make the next run smarter.

Proxy capture is global rather than per-engagement and has its own control:
`DELETE /api/proxy/flows`.

The risk in a purge is not the DELETE, it is missing a table: rows that survive
keep surfacing in aggregate views and nothing fails loudly. So the covered
tables are checked against the registered schemas - a table added later with an
`engagement_id` column fails the test until it is either purged or listed as a
deliberate survivor.

## Running the tests

    cd backend  && pytest -q && ruff check .    # 1416 tests, no DB / network / LLM
    cd frontend && npm test && npm run lint     # 151 tests (vitest + jsdom)

### What CI checks

On every push:

| Job | What it answers |
| --- | --- |
| Backend | Does it parse, lint clean, and pass 1416 unit tests? |
| Frontend | Does it lint clean, pass 151 tests, and build? |
| Compose + Dockerfile | Is the compose file valid, do all three Dockerfiles lint, do the four shell scripts pass shellcheck? |
| Dependencies | Any known CVE in a pinned Python or npm package? |
| Wrapped tools | Does every pinned tool download still exist, on both architectures? |

Nightly, on `main` only:

* the same suite against the **latest** release of every test dependency, so a
  breaking upstream change is a warning before it is a broken pin;
* the four images built for **amd64 and arm64** under QEMU — the only way to
  catch a tool with no arm64 archive or a wheel with no aarch64 build;
* every test module imported with the CI dependency set *alone*, which is how
  a test that silently skipped in CI was found;
* a **smoke test**: a fresh install, booted, exercised from outside. Nothing
  is reachable before setup; setup creates the account and then refuses a
  second call; the session works and a wrong password does not; a run is
  refused while no model is configured; logout ends the session. Every one of
  those is checked in isolation by a unit test and by nothing end to end.

The linters are configured to catch bugs, not style — see `backend/ruff.toml`
and `frontend/eslint.config.js`, both of which explain what is deliberately
*off* and why. Their first run found eight defects, including an `except
ScopeError:` whose name was imported in a different function (so an
out-of-scope URL raised `NameError` instead of being skipped) and three places
where a failed load rendered as an empty result.

The frontend suite covers the shared data layer rather than the markup: that a
slow response cannot overwrite a newer one, that an error reaches `error`
instead of vanishing, that polling stops while the tab is hidden and refetches
on return, and that a panel keeps "loading", "broken" and "empty" as three
distinguishable states. It found a real bug on its first run - FastAPI returns
`detail` as a string for an HTTPException but as an array of objects for a 422,
and the array was handed straight to `new Error()`, so every validation failure
reached the operator as the literal text `[object Object]`.

## When the planner cannot answer

Reordering by LLM is advisory: the planner may re-rank tasks within a phase,
never add or drop one. So a planner that fails must not stop a run - the batch
keeps its deterministic catalog order and the engagement proceeds.

That fallback used to be silent. With no key for the planner role the code
returned early without logging anything, and a provider error only reached the
container's stderr. The run looked normal and the only trace was a zero next to
`planner` in the token panel, which is how it was actually noticed.

The live console now says it once per run, at info level, with the reason and
an explicit note that the run continues. If you see it and did not expect it,
check `PLANNER_API_KEY` - the default `.env` points the planner at Kimi
(`api.moonshot.ai`, `kimi-k3`) and ships the key empty.

## Where the tokens went

The `llm_usage` table always recorded the role, the timestamp and the
prompt/completion split. The UI showed one total and a per-model bar, so the
question that actually matters - *which part of the system is spending this* -
had no answer. The planner is re-invoked on every loop iteration, which is the
usual reason a run costs more than expected.

`GET /api/engagements/{id}/usage` now returns all of it, and the live view has
a **Tokens** tab showing:

- **by role** — planner / executor / validator, counted by distinct call. Two
  roles often share a model, so the per-model bar could never answer this;
- **prompt vs completion** — a run at 95% prompt is wasted context, and
  `LLM_RECON_BUDGET_CHARS` (150k) is the first thing to look at when it is;
- **burn rate** — tokens per minute over the window the engagement has run, so
  "is this going to cost $0.50 or $15?" is answerable *while* it runs;
- **tokens over the run** — a sparkline; a spike is usually the planner being
  re-asked;
- **most expensive calls** — because a summary cannot tell you that one
  80k-token prompt is the whole bill;
- **cost per confirmed finding** — the only ratio that says whether the spend
  bought anything.

The Home page carries the same role breakdown globally, next to the per-model one.

### The per-engagement budget now does something

`budget.per_engagement_usd` had an input in Settings from the start and
**nothing ever read it** — an operator could set a cap that did nothing while a
runaway planner loop billed freely. The orchestrator now checks it once per
iteration and ends the run with `stop_reason = llm_budget`; the live view and
the Tokens tab report the same state. A cap of 0, unset or unparseable means no
ceiling, never "always over": a guardrail that cannot be read must not stop a
run you asked for.

## Is the tunnel actually covering DNS?

A tunnel can carry the traffic while name lookups still go to the host resolver
in cleartext. `wg-quick` replaces `/etc/resolv.conf` with the provider's `DNS`,
which breaks resolution of `postgres` and `redis` inside the container - so the
DNS line used to be stripped, and every target lookup leaked.

Now the internal service IPs are resolved and pinned into `/etc/hosts` *before*
the tunnel comes up, which lets the tunnel keep its own DNS. The Home page
reports which of the two you have under **Target DNS via tunnel**; if pinning
failed it says so rather than pretending.
