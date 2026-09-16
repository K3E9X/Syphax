# Running Syphax on k3s

The shipping deployment is `docker compose`, and it stays that way — see the
repository root. These manifests exist for the case where the server you have
is already a k3s node and you would rather not install Docker beside it.

Nothing about the application changes. What changes is how four properties that
compose gets structurally are produced here, and one of them genuinely weakens.

---

## Install

Postgres, Redis and the data volume all use `ReadWriteOnce` claims and the
workloads are `Recreate`, so this is a **single-node** deployment. It will
schedule on a multi-node cluster and then fail to reschedule; pin it with a
`nodeSelector` if you have more than one.

```bash
# 1. Build the images and put them where k3s can see them.
#    On the node itself, no registry needed:
./build-and-import.sh
#    More than one node:
./build-and-import.sh --registry registry.example.com/syphax

# 2. Generate the secrets. Nothing ships with a working default.
./make-secret.sh > secret.yaml
#    ...or seed the first operator account at the same time:
./make-secret.sh --admin operator "a passphrase of your own" > secret.yaml

# 3. Apply.
kubectl apply -f secret.yaml
kubectl apply -k .

# 4. Watch it come up. The first start runs every CREATE TABLE.
kubectl -n syphax get pods -w
```

Then edit `08-ingress.yaml` — it ships with `syphax.example.com` and a
cert-manager annotation you almost certainly need to change — or skip the
Ingress entirely and reach it over a tunnel:

```bash
kubectl -n syphax port-forward svc/frontend 3000:80
```

Open it, create the operator account, connect a model. The tool does not run
without either.

---

## What changed from compose, and what that costs

### The four containers are one pod, and that is not tidiness

`docker-compose.yml` puts `worker`, `orchestrator` and `proxy` on
`network_mode: "service:backend"`. Only the backend holds `NET_ADMIN` and
`/dev/net/tun`, so its network namespace is the only one `wg-quick` can route.
Without the sharing, the scanners egress directly while the UI reports a
healthy tunnel — `verify_exit_ip()` measures the backend, not the tools that
are actually sending traffic.

Containers in a pod share a network namespace natively, so one pod is the exact
translation. **Splitting these into four Deployments would reintroduce that bug
silently**: everything keeps working and the tunnel covers nothing.

### The sandbox runner's isolation changed in kind

This is the one that is genuinely weaker, and it is worth understanding before
you run a third-party PoC here.

In compose, the runner is attached to a network that Postgres, Redis and the
backend's secrets are not on. There is no route to them. Not filtered —
**unaddressable**. `backend/tests/test_sandbox_isolation.py` says so in as many
words, because that distinction is the whole design.

Kubernetes has no equivalent. Every pod gets a network and can address every
Service, so the same property has to be *written down* as NetworkPolicy
(`07-networkpolicy.yaml`):

* nothing reaches the runner except the API pod, on 8090 — so the approval flow
  in the API is the only way to get code into it;
* the runner reaches the internet but not `10.42.0.0/16` or `10.43.0.0/16`, the
  k3s pod and service ranges — which is where Postgres, Redis and the API
  server live;
* Postgres and Redis separately refuse anything that is not the API pod.

k3s enforces NetworkPolicies by default (kube-router). **On a cluster started
with `--disable-network-policy`, or with a CNI that ignores them, all of that is
inert and the runner can reach the database.** Nothing in these manifests
detects that — you were offered a startup check and declined it, which is a
reasonable call for a cluster you control. If you ever hand this to someone
else's cluster, check first:

```bash
ps -ef | grep -o 'disable-network-policy'      # on the node
kubectl -n syphax get networkpolicy
```

Two things did carry over intact: the runner has no secret mounted, no data
volume, and no service-account token, so there is nothing worth reaching the
database *for*; and `dnsPolicy: None` means it cannot resolve a Service name,
which is the first step of reaching one.

### `/dev/net/tun` is a hostPath

`04-syphax.yaml` mounts the node's `/dev/net/tun` and gives the backend
container `NET_ADMIN`. That is a privileged-ish pod on your cluster, and it is
what the VPN endpoints need. Load the module on the node first:

```bash
sudo modprobe tun
```

If you would rather not, delete the `tun` volume and its mount: everything works
except `POST /api/network/vpn/connect`. Bring the tunnel up on the host instead
— the kill switch compares exit IPs and protects the scan whoever owns the
tunnel.

### `./data` became a PVC

The bind mount held the mitmproxy CA and, when `SYPHAX_SECRET_KEY` is unset, the
generated at-rest key. `make-secret.sh` always sets that key, so losing the
volume costs you the CA (every client you configured must trust a new one) and
nothing else.

---

## Day to day

```bash
# The mitmproxy port is deliberately not exposed. Reach it over a tunnel.
kubectl -n syphax port-forward svc/mitmproxy 8080:8080

# Scope the sandbox before approving a PoC. EMPTY MEANS DENY ALL OUTBOUND.
kubectl -n syphax set env deploy/sandbox-runner \
    SANDBOX_ALLOWED_HOSTS=app.example.com

# Logs, per container - they share a pod.
kubectl -n syphax logs deploy/syphax -c backend -f
kubectl -n syphax logs deploy/syphax -c orchestrator -f
kubectl -n syphax logs deploy/sandbox-runner

# Forgotten the operator password. There is no reset link.
kubectl -n syphax exec deploy/postgres -- \
    psql -U syphax -d syphax -c 'DELETE FROM user_sessions; DELETE FROM users;'

# Remove everything, including the data.
kubectl delete -k .
kubectl -n syphax delete pvc --all
```

## What is not here

No HorizontalPodAutoscaler, no PodDisruptionBudget, no multi-replica anything.
One orchestrator is a design constraint, not a limitation waiting to be lifted:
a second one picks the same run off the queue.

No Helm chart. These are eight files with comments in them; a chart would add a
values schema over a deployment that has one shape.
