"""The k3s manifests, checked against the properties compose gets for free.

These are configuration tests for the same reason tests/test_sandbox_isolation.py
is: the isolation IS the configuration. A manifest that drops a NetworkPolicy or
splits the pod keeps working perfectly - the UI comes up, scans run - and the
property it was carrying is gone with no symptom.

The one property that genuinely weakens in Kubernetes is the sandbox runner's.
In compose it is unaddressable; here it is filtered. That is written down in the
manifests and in deploy/k3s/README.md, and it is the operator's call - these
tests pin that the filtering is at least present and correct.
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

K3S = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "k3s"


def load(name: str):
    return [d for d in yaml.safe_load_all((K3S / name).read_text()) if d]


@pytest.fixture(scope="module")
def everything():
    docs = []
    for path in sorted(K3S.glob("*.yaml")):
        if path.name in ("kustomization.yaml", "secret.example.yaml"):
            continue
        docs.extend(d for d in yaml.safe_load_all(path.read_text()) if d)
    return docs


def of_kind(docs, kind, name=None):
    out = [d for d in docs if d.get("kind") == kind]
    if name:
        out = [d for d in out if d["metadata"]["name"] == name]
    return out


def pod_spec(deployment):
    return deployment["spec"]["template"]["spec"]


def containers(deployment):
    return {c["name"]: c for c in pod_spec(deployment)["containers"]}


# ---- everything parses and is namespaced ------------------------------------

def test_every_manifest_parses_and_lands_in_one_namespace(everything):
    assert everything, "no manifests found"
    for doc in everything:
        assert doc.get("apiVersion") and doc.get("kind"), doc
        if doc["kind"] != "Namespace":
            assert doc["metadata"].get("namespace") == "syphax", doc["metadata"]["name"]


def test_kustomization_lists_every_manifest():
    """A file that exists and is not applied is a property nobody has."""
    listed = set(yaml.safe_load((K3S / "kustomization.yaml").read_text())["resources"])
    on_disk = {p.name for p in K3S.glob("*.yaml")} - {"kustomization.yaml",
                                                      "secret.example.yaml",
                                                      "secret.yaml"}
    assert on_disk == listed, f"not applied: {sorted(on_disk - listed)}"


def test_the_real_secret_is_not_committed():
    assert not (K3S / "secret.yaml").exists()
    ignore = (K3S.parents[1] / ".gitignore").read_text()
    assert "deploy/k3s/secret.yaml" in ignore


def test_nothing_ships_with_a_working_credential():
    example = yaml.safe_load((K3S / "secret.example.yaml").read_text())
    for key, value in example["stringData"].items():
        if any(w in key for w in ("PASSWORD", "SECRET", "KEY", "TOKEN")):
            assert value in ("", "CHANGE-ME"), f"{key} ships with a usable value"


# ---- the shared network namespace -------------------------------------------

def test_the_four_services_share_one_pod(everything):
    """docker-compose puts worker, orchestrator and proxy on
    `network_mode: service:backend` because only the backend holds NET_ADMIN
    and /dev/net/tun, so it is the only namespace wg-quick can route. Splitting
    them into separate Deployments here would reintroduce that bug silently:
    everything keeps working and the tunnel covers nothing.
    """
    syphax = of_kind(everything, "Deployment", "syphax")[0]
    assert set(containers(syphax)) == {"backend", "proxy", "worker", "orchestrator"}


def test_only_the_backend_container_holds_net_admin(everything):
    syphax = of_kind(everything, "Deployment", "syphax")[0]
    for name, container in containers(syphax).items():
        caps = ((container.get("securityContext") or {}).get("capabilities") or {})
        added = set(caps.get("add") or [])
        if name == "backend":
            assert "NET_ADMIN" in added
        else:
            assert not added, f"{name} asks for {added}; it inherits the netns instead"


def test_the_tun_device_is_mounted_for_the_tunnel(everything):
    syphax = of_kind(everything, "Deployment", "syphax")[0]
    volumes = {v["name"]: v for v in pod_spec(syphax)["volumes"]}
    assert volumes["tun"]["hostPath"]["path"] == "/dev/net/tun"
    mounts = {m["name"] for m in containers(syphax)["backend"]["volumeMounts"]}
    assert "tun" in mounts


def test_the_stateful_workloads_never_run_two_at_once(everything):
    """Two orchestrators pick the same run off the queue, and every data claim
    here is ReadWriteOnce."""
    for name in ("syphax", "postgres", "redis"):
        deployment = of_kind(everything, "Deployment", name)[0]
        assert deployment["spec"]["replicas"] == 1
        assert deployment["spec"]["strategy"]["type"] == "Recreate"


def test_the_backend_service_keeps_the_name_nginx_proxies_to(everything):
    """frontend/nginx.conf hardcodes http://backend:8000. Renaming this Service
    means editing that file and rebuilding the image."""
    service = of_kind(everything, "Service", "backend")[0]
    assert service["spec"]["selector"] == {"app": "syphax"}
    assert [p["port"] for p in service["spec"]["ports"]] == [8000]


# ---- the sandbox runner -----------------------------------------------------

def test_the_runner_carries_nothing_worth_stealing(everything):
    """A trojaned PoC's usual objective is the environment. There is nothing in
    this one: no provider keys, no database password, no CA, no API token."""
    runner = of_kind(everything, "Deployment", "sandbox-runner")[0]
    container = containers(runner)["runner"]
    assert "envFrom" not in container, "that would hand it the secret"
    for entry in container.get("env") or []:
        assert entry["name"].startswith("SANDBOX_"), entry["name"]
    assert pod_spec(runner)["automountServiceAccountToken"] is False


def test_the_runner_writes_only_to_memory(everything):
    runner = of_kind(everything, "Deployment", "sandbox-runner")[0]
    container = containers(runner)["runner"]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    volumes = {v["name"]: v for v in pod_spec(runner)["volumes"]}
    for name in ("work", "run", "tmp"):
        assert volumes[name]["emptyDir"]["medium"] == "Memory", \
            f"{name} survives the pod on disk"
    assert not any(v.get("persistentVolumeClaim") for v in volumes.values())


def test_the_runner_drops_every_capability_but_the_one_it_needs(everything):
    """NET_ADMIN is held only long enough for entrypoint.sh to pin the egress
    rules; it drops to an unprivileged user immediately after."""
    runner = of_kind(everything, "Deployment", "sandbox-runner")[0]
    caps = containers(runner)["runner"]["securityContext"]["capabilities"]
    assert caps["drop"] == ["ALL"]
    assert caps["add"] == ["NET_ADMIN"]


def test_the_runner_cannot_resolve_a_service_name(everything):
    """Resolving one is the first step of reaching it. Its own iptables then
    close DNS entirely after boot, which closes it as a covert channel."""
    runner = of_kind(everything, "Deployment", "sandbox-runner")[0]
    assert pod_spec(runner)["dnsPolicy"] == "None"
    assert pod_spec(runner)["dnsConfig"]["nameservers"], "boot-time resolution must work"


def test_the_scope_defaults_to_deny_all(everything):
    """EMPTY MEANS DENY ALL OUTBOUND. A sandbox that silently allows the whole
    internet is worse than one that fails visibly."""
    runner = of_kind(everything, "Deployment", "sandbox-runner")[0]
    env = {e["name"]: e["value"] for e in containers(runner)["runner"]["env"]}
    assert env["SANDBOX_ALLOWED_HOSTS"] == ""


# ---- the policies that replace "no route" -----------------------------------

def test_only_the_api_may_reach_the_runner(everything):
    """Without this, any pod in any namespace could POST code to /v1/run. The
    approval flow lives in the API; this is what makes the API the only way in."""
    policy = of_kind(everything, "NetworkPolicy", "sandbox-runner-ingress")[0]
    assert policy["spec"]["podSelector"]["matchLabels"] == {"app": "sandbox-runner"}
    assert policy["spec"]["policyTypes"] == ["Ingress"]
    rule = policy["spec"]["ingress"][0]
    assert rule["from"] == [{"podSelector": {"matchLabels": {"app": "syphax"}}}]
    assert rule["ports"] == [{"protocol": "TCP", "port": 8090}]


def test_the_runner_reaches_the_internet_but_not_the_cluster(everything):
    """Compose gives this structurally - the runner is on a network Postgres is
    not on. Kubernetes routes everything to everything, so it has to be said."""
    policy = of_kind(everything, "NetworkPolicy", "sandbox-runner-egress")[0]
    assert policy["spec"]["policyTypes"] == ["Egress"]
    block = policy["spec"]["egress"][0]["to"][0]["ipBlock"]
    assert block["cidr"] == "0.0.0.0/0"
    # The k3s pod and service ranges: every other pod, plus Postgres, Redis and
    # the API server.
    assert set(block["except"]) == {"10.42.0.0/16", "10.43.0.0/16"}


def test_the_stores_refuse_anything_that_is_not_the_api(everything):
    """Belt and braces with the egress policy: that one stops the runner
    leaving, these stop the stores listening."""
    for name, port in (("postgres-ingress", 5432), ("redis-ingress", 6379)):
        policy = of_kind(everything, "NetworkPolicy", name)[0]
        rule = policy["spec"]["ingress"][0]
        assert rule["from"] == [{"podSelector": {"matchLabels": {"app": "syphax"}}}]
        assert rule["ports"] == [{"protocol": "TCP", "port": port}]


def test_the_stores_are_not_published_outside_the_cluster(everything):
    for name in ("postgres", "redis"):
        service = of_kind(everything, "Service", name)[0]
        assert service["spec"].get("type", "ClusterIP") == "ClusterIP"


# ---- exposure ---------------------------------------------------------------

def test_the_mitmproxy_port_has_no_ingress(everything):
    """It has no authentication of its own, relays for anyone who can reach it,
    and sits behind a CA the configured devices trust."""
    for ingress in of_kind(everything, "Ingress"):
        for rule in ingress["spec"]["rules"]:
            for path in rule["http"]["paths"]:
                assert path["backend"]["service"]["port"]["number"] != 8080
                assert path["backend"]["service"]["name"] != "mitmproxy"


def test_the_ingress_terminates_tls(everything):
    """The session cookie takes its Secure flag from X-Forwarded-Proto. Over
    plain HTTP it is issued without it, and the password that created it
    crossed the network in clear."""
    ingress = of_kind(everything, "Ingress", "syphax")[0]
    assert ingress["spec"]["tls"], "no TLS block"
    assert ingress["spec"]["tls"][0]["hosts"]
