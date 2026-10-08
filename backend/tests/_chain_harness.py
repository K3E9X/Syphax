"""In-memory stand-ins for the repositories, so the REAL proof chain can run.

Every other test in this suite is a unit test that never touches Postgres
(see conftest.py). That is how a run could spend its entire job budget before
reaching the exploitation phase with 2000 tests green: each unit was correct and
nothing exercised the chain.

This module fakes the four repositories, the event bus and the sandbox - the
I/O edges - and nothing else. validate_engagement, run_campaign, strategy,
authoring, refine, poc_run and cve_checks all run for real on top of it.
"""
from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from app.scans.models import Finding
from app.validation.models import ValidatedFinding


# --------------------------------------------------------------------------- #
# repositories

class FakeVFRepo:
    """validated_findings. Shared store so every instance sees the same rows,
    which is what a real repository does and what the chain depends on."""

    store: Dict[str, ValidatedFinding] = {}

    @classmethod
    def reset(cls):
        cls.store = {}

    async def replace_for_engagement(self, engagement_id: str,
                                     items: List[ValidatedFinding]) -> None:
        # DELETE + INSERT, exactly like the real one - this is what used to
        # orphan every staged PoC.
        for vf_id in [k for k, v in self.store.items()
                      if v.engagement_id == engagement_id]:
            del self.store[vf_id]
        for item in items:
            self.store[item.id] = item

    async def list(self, engagement_id: str) -> List[ValidatedFinding]:
        return [v for v in self.store.values() if v.engagement_id == engagement_id]

    async def get(self, vf_id: str) -> Optional[ValidatedFinding]:
        return self.store.get(vf_id)

    async def update_verdict(self, vf_id: str, *, status: str, confidence: float,
                             method: str) -> None:
        vf = self.store.get(vf_id)
        if vf is None:
            return
        vf.status = status
        vf.confidence = confidence
        vf.method = method

    async def set_metadata(self, vf_id: str, patch: Dict[str, Any]) -> None:
        vf = self.store.get(vf_id)
        if vf is None:
            return
        vf.metadata = {**(vf.metadata or {}), **patch}

    async def set_chain(self, vf_id: str, chain_id: str) -> None:
        pass

    async def summary(self, engagement_id: str) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for vf in await self.list(engagement_id):
            out[vf.status] = out.get(vf.status, 0) + 1
        out["total"] = sum(out.values())
        return out


class FakeStagedRepo:
    store: Dict[str, Any] = {}

    @classmethod
    def reset(cls):
        cls.store = {}

    async def create(self, poc) -> None:
        self.store[poc.id] = poc

    async def get(self, poc_id: str):
        return self.store.get(poc_id)

    async def list(self, engagement_id: str):
        return [p for p in self.store.values() if p.engagement_id == engagement_id]

    async def attach_run_result(self, poc_id: str, result: Dict[str, Any]) -> None:
        poc = self.store.get(poc_id)
        if poc is not None:
            poc.inspection = {**(poc.inspection or {}), "run_result": result}

    async def set_status(self, poc_id: str, status: str, *, decided_by: str = "") -> None:
        poc = self.store.get(poc_id)
        if poc is not None:
            poc.status = status
            poc.decided_by = decided_by

    async def repoint_findings(self, engagement_id: str, mapping: Dict[str, str]) -> int:
        moved = 0
        for poc in self.store.values():
            if poc.engagement_id != engagement_id:
                continue
            new_id = mapping.get(getattr(poc, "finding_id", None))
            if new_id:
                poc.finding_id = new_id
                moved += 1
        return moved


class FakeJobRepo:
    jobs: List[Any] = []

    @classmethod
    def reset(cls):
        cls.jobs = []

    async def list_by_engagement(self, engagement_id: str):
        return [j for j in self.jobs if j.engagement_id == engagement_id]


def job(tool: str, findings: List[Finding], *, engagement_id="eng_1", job_id=None):
    return SimpleNamespace(
        id=job_id or f"job_{tool}", tool=tool, engagement_id=engagement_id,
        findings=findings, status="completed", target="https://app.example.com/",
        created_at=time.time(),
    )


def engagement(**kw):
    base = dict(
        id="eng_1", target_url="https://app.example.com/",
        target_host="app.example.com", scope_hosts=["app.example.com"],
        allow_active_exploit=True, allow_sql_os_cmd=False, allow_data_proof=False,
        allow_destructive=False, allow_persistence=False,
        allow_denial_of_service=False, allow_credential_spray=False,
        budget_requests=None, budget_seconds=None,
    )
    base.update(kw)
    eng = SimpleNamespace(**base)
    eng.host_in_scope = lambda h: h in base["scope_hosts"] or any(
        h.endswith("." + s) for s in base["scope_hosts"])
    return eng


# --------------------------------------------------------------------------- #
# installation

# Modules in the proof chain. Imported before any swap, because
# _swap_everywhere can only reach modules that are already in sys.modules - and
# a module imported LATER would bind the real, DB-backed class.
_CHAIN_MODULES = (
    "app.audit", "app.events",
    "app.engagements", "app.engagements.storage",
    "app.scans.storage",
    "app.validation.storage", "app.validation.run", "app.validation.validator",
    "app.validation.baseline", "app.validation.safe_poc",
    "app.sandbox.staging", "app.sandbox.runner_client", "app.sandbox.inspect",
    "app.exploit.campaign", "app.exploit.poc_run", "app.exploit.authoring",
    "app.exploit.refine", "app.exploit.strategy", "app.exploit.vetting",
    "app.exploit.cve_checks", "app.exploit.payload_gen", "app.exploit.proof",
    "app.exploit.settings_live", "app.exploit.poc_select",
    "app.analysis._store", "app.intel.cloud_creds",
    "app.orchestrator.state", "app.analysis.param_discovery",
)


def _import_chain() -> None:
    import importlib
    for name in _CHAIN_MODULES:
        try:
            importlib.import_module(name)
        except Exception:  # noqa: BLE001 - an optional module is not fatal
            pass


def _swap_everywhere(monkeypatch, attr_name, replacement, *,
                     only_module_prefix=None):
    """Replace `attr_name` in every loaded app module that binds it.

    `from app.validation.storage import ValidatedFindingRepository` copies the
    class object into the importing module's namespace, so patching the
    definition site does nothing for the importers. A hand-maintained list of
    paths goes stale the moment someone adds an import - and the symptom is a
    test that quietly talks to a real database.
    """
    import sys

    for name, module in list(sys.modules.items()):
        if not name.startswith("app.") and name != "app":
            continue
        if only_module_prefix and not name.startswith(only_module_prefix):
            continue
        if getattr(module, attr_name, None) is None:
            continue
        monkeypatch.setattr(module, attr_name, replacement, raising=False)


def install(monkeypatch, *, eng=None, jobs=None, sandbox=None, llm_reply=None,
            events_sink=None):
    """Patch the I/O edges. Returns the pieces the test wants to inspect."""
    _import_chain()
    FakeVFRepo.reset()
    FakeStagedRepo.reset()
    FakeJobRepo.reset()
    eng = eng or engagement()
    FakeJobRepo.jobs = list(jobs or [])
    emitted: List[str] = events_sink if events_sink is not None else []

    # `from app.x import Y` binds Y into the importing module at import time, so
    # patching app.x.Y leaves every importer pointing at the real, DB-backed
    # class. Rather than maintain a list of paths that silently goes stale, swap
    # the attribute wherever it is bound.
    _swap_everywhere(monkeypatch, "ValidatedFindingRepository", FakeVFRepo)
    _swap_everywhere(monkeypatch, "StagedPoCRepository", FakeStagedRepo)
    _swap_everywhere(monkeypatch, "JobRepository", FakeJobRepo)

    class _EngRepo:
        async def get(self, _id):
            return eng

        async def list(self, *a, **k):
            return [eng]

    _swap_everywhere(monkeypatch, "EngagementRepository", _EngRepo)

    async def _emit(engagement_id, kind, message="", **kw):
        emitted.append(str(message))

    monkeypatch.setattr("app.events.emit", _emit)
    _swap_everywhere(monkeypatch, "emit", _emit, only_module_prefix="app.events")

    async def _audit(*a, **k):
        return None

    # `from app.audit import audit` binds the function into each module at
    # import time, so patching app.audit.audit alone leaves every one of them
    # pointing at the real, DB-backed version. Patch the bound names too.
    monkeypatch.setattr("app.audit.audit", _audit, raising=False)
    _swap_everywhere(monkeypatch, "audit", _audit)

    # The sandbox. `sandbox` is a callable(code, language, argv) -> dict.
    from app.sandbox import runner_client

    async def _health():
        if sandbox is None:
            raise runner_client.SandboxUnavailable("no runner in this test")
        return {"status": "ok", "egress_locked": True,
                "egress_mode": "per-request",
                "clients": {"python_requests": True, "curl": True, "node": True}}

    async def _run_poc(code, *, language="python", scope_hosts, argv=None, timeout=60):
        if sandbox is None:
            raise runner_client.SandboxUnavailable("no runner in this test")
        out = sandbox(code, language, list(argv or []))
        return runner_client.SandboxResult(
            exit_code=out.get("exit_code", 0), timed_out=out.get("timed_out", False),
            duration_s=0.1, stdout=out.get("stdout", ""), stderr=out.get("stderr", ""),
            scope_hosts=list(scope_hosts))

    monkeypatch.setattr(runner_client, "health", _health)
    monkeypatch.setattr(runner_client, "run_poc", _run_poc)

    async def _available():
        return sandbox is not None

    monkeypatch.setattr(runner_client, "is_available", _available)

    # The model. `llm_reply` is a str or a callable(messages) -> str.
    if llm_reply is not None:
        class _Client:
            configured = True
            model = "fake-model"
            last_used_model = "fake-model"

            async def chat(self, messages, **kw):
                return llm_reply(messages) if callable(llm_reply) else llm_reply

        class _Router:
            def get(self, _role):
                return _Client()

        monkeypatch.setattr("app.llm.get_router", lambda: _Router())
        monkeypatch.setattr("app.exploit.authoring.get_router", lambda: _Router())

    # Settings read at point of use.
    async def _true():
        return True

    async def _iters():
        return 2

    monkeypatch.setattr("app.exploit.settings_live.auto_run_poc", _true)
    monkeypatch.setattr("app.exploit.settings_live.refine_iterations", _iters)

    async def _no_key(_name):
        return ""

    monkeypatch.setattr("app.settings_store.get_integration_key", _no_key,
                        raising=False)

    return SimpleNamespace(eng=eng, vf=FakeVFRepo(), pocs=FakeStagedRepo(),
                           events=emitted)


def fake_http(monkeypatch, routes, *, default_status=404, default_body=""):
    """Patch SafePoC.fetch. `routes` maps a URL substring -> (status, body).

    Longest match wins, so a specific path beats a prefix. Anything unmatched
    answers `default_status`, which is how the 404 triage filter is exercised.
    """
    seen: List[str] = []

    async def _fetch(self, url, method="GET", **kw):
        seen.append(url)
        best = None
        for marker, value in routes.items():
            if marker in url and (best is None or len(marker) > len(best[0])):
                best = (marker, value)
        status, body = best[1] if best else (default_status, default_body)
        return SimpleNamespace(
            status_code=status, text=body, content=body.encode(),
            headers={"content-type": "text/html"}, url=url, elapsed_ms=5,
            request_headers={}, json=lambda: {})

    from app.validation.safe_poc import SafePoC
    monkeypatch.setattr(SafePoC, "fetch", _fetch)
    return seen


def fake_analysis_store(monkeypatch):
    """Capture save_analysis_job instead of writing a job row."""
    saved: List[Dict[str, Any]] = []

    async def _save(engagement_id, tool, findings, *, target="", **kw):
        saved.append({"tool": tool, "findings": list(findings), "target": target})
        FakeJobRepo.jobs.append(job(tool, list(findings),
                                    engagement_id=engagement_id,
                                    job_id=f"job_{tool}_{len(saved)}"))

    for path in ("app.analysis._store.save_analysis_job",
                 "app.exploit.cve_checks.save_analysis_job",
                 "app.exploit.payload_gen.save_analysis_job",
                 "app.intel.cloud_creds.save_analysis_job"):
        monkeypatch.setattr(path, _save, raising=False)
    return saved


def fake_state(monkeypatch, *, technologies=(), assets=()):
    """EngagementState without a database."""
    class _State:
        def __init__(self, engagement_id):
            self.engagement_id = engagement_id

        async def technologies(self):
            return list(technologies)

        async def assets(self, kind=None):
            return [a for a in assets if kind is None or a.kind == kind]

        async def add_asset(self, *a, **k):
            return None

        async def add_fingerprint(self, *a, **k):
            return None

    for path in ("app.orchestrator.state.EngagementState",
                 "app.analysis.param_discovery.EngagementState"):
        monkeypatch.setattr(path, _State, raising=False)
    return _State
