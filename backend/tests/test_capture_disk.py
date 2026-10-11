"""Keep captured traffic from filling the disk.

A crawl of a real site stored every response body - images, video, fonts,
multi-MB bundles - and on a 2GB VM that filled the disk mid-run (11G -> 14G in
one run). Two levers: don't store bodies with no analysis value, and purge the
transient traffic after the analysers have read it.
"""
from __future__ import annotations

import sys
import types

import pytest

# addon imports mitmproxy; stub it so the pure helpers are importable here.
if "mitmproxy" not in sys.modules:
    m = types.ModuleType("mitmproxy")
    m.http = types.SimpleNamespace(HTTPFlow=object)
    sys.modules["mitmproxy"] = m
    sys.modules["mitmproxy.http"] = m.http

from app.proxy.addon import MAX_BODY_BYTES, _worth_storing


# ---- what is worth storing --------------------------------------------

@pytest.mark.parametrize("content_type", [
    "image/png", "image/jpeg", "image/gif", "video/mp4", "audio/mpeg",
    "font/woff2", "application/octet-stream", "application/pdf",
    "application/zip", "application/wasm", "model/gltf-binary",
    "application/vnd.ms-fontobject",
])
def test_binary_media_bodies_are_not_stored(content_type):
    """These are the bulk of captured bytes and nothing analyses them."""
    assert not _worth_storing(content_type)


@pytest.mark.parametrize("content_type", [
    "application/json", "application/json; charset=utf-8",
    "text/html", "text/html; charset=utf-8", "application/javascript",
    "text/javascript", "application/xml", "text/plain",
    "application/x-www-form-urlencoded", "application/graphql",
])
def test_bodies_the_analysers_read_are_stored(content_type):
    """Schema audit, JS mining, secret and PII scans all read these."""
    assert _worth_storing(content_type)


def test_an_unknown_content_type_is_kept():
    """Absent or unusual content type: keep it, it is usually text, and a
    missed binary is cheaper than a missed finding."""
    assert _worth_storing("")
    assert _worth_storing(None)
    assert _worth_storing("application/vnd.custom+json")


def test_the_body_cap_was_lowered():
    """2 MiB per body across a whole crawl was the disk problem."""
    assert MAX_BODY_BYTES <= 1024 * 1024


def test_a_dropped_binary_still_records_its_size():
    """The row stays honest: a dropped image still shows its true size in the
    UI. Asserted on the capture code, which sets response_size before deciding
    whether to keep the body."""
    import inspect

    from app.proxy import addon
    src = inspect.getsource(addon.FlowLogger._persist)
    size_at = src.index("response_size = len(resp.raw_content")
    body_at = src.index("response_body = (_truncate")
    assert size_at < body_at, "size must be recorded regardless of the body"


# ---- the purge actually frees disk ------------------------------------

def test_the_purge_truncates_rather_than_deletes():
    """DELETE leaves dead tuples that never return pages to the OS, so on a
    disk-constrained box it frees nothing. TRUNCATE drops the data files."""
    import inspect

    from app.proxy.storage import FlowRepository
    src = inspect.getsource(FlowRepository.purge)
    # the SQL it runs, not its prose: strip comment/docstring lines first.
    code = "\n".join(ln for ln in src.splitlines()
                     if not ln.strip().startswith("#"))
    assert 'execute("TRUNCATE flows")' in code
    assert 'execute("DELETE' not in code


def test_the_purge_is_off_by_default_and_env_gated():
    """A roomy box keeps the Proxy page populated; a small one opts in."""
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop._purge_captured_traffic)
    assert "PURGE_FLOWS_AFTER_RUN" in src
    assert '"false"' in src          # the default


def test_the_purge_runs_after_validation_not_during_it():
    """It must not clear flows an analyser still needs. It is the last thing
    _finalize_engagement does, after the validation try/except."""
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop._finalize_engagement)
    assert "_purge_captured_traffic(engagement, run)" in src
    assert src.index("validation phase error") < src.index("_purge_captured_traffic")


def test_the_purge_never_fails_the_run():
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop._purge_captured_traffic)
    assert "except Exception" in src and "logger.exception" in src


def test_the_knobs_are_documented():
    import pathlib
    env = (pathlib.Path(__file__).resolve().parents[2] / ".env.example").read_text()
    assert "PURGE_FLOWS_AFTER_RUN" in env
