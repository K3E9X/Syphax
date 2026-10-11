"""A run that spent 206 jobs on an image resizer and reached nothing.

www.khelassischool.com, iteration 28, 206 jobs, 0 findings, exploitation and
validation never reached. The console was one line repeated:

    [task_launched] nuclei -> /_next/image?url=%2F_next%2Fstatic%2Fmedia%2F
                             hichem1.b98e2c6a.gif&w=1920&q=75

Next.js serves every image through /_next/image, once per breakpoint. 89 of
the 197 endpoints discovered were that one resizer. Three defects in the
planner's own ranking stacked up, all mine:

  * _is_static_asset tested the path's EXTENSION. /_next/image has none - the
    file is in the query string - so the resizer was never recognised.
  * asset_interest returned 1 for anything with a query string BEFORE testing
    whether the path was dull, so the check that would have caught it was
    unreachable for exactly the URLs that needed it.
  * nothing collapsed parameter VALUES, so the same test was queued once per
    breakpoint.
"""
from __future__ import annotations

import pytest

from app.orchestrator.planner import (_is_static_asset, _one_per_shape,
                                      asset_interest, injection_shape)
from app.orchestrator.state import Asset

RESIZER = ("https://www.khelassischool.com/_next/image"
           "?url=%2F_next%2Fstatic%2Fmedia%2Fhichem1.b98e2c6a.gif&w={w}&q=75")


# ---- the resizer is a static asset, parameters and all ----------------

@pytest.mark.parametrize("url", [
    RESIZER.format(w=384), RESIZER.format(w=1920),
    "https://t.example/_vercel/image?url=/a.png&w=64",
    "https://t.example/cdn-cgi/image/width=80/logo.png",
    "https://t.example/_ipx/w_200/img/hero.jpg",
    "https://t.example/_nuxt/image?src=/a.png",
    "https://t.example/_astro/hero.abc123.webp",
])
def test_an_image_pipeline_is_recognised_without_an_extension_in_the_path(url):
    assert _is_static_asset(url)


def test_an_unknown_resizer_is_caught_by_the_file_it_serves():
    """A path we have never heard of, whose url= points at a .jpg, is the
    same thing under another name."""
    assert _is_static_asset("https://t.example/thumb.php?src=/media/a.jpg&w=90")
    assert _is_static_asset("https://t.example/i?file=/assets/logo.svg")


@pytest.mark.parametrize("url", [
    "https://t.example/api/v1/users?id=1",
    "https://t.example/search?q=test",
    "https://t.example/download?file=report",     # no static extension
    "https://t.example/login",
])
def test_a_real_endpoint_is_not_mistaken_for_one(url):
    """The filter must not eat the injection points it sits next to -
    ?file=report is exactly the parameter an LFI test wants."""
    assert not _is_static_asset(url)


# ---- dullness is decided before the parameterised bonus ---------------

def test_the_resizer_ranks_behind_everything_worth_a_job():
    """It scored 1, level with /api/v1/users?id= - that is what spent the
    budget. Lower is better."""
    assert asset_interest(RESIZER.format(w=1920)) > \
        asset_interest("https://t.example/api/v1/users?id=1")
    assert asset_interest(RESIZER.format(w=1920)) > \
        asset_interest("https://t.example/about")


def test_a_parameterised_static_file_is_still_a_static_file():
    """A cache-buster does not turn a stylesheet into an injection point."""
    assert asset_interest("https://t.example/static/app.css?v=3") >= 85


def test_a_real_injection_point_still_ranks_first():
    """The fix must not cost what the ordering was built for."""
    assert asset_interest("https://t.example/api/v1/users?id=1") == 1
    assert asset_interest("https://t.example/search?q=x") == 1


def test_the_engagement_target_still_outranks_everything():
    assert asset_interest("https://t.example/", source="engagement") == 0


# ---- one budget slot per injection shape ------------------------------

def test_two_breakpoints_of_one_image_are_one_test():
    assert injection_shape(RESIZER.format(w=384)) == \
        injection_shape(RESIZER.format(w=1920))


def test_two_pages_of_one_listing_are_one_test():
    assert injection_shape("https://t.example/products?page=1") == \
        injection_shape("https://t.example/products?page=2")


def test_a_different_parameter_set_is_a_different_test():
    """?page= and ?page=&sort= are not the same surface: the second has a
    parameter the first never exercises."""
    assert injection_shape("https://t.example/products?page=1") != \
        injection_shape("https://t.example/products?page=1&sort=name")


def test_a_different_path_is_a_different_test():
    assert injection_shape("https://t.example/a?id=1") != \
        injection_shape("https://t.example/b?id=1")


def test_a_different_host_is_a_different_test():
    assert injection_shape("https://a.example/x?id=1") != \
        injection_shape("https://b.example/x?id=1")


def test_a_param_less_endpoint_has_no_shape_and_is_never_collapsed():
    """Distinct paths are distinct tests; folding them would lose coverage."""
    assert injection_shape("https://t.example/about") == ""
    assets = [Asset(kind="endpoint", value=f"https://t.example/p{n}")
              for n in range(20)]
    assert len(_one_per_shape(assets)) == 20


def test_the_run_that_prompted_this_collapses_to_a_handful():
    urls = ([RESIZER.format(w=w) for w in (384, 828, 1080, 1200, 1920)] * 18
            + [f"https://t.example/products?page={n}" for n in range(1, 21)]
            + ["https://t.example/api/v1/users?id=1",
               "https://t.example/search?q=x",
               "https://t.example/login"])
    assets = [Asset(kind="endpoint", value=u, has_params="?" in u) for u in urls]
    assets.sort(key=lambda a: (asset_interest(a.value), a.value))
    kept = _one_per_shape(assets)
    assert len(urls) > 100
    assert len(kept) == 5
    # And the order is what the budget is spent in.
    assert kept[0].value.startswith("https://t.example/api/v1/users")
    assert "_next/image" in kept[-1].value


def test_hosts_are_never_collapsed():
    hosts = [Asset(kind="host", value=f"h{n}.example") for n in range(5)]
    assert len(_one_per_shape(hosts)) == 5


def test_the_collapse_keeps_the_best_ranked_representative():
    """It keeps the FIRST of each shape, which is the best one only because
    the caller sorts first. If that ever stops being true the budget starts
    buying the worst URL of each shape."""
    import inspect

    from app.orchestrator import planner
    src = inspect.getsource(planner.Planner._candidate_tasks)
    sort_at = src.index("assets = sorted(")
    collapse_at = src.index("_one_per_shape(assets)")
    assert sort_at < collapse_at


def test_collapsing_is_in_the_budget_not_in_discovery():
    """The user's standing requirement: discovery stays unbounded. Every URL
    must still reach the assets table and the Surface page - what stops is
    paying for the same test twice."""
    import inspect

    from app.orchestrator import planner, state
    assert "_one_per_shape" not in inspect.getsource(state.EngagementState.add_asset)
    assert "_one_per_shape" in inspect.getsource(planner.Planner._candidate_tasks)


# ---- our own proxy is not the target's technology ---------------------

@pytest.mark.parametrize("tech", ["mitmproxy 12.2.3", "mitmproxy", "mitmdump"])
def test_the_capture_proxy_is_not_reported_as_the_targets_stack(tech):
    """Every tool runs through it, so whatweb fingerprints it. It appeared in
    the Surface panel, would appear in the report, and feeds the `tech_any`
    conditions that gate catalog items."""
    from app.orchestrator.state import fingerprint_noise
    reason = fingerprint_noise(tech)
    assert reason and "own capture proxy" in reason


@pytest.mark.parametrize("plugin", ["country", "ip", "title", "script",
                                    "html5", "httpserver", "uncommonheaders"])
def test_whatwebs_contentless_plugins_are_not_technologies(plugin):
    """They fire on essentially every site. No catalog item can usefully gate
    on "this response had a title"."""
    from app.orchestrator.state import fingerprint_noise
    assert fingerprint_noise(plugin)


@pytest.mark.parametrize("tech", ["vercel", "hsts", "nginx 1.25", "wordpress",
                                  "waf:cloudflare", "express", "php 8.2"])
def test_a_real_technology_is_kept(tech):
    from app.orchestrator.state import fingerprint_noise
    assert fingerprint_noise(tech) == ""


def test_dropping_a_fingerprint_is_said_out_loud():
    """An operator who notices mitmproxy missing should be able to find out
    that we removed it - in case the target really does run one."""
    import inspect

    from app.orchestrator import state
    src = inspect.getsource(state.EngagementState.add_fingerprint)
    assert "_say_fingerprint_dropped" in src


# ---- a cancelled run keeps what it already found ---------------------

def test_cancelling_still_validates_what_the_run_collected():
    """206 jobs ran and the Findings page was empty. The graceful stop paths
    fall into _finalize_engagement - whose own comment says "Always run it
    (even on stop) so partial results are still validated" - but the
    CancelledError path persisted the row and re-raised. Pressing Stop is
    exactly what an operator does when they can see the budget being wasted,
    and it threw away the whole run."""
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    # rindex: the per-iteration try block has its own `except CancelledError`
    # that simply re-raises. The one that ends the run is the last.
    handler = src[src.rindex("except asyncio.CancelledError:"):]
    assert "_salvage_on_cancel" in handler
    assert handler.index("_salvage_on_cancel") < handler.rindex("raise")


def test_the_salvage_is_bounded():
    """The operator pressed Stop and is watching."""
    from app.orchestrator.loop import CANCEL_SALVAGE_SECONDS
    assert 30 <= CANCEL_SALVAGE_SECONDS <= 300


class _Run:
    id = "run1"
    jobs_launched = 206
    phase = ""
    stop_reason = "cancelled"


class _Eng:
    id = "eng1"


class _Runs:
    async def update(self, run):
        return None


def _salvage_with(monkeypatch, failure):
    """Run _salvage_on_cancel with a finalisation that raises `failure`."""
    import asyncio

    from app.orchestrator import loop

    async def _boom(*args, **kwargs):
        raise failure

    monkeypatch.setattr(loop, "_finalize_engagement", _boom)
    return asyncio.run(
        loop._salvage_on_cancel(_Eng(), _Run(), _Runs(), None, set()))


def test_a_second_cancel_stops_immediately(monkeypatch):
    """Everything else is swallowed, but a second cancel is the operator
    saying they meant it - so it must propagate, not be absorbed."""
    import asyncio

    with pytest.raises(asyncio.CancelledError):
        _salvage_with(monkeypatch, asyncio.CancelledError())


def test_a_failure_inside_the_salvage_does_not_mask_the_cancel(monkeypatch):
    """The run is already being cancelled; a broken analyser must not turn
    that into a crash that loses the run row too."""
    assert _salvage_with(monkeypatch, ValueError("analyser exploded")) is None


def test_a_slow_salvage_gives_up_rather_than_hanging_the_stop(monkeypatch):
    import asyncio

    from app.orchestrator import loop

    async def _slow(*args, **kwargs):
        await asyncio.sleep(10)

    monkeypatch.setattr(loop, "_finalize_engagement", _slow)
    monkeypatch.setattr(loop, "CANCEL_SALVAGE_SECONDS", 0.2)
    asyncio.run(loop._salvage_on_cancel(_Eng(), _Run(), _Runs(), None, set()))


def test_the_salvage_never_masks_a_failure_into_a_crash():
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop._salvage_on_cancel)
    assert "asyncio.TimeoutError" in src
    assert "logger.exception" in src


def test_no_active_step_runs_on_a_cancelled_run():
    """The operator stopped it. Validation is read-only; exploitation is not,
    and every active block already gates on this."""
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop._finalize_engagement)
    assert '_suppressed = {"exploit_denied", "stopped", "cancelled"}' in src
    assert src.count("run.stop_reason not in _suppressed") >= 3
    assert '_active_ok = run.stop_reason not in {"exploit_denied", "stopped", "cancelled"}' in src


def test_the_operator_is_told_the_run_is_salvaging():
    """A silent 120-second pause after pressing Stop reads as a hang."""
    import inspect

    from app.orchestrator import loop
    src = inspect.getsource(loop._salvage_on_cancel)
    assert "events.emit" in src
    assert "Validating what" in src
