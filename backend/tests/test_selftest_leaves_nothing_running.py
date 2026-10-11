"""The self-test must not print a traceback under its own verdict.

A real run ended like this:

    Nothing broken.
    Exception ignored in: <function BaseSubprocessTransport.__del__ ...>
    RuntimeError: Event loop is closed

ffuf, gau, nmap and nuclei all reach the invocation check's timeout branch -
"accepted its arguments (still running)" - and the branch returned without
reaping them. Their subprocess transports were then finalised after
asyncio.run() had closed the loop, which raises inside __del__ and prints a
traceback that Python cannot attribute to anything.

Cosmetic, except in this one tool: the self-test exists so an operator does
not have to guess, and a traceback directly below "Nothing broken" is exactly
a thing to guess about. (It reproduces on the container's Python 3.12 and not
on every version, so these tests assert the behaviour - no process left
running - rather than the absence of the message.)
"""
from __future__ import annotations

import asyncio

from app import selftest


async def _spawn_a_probe_that_outlives_its_timeout():
    proc = await asyncio.create_subprocess_exec(
        "sleep", "60",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    try:
        await asyncio.wait_for(proc.communicate(None), timeout=0.2)
    except asyncio.TimeoutError:
        pass
    return proc


def test_a_probe_that_was_still_running_is_dead_afterwards():
    async def body():
        proc = await _spawn_a_probe_that_outlives_its_timeout()
        assert proc.returncode is None, "the probe exited on its own; no test here"
        await selftest._reap(proc)
        return proc.returncode

    assert asyncio.run(body()) is not None


def test_reaping_waits_rather_than_only_signalling():
    """Returning before the process is reaped leaves its transport to be
    closed on a loop that may already be gone, which is the whole bug."""
    async def body():
        proc = await _spawn_a_probe_that_outlives_its_timeout()
        await selftest._reap(proc)
        # wait() returns immediately for a process already reaped.
        return await asyncio.wait_for(proc.wait(), timeout=0.1)

    assert asyncio.run(body()) is not None


def test_reaping_a_process_that_already_exited_is_not_an_error():
    async def body():
        proc = await asyncio.create_subprocess_exec("true")
        await proc.wait()
        await selftest._reap(proc)      # must not raise
    asyncio.run(body())


def test_the_invocation_check_leaves_no_child_behind(monkeypatch):
    """End to end: a tool whose command hangs is reported as having accepted
    its arguments, AND is not still running when the check returns."""
    spawned = []

    class _Hanging:
        name = "hangs"
        def is_available(self):
            return True
        def build_command(self, target, options):
            return ["sleep", "60"]
        def stdin_for(self, target, options):
            return None

    from app.scans import wrappers
    monkeypatch.setattr(wrappers, "_WRAPPERS", {"hangs": _Hanging()})
    monkeypatch.setattr(selftest, "_INVOCATION_TIMEOUT", 0.3)

    real_exec = asyncio.create_subprocess_exec

    async def _tracking(*args, **kwargs):
        proc = await real_exec(*args, **kwargs)
        spawned.append(proc)
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _tracking)

    lines = asyncio.run(selftest.check_invocations())
    assert any("still running" in line for line in lines)
    assert spawned, "nothing was launched - the check would be vacuous"
    for proc in spawned:
        assert proc.returncode is not None, "a probe is still running"


def test_the_timeout_branch_is_still_a_pass():
    """Reaping must not turn "it parsed our arguments and went to the network"
    into a failure: that is the outcome the branch exists to report."""
    assert selftest.OK != selftest.BROKEN


# ---- a precondition-gated tool is not probed with empty options -------

def test_a_tool_that_refuses_bare_options_is_not_invocation_probed(monkeypatch):
    """nord_stream needs an operator-supplied platform and token, so
    build_command(target, []) is deliberately incomplete and the tool prints
    'Usage:'. The worker gates it on precondition before spawning, so probing
    it bare tested a command line that can never run - and reported FAIL on a
    tool working as designed."""
    class _Gated:
        name = "gated"
        def is_available(self):
            return True
        def precondition(self, target, options):
            return "needs an operator-supplied token"
        def build_command(self, target, options):
            return ["false"]        # would exit non-zero if ever run
        def stdin_for(self, target, options):
            return None

    from app.scans import wrappers
    monkeypatch.setattr(wrappers, "_WRAPPERS", {"gated": _Gated()})
    lines = asyncio.run(selftest.check_invocations())
    body = "\n".join(lines)
    assert "gated" in body
    assert "not invoked bare" in body
    assert selftest.BROKEN not in body


def test_an_ungated_tool_is_still_probed(monkeypatch):
    """The skip must be narrow: a tool with no precondition still gets run."""
    ran = {"did": False}

    class _Normal:
        name = "normal"
        def is_available(self):
            return True
        def precondition(self, target, options):
            return ""
        def build_command(self, target, options):
            ran["did"] = True
            return ["true"]
        def stdin_for(self, target, options):
            return None

    from app.scans import wrappers
    monkeypatch.setattr(wrappers, "_WRAPPERS", {"normal": _Normal()})
    asyncio.run(selftest.check_invocations())
    assert ran["did"], "an ungated tool was not probed"
