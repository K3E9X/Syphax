"""Every phase must run after whatever produces the data it reads.

This class of bug cost days and three separate symptoms: a phase that reads
VALIDATED findings but runs before validate_engagement writes them finds an
empty table, takes its early return, and produces nothing - silently. It looks
exactly like "there was nothing to do".

Two offenders were found this way: run_campaign (no PoC was ever staged, no
exploit ever written) and probe_leaked_cloud_creds (a leaked AWS key could
never be tested). The test enumerates the consumers instead of naming them, so
a new one is covered the day it lands.
"""
import inspect
import re

from app.orchestrator import loop

SRC = inspect.getsource(loop)

# Phases that read ValidatedFindingRepository, directly or through a helper.
VALIDATED_CONSUMERS = (
    "run_campaign",
    "probe_leaked_cloud_creds",
    "run_payload_validation",
    "run_chain_campaign",
)
# Phases that read raw job findings: these legitimately run BEFORE validation.
JOB_CONSUMERS = ("run_known_exploits", "prove_impact")


def _call_pos(name: str) -> int:
    m = re.search(rf"await {re.escape(name)}\(", SRC)
    assert m, f"{name} is not called by the loop at all"
    return m.start()


def _validation_pos() -> int:
    m = re.search(r"await validate_engagement\(", SRC)
    assert m, "validate_engagement is not called"
    return m.start()


def test_every_consumer_of_validated_findings_runs_after_validation():
    after = _validation_pos()
    for name in VALIDATED_CONSUMERS:
        assert _call_pos(name) > after, (
            f"{name} reads validated findings but runs before "
            "validate_engagement writes them: it will find an empty table and "
            "silently do nothing")


def test_chain_exploitation_runs_after_the_chains_are_built():
    assert _call_pos("build_chains") < _call_pos("run_chain_campaign")


def test_the_public_exploit_aggregation_feeds_the_campaign():
    """run_campaign reads the aggregation to know which findings have a
    published PoC."""
    assert _call_pos("analyze_public_exploits") < _call_pos("run_campaign")


def test_job_consumers_may_run_before_validation():
    """known-CVE and proof-of-impact read raw job findings, which exist as soon
    as the scans finish - they are correct where they are, and moving them
    after validation would delay the confirmations validation then reads."""
    after = _validation_pos()
    for name in JOB_CONSUMERS:
        assert _call_pos(name) < after, f"{name} moved unexpectedly"
