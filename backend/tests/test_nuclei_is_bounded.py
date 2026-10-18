"""nuclei must be rate/time-bounded or it burns the whole job timeout and
returns nothing - see the live run where 15/16 jobs hit `timeout after 1800s`."""
from app.scans.wrappers.nuclei import NucleiWrapper


def test_nuclei_command_is_bounded_by_default():
    cmd = NucleiWrapper().build_command("http://t/x?q=1", [])
    for flag in ("-rate-limit", "-c", "-bulk-size", "-timeout", "-retries",
                 "-max-host-error"):
        assert flag in cmd, f"{flag} missing - nuclei will stall on slow hosts"


def test_caller_options_are_not_duplicated():
    cmd = NucleiWrapper().build_command(
        "http://t/x?q=1", ["-timeout", "20", "-concurrency", "10"])
    assert cmd.count("-timeout") == 1
    assert "-c" not in cmd          # suppressed when -concurrency is given
    assert "-rate-limit" in cmd     # the others still applied


def test_a_catalog_item_can_still_override_a_bound():
    """Each default is applied only if the caller did not set it, so an
    exposures/CVE scan can tune rate or timeout per scan."""
    cmd = NucleiWrapper().build_command(
        "http://t/", ["-rate-limit", "40", "-max-host-error", "5"])
    assert cmd.count("-rate-limit") == 1
    assert "40" in cmd and "150" not in cmd
    assert cmd.count("-max-host-error") == 1
    assert "5" in cmd
