"""Path-traversal filter bypasses.

The plain "../../etc/passwd" is defeated by a single-pass '../' strip, by a
gateway that decodes once before the app decodes again, and by a legacy UTF-8
decoder - while the underlying file read still works. Each bypass is its own
family so the prober actually tries it.
"""
from app.exploit.payload_families import FAMILIES

LFI = [f for f in FAMILIES if f.vuln_class == "lfi"]


def test_bypass_families_exist():
    engines = {f.engine for f in LFI}
    assert {"unix-double-encoded", "unix-nested", "unix-overlong",
            "unix-absolute", "unix-nullbyte", "windows-encoded"} <= engines


def test_every_family_has_a_distinct_payload_and_engine():
    assert len({f.engine for f in LFI}) == len(LFI)
    assert len({f.payload for f in LFI}) == len(LFI)


def test_every_family_carries_an_oracle():
    for f in LFI:
        assert f.expect, f.engine
        assert f.oracle == "signature"


def test_unix_families_look_for_the_passwd_signature():
    for f in LFI:
        if f.engine.startswith("unix") and "proc" not in f.engine:
            assert f.expect == "root:x:0:0", f.engine


def test_windows_families_look_for_win_ini():
    for f in LFI:
        if f.engine.startswith("windows"):
            assert f.expect == "[fonts]", f.engine


def test_nested_payload_survives_one_strip():
    """"....//" minus one "../" is still "../" - that is the whole point."""
    nested = next(f for f in LFI if f.engine == "unix-nested")
    assert nested.payload.replace("../", "", 1).startswith("..")


def test_double_encoded_decodes_once_to_single_encoded():
    from urllib.parse import unquote
    dbl = next(f for f in LFI if f.engine == "unix-double-encoded")
    assert "%2f" in unquote(dbl.payload).lower()
