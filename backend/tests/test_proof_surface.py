"""Every proof a finding carries must reach the operator.

A verdict of "confirmed" is only worth something if the reader can see what
decided it and re-run it. These pin the data path: what the backend records on
a finding has to be exposed by the findings API, or the UI cannot show it.
"""
import inspect

from app.api import findings as findings_api
from app.exploit.repro import ReproRecord


def _exposed_keys() -> set:
    src = inspect.getsource(findings_api.list_findings)
    body = src[src.index("g = {"):src.index("groups[key] = g")]
    import re
    return set(re.findall(r'"([a-z_]+)":', body))


def test_the_whole_proof_chain_is_exposed():
    keys = _exposed_keys()
    for k in ("evidence", "poc", "req", "resp",          # raw material
              "exploitation",                             # a PoC ran
              "proof_replay",                             # replayed the claim
              "repro",                                    # how to re-run it
              "corroboration", "oracle", "method",        # why it is believed
              "confidence", "proven", "shadow_judge"):
        assert k in keys, f"findings API drops {k}"


def test_repro_record_carries_the_command_and_its_output():
    """The command alone is not a proof - what it printed is. For an RCE the
    output of id/whoami IS the capture."""
    rec = ReproRecord(tool="commix", target="https://t.example/x",
                      command="commix -u https://t.example/x --os-cmd id",
                      exit_code=0, duration_s=2.5, ran_at=0.0,
                      output_excerpt="uid=33(www-data) gid=33(www-data)")
    d = rec.to_dict()
    assert d["command"].startswith("commix")
    assert d["exit_code"] == 0
    assert "www-data" in d["output_excerpt"]
    # and the human-readable block keeps it too
    assert "# Output" in rec.as_evidence()
    assert "www-data" in rec.as_evidence()


def test_repro_without_output_is_still_valid():
    rec = ReproRecord(tool="nuclei", target="t", command="nuclei -u t",
                      exit_code=0, duration_s=None, ran_at=0.0)
    assert rec.to_dict()["output_excerpt"] == ""
    assert "# Output" not in rec.as_evidence()
