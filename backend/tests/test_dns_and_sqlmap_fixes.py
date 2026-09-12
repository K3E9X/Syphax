"""Guards for the DNS leak, the sqlmap block parser and shared network state."""
from app.network.privacy import hosts_block, internal_hostnames, merge_hosts
from app.scans.wrappers.sqlmap import SqlmapWrapper, parse_injection_blocks


# ---- DNS: pin internal names so the tunnel's own resolver can be kept --------
def test_only_real_service_names_need_pinning():
    names = internal_hostnames("postgresql://u:p@postgres:5432/db",
                               "redis://redis:6379/0")
    assert names == ["postgres", "redis"]
    # an address resolves itself; an empty url has nothing to pin
    assert internal_hostnames("redis://127.0.0.1:6379") == []
    assert internal_hostnames("", None) == []


def test_hosts_block_is_replaced_not_stacked():
    original = "127.0.0.1\tlocalhost\n172.18.0.5\tsyphax-backend\n"
    once = merge_hosts(original, hosts_block({"postgres": "172.18.0.2"}))
    twice = merge_hosts(once, hosts_block({"postgres": "172.18.0.9"}))
    # reconnecting must not accumulate duplicate blocks
    assert twice.count("syphax internal services") == 2      # begin + end marker
    assert "172.18.0.9" in twice and "172.18.0.2" not in twice
    # everything Docker wrote survives
    assert "localhost" in twice and "syphax-backend" in twice


# ---- sqlmap: a truncated block must not steal the next block's payload ------
_TRUNCATED_THEN_COMPLETE = """
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE clause

Parameter: name (GET)
    Type: error-based
    Title: MySQL error-based
    Payload: name=x' AND EXTRACTVALUE(1,CONCAT(0x5c,MD5(1)))-- -
"""


def test_truncated_block_is_dropped_and_the_complete_one_kept():
    blocks = parse_injection_blocks(_TRUNCATED_THEN_COMPLETE)
    assert len(blocks) == 1
    # the old DOTALL pattern reported parameter 'id' carrying name's payload
    assert blocks[0]["parameter"] == "name"
    assert "EXTRACTVALUE" in blocks[0]["payload"]


def test_two_complete_blocks_keep_their_own_payloads():
    text = """
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: id=1 AND 1=1

Parameter: q (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based
    Payload: q=x' AND SLEEP(5)-- -
"""
    blocks = parse_injection_blocks(text)
    assert [b["parameter"] for b in blocks] == ["id", "q"]
    assert "1 AND 1=1" in blocks[0]["payload"]
    assert "SLEEP(5)" in blocks[1]["payload"]


def test_empty_and_garbage_output_yield_no_findings():
    for raw in (b"", b"no injection found", b"\x00\xff binary"):
        assert SqlmapWrapper().parse(raw, b"", 0, "https://t").findings == []
