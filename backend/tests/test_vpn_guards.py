"""Guards on the VPN path: the config reaches wg-quick from an API request body,
and wg-quick runs hooks as root."""
import os
import tempfile

import pytest

from app.network.privacy import (config_path_allowed, prepare_wg_config)

_MINIMAL = """[Interface]
PrivateKey = aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gMTI=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = cHVibGljIGtleSBwdWJsaWMga2V5IHB1YmxpYyAxMg=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
"""


def _write(tmp, body, name="wg0.conf"):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(body)
    return p


# ---- root command execution via wg-quick hooks ------------------------------
@pytest.mark.parametrize("hook", ["PostUp", "PreUp", "PreDown", "PostDown", "Table"])
def test_config_with_a_root_hook_is_refused(hook):
    with tempfile.TemporaryDirectory() as tmp:
        src = _write(tmp, _MINIMAL + f"\n{hook} = /bin/sh -c 'id > /data/pwned'\n")
        with pytest.raises(ValueError) as exc:
            prepare_wg_config(src, dest_dir=os.path.join(tmp, "out"))
        assert hook.lower() in str(exc.value).lower()


def test_hook_detection_is_case_insensitive_and_tolerates_spacing():
    with tempfile.TemporaryDirectory() as tmp:
        src = _write(tmp, _MINIMAL + "\n   postup   =  touch /tmp/x\n")
        with pytest.raises(ValueError):
            prepare_wg_config(src, dest_dir=os.path.join(tmp, "out"))


def test_a_clean_config_is_prepared_and_keeps_the_peer():
    with tempfile.TemporaryDirectory() as tmp:
        src = _write(tmp, _MINIMAL)
        out = prepare_wg_config(src, dest_dir=os.path.join(tmp, "out"))
        body = open(out, encoding="utf-8").read()
        assert "Endpoint = vpn.example.com:51820" in body
        assert "DNS =" not in body                 # stripped so Docker DNS survives
        assert oct(os.stat(out).st_mode)[-3:] == "600"   # carries a private key


# ---- where a config may come from -------------------------------------------
def test_config_path_confined_to_allowed_roots():
    with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as other:
        inside = _write(allowed, _MINIMAL)
        outside = _write(other, _MINIMAL)
        assert config_path_allowed(inside, roots=[allowed])
        assert not config_path_allowed(outside, roots=[allowed])


def test_config_path_rejects_traversal_out_of_the_root():
    with tempfile.TemporaryDirectory() as allowed:
        sub = os.path.join(allowed, "sub")
        os.makedirs(sub)
        escape = os.path.join(sub, "..", "..", "etc", "passwd")
        assert not config_path_allowed(escape, roots=[allowed])
        assert not config_path_allowed("", roots=[allowed])
