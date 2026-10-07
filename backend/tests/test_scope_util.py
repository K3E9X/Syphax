"""Generic registrable-domain + same-server scope logic.

Auto-scope-expansion must stay on the target's own organisation and server:
never a different registrable domain, never a shared hosting platform, never a
different netblock.
"""
from app.engagements.scope_util import (is_ip, registrable_domain,
                                        same_registrable_domain, same_server)


def test_registrable_domain_generic():
    assert registrable_domain("prospex.datax.iliad.fr") == "iliad.fr"
    assert registrable_domain("x.example.com") == "example.com"
    assert registrable_domain("example.com") == "example.com"


def test_registrable_domain_multi_label_cctld():
    assert registrable_domain("www.acme.co.uk") == "acme.co.uk"
    assert registrable_domain("shop.loja.com.br") == "loja.com.br"


def test_shared_platforms_do_not_expand():
    # Expanding here would scope other tenants -> never.
    for h in ("myapp.herokuapp.com", "foo.github.io", "site.vercel.app",
              "bucket.s3.amazonaws.com", "x.azurewebsites.net"):
        assert registrable_domain(h) is None, h


def test_ip_and_bare_tld_do_not_expand():
    assert registrable_domain("51.159.110.74") is None
    assert registrable_domain("localhost") is None


def test_same_registrable_domain():
    assert same_registrable_domain("a.datax.iliad.fr", "prospex.datax.iliad.fr")
    assert not same_registrable_domain("evil.com", "prospex.datax.iliad.fr")
    # shared platform never counts as "same domain" even if literally equal suffix
    assert not same_registrable_domain("a.herokuapp.com", "b.herokuapp.com")


def test_same_server_exact_and_netblock():
    assert same_server(["1.2.3.4"], ["1.2.3.4"])           # same IP
    assert same_server(["1.2.3.50"], ["1.2.3.4"])          # same /24
    assert not same_server(["9.9.9.9"], ["1.2.3.4"])       # different infra
    assert not same_server([], ["1.2.3.4"])                # unresolved -> no


def test_is_ip():
    assert is_ip("1.2.3.4")
    assert is_ip("2001:db8::1")
    assert not is_ip("example.com")
