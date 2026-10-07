"""Scope-candidate filtering: what may be offered as "add to scope".

The panel lists hosts a run discovered but could not touch. It must not offer
artefacts - a bare port number was a real "host" in the audit log before the
port-asset bug was fixed, and offering "443" as a scope entry would be absurd.
"""
from app.api.surface import _plausible_host


def test_real_hosts_are_offered():
    for h in ("api.example.com", "prospex.datax.iliad.fr", "example.com",
              "51.159.110.74", "2001:db8::1"):
        assert _plausible_host(h), h


def test_port_number_artefacts_are_refused():
    # These came from the port-asset regression; never offer them as scope.
    for h in ("80", "443", "22", "8080"):
        assert not _plausible_host(h), h


def test_junk_is_refused():
    for h in ("", "   ", "nodot", "a" * 300, "1.2.3", ".."):
        assert not _plausible_host(h), repr(h)
