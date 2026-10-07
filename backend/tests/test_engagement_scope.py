"""The authorization gate: scope checks and attestation -> AUTHORIZED."""
from app.engagements.models import Engagement, EngagementStatus, VerificationMethod


def test_host_in_scope_exact():
    e = Engagement.create("https://example.com", attested=True)
    assert e.host_in_scope("example.com")
    assert not e.host_in_scope("evil.com")


def test_host_in_scope_wildcard_subdomain():
    e = Engagement.create("https://example.com", scope_hosts=[".example.com"], attested=True)
    assert e.host_in_scope("api.example.com")
    assert e.host_in_scope("deep.sub.example.com")
    assert not e.host_in_scope("notexample.com")


def test_url_in_scope():
    e = Engagement.create("https://example.com", attested=True)
    assert e.url_in_scope("https://example.com/admin")
    assert not e.url_in_scope("https://attacker.test/x")


def test_attestation_authorizes_immediately():
    e = Engagement.create("https://example.com", attested=True)
    assert e.status == EngagementStatus.AUTHORIZED
    assert e.verification_method == VerificationMethod.ATTESTATION


def test_without_attestation_is_pending():
    e = Engagement.create("https://example.com")
    assert e.status == EngagementStatus.PENDING_AUTHORIZATION


def test_primary_host_always_in_scope():
    e = Engagement.create("https://example.com", scope_hosts=["other.com"], attested=True)
    assert "example.com" in e.scope_hosts
    assert e.host_in_scope("example.com")


def test_active_exploit_on_by_default_destructive_subflags_off():
    # Active exploitation (known-CVE verification + benign read-only proof) is
    # on by default on every engagement; the destructive sub-flags are not.
    e = Engagement.create("https://example.com", attested=True)
    assert e.allow_active_exploit is True
    assert e.allow_sql_os_cmd is False
    assert e.allow_data_proof is False


def test_active_exploit_flags_opt_in():
    e = Engagement.create("https://example.com", attested=True,
                          allow_active_exploit=True, allow_sql_os_cmd=True,
                          allow_data_proof=True)
    assert e.allow_active_exploit is True
    assert e.allow_sql_os_cmd is True
    assert e.allow_data_proof is True
    # exposed as flags in the public view
    assert e.to_public()["allow_active_exploit"] is True
    assert e.to_public()["allow_data_proof"] is True


def test_public_view_hides_credentials():
    e = Engagement.create("https://example.com", attested=True,
                          primary_auth=[{"name": "Cookie", "value": "secret"}],
                          secondary_auth=[{"name": "Cookie", "value": "low"}])
    pub = e.to_public()
    assert "primary_auth" not in pub and "secondary_auth" not in pub
