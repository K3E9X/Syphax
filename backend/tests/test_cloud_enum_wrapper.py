"""cloud_enum wrapper: brand-keyword cloud-storage enumeration.

cloud_enum prints line-oriented results (no JSON). These tests pin the marker
parsing against sample output in the shape the tool emits, and the keyword
derivation from a target host/URL.
"""
from app.scans.wrappers.cloud_enum import CloudEnumWrapper, _keyword

W = CloudEnumWrapper()

# Representative cloud_enum stdout: a public S3 bucket, an authenticated-only
# Azure container, a public GCS bucket, and non-findings that must be ignored.
SAMPLE = b"""
[+] Checking for S3 buckets
      OPEN S3 BUCKET: http://acme-backups.s3.amazonaws.com/
      Protected S3 Bucket: http://acme-private.s3.amazonaws.com/
[+] Checking for Azure blobs
      AUTHENTICATED AZURE CONTAINER: https://acme.blob.core.windows.net/data
[+] Checking for Google buckets
      OPEN GOOGLE BUCKET: https://storage.googleapis.com/acme-public-assets
[+] Checking for Azure websites
      Nothing found.
"""


def test_public_bucket_is_high_and_private_is_medium():
    res = W.parse(SAMPLE, b"", 0, "https://acme.com")
    by_url = {f.metadata["resource"]: f for f in res.findings}
    assert by_url["http://acme-backups.s3.amazonaws.com/"].severity == "high"
    assert by_url["http://acme-backups.s3.amazonaws.com/"].metadata["public"] is True
    assert by_url["http://acme-private.s3.amazonaws.com/"].severity == "medium"
    assert by_url["http://acme-private.s3.amazonaws.com/"].metadata["public"] is False


def test_each_provider_is_labelled():
    res = W.parse(SAMPLE, b"", 0, "https://acme.com")
    provs = {f.metadata["provider"] for f in res.findings}
    assert provs == {"AWS S3", "Azure Blob", "Google Cloud Storage"}


def test_all_findings_carry_the_vuln_class():
    res = W.parse(SAMPLE, b"", 0, "https://acme.com")
    assert res.findings
    assert all(f.metadata["vuln_class"] == "exposed_bucket" for f in res.findings)


def test_non_findings_are_dropped():
    res = W.parse(SAMPLE, b"", 0, "https://acme.com")
    # 4 storage lines above; the "Nothing found." / banner lines are not results.
    assert len(res.findings) == 4


def test_command_includes_brand_keyword():
    cmd = W.build_command("https://shop.acme.co.uk/login", [])
    assert "cloud_enum" in cmd[0]
    assert "acme" in cmd  # registrable brand label, not the full FQDN


def test_keyword_derivation():
    assert _keyword("https://www.acme.com/x") == "acme"
    assert _keyword("acme.co.uk") == "acme"
    assert _keyword("https://glpi.equaline.fr") == "equaline"
