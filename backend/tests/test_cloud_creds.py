"""Leaked AWS credential -> IAM privilege probe (app/intel/cloud_creds)."""
from types import SimpleNamespace

from app.intel import cloud_creds


def _vf(evidence="", poc="", metadata=None):
    return SimpleNamespace(evidence=evidence, poc=poc, metadata=metadata or {})


def test_extract_pairs_from_evidence():
    vf = _vf(evidence="found AKIAIOSFODNN7EXAMPLE and secret "
                       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY in config.js")
    pairs = cloud_creds._extract_aws_pairs([vf])
    assert pairs == [("AKIAIOSFODNN7EXAMPLE",
                      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")]


def test_extract_pairs_from_metadata():
    vf = _vf(metadata={"access_key": "AKIAIOSFODNN7EXAMPLE",
                       "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
    assert cloud_creds._extract_aws_pairs([vf])


def test_no_secret_means_no_pair():
    vf = _vf(evidence="key id AKIAIOSFODNN7EXAMPLE but no secret here")
    assert cloud_creds._extract_aws_pairs([vf]) == []


def test_finding_for_broad_perms_is_critical():
    f = cloud_creds._finding_for("AKIAIOSFODNN7EXAMPLE", {
        "account": "123456789012", "arn": "arn:aws:iam::123456789012:user/ci",
        "allowed": ["iam:GetUser", "s3:ListAllMyBuckets", "ec2:DescribeInstances"],
    })
    assert f.severity == "critical"
    assert f.metadata["vuln_class"] == "privilege_escalation"
    assert f.metadata["proven"] is True


def test_finding_for_identity_only_is_high():
    f = cloud_creds._finding_for("AKIAIOSFODNN7EXAMPLE", {
        "account": "123456789012", "arn": "arn:aws:iam::123456789012:user/ci",
        "allowed": [],
    })
    assert f.severity == "high"
    assert f.metadata["vuln_class"] == "secret_exposure"


def test_probe_degrades_without_boto3():
    # boto3 is not installed in the test env: the probe must return None, not raise.
    assert cloud_creds._probe_aws("AKIAIOSFODNN7EXAMPLE", "x" * 40) is None
