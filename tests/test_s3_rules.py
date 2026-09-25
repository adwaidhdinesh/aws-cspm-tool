"""Unit tests for S3 security rules — pure functions, no AWS access."""

from src.inventory.inventory import Asset
from src.rules import s3_rules


def _bucket(name="my-bucket", public=False, encrypted=True):
    return Asset(
        account_id="123456789012",
        service="S3",
        resource_id=name,
        resource_type="S3::Bucket",
        name=name,
        metadata={"public": public, "encrypted": encrypted},
    )


def test_public_bucket_fail():
    findings = s3_rules.check_public_buckets([_bucket(public=True)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["rule_id"] == "S3-001"
    assert f["severity"] == "Critical"
    assert f["cis_control"] == "2.1.5"
    assert f["resource"] == "my-bucket"


def test_private_bucket_pass():
    findings = s3_rules.check_public_buckets([_bucket(public=False)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"


def test_bucket_encryption_enabled_pass():
    findings = s3_rules.check_bucket_encryption([_bucket(encrypted=True)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert findings[0]["rule_id"] == "S3-002"


def test_bucket_encryption_disabled_fail():
    findings = s3_rules.check_bucket_encryption([_bucket(encrypted=False)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["severity"] == "Medium"
    assert f["cis_control"] == "2.1.1"


def test_public_bucket_rule_ignores_non_s3():
    ec2 = Asset(
        account_id="123456789012", service="EC2", resource_id="i-1",
        resource_type="EC2::Instance", metadata={},
    )
    assert s3_rules.check_public_buckets([ec2]) == []
    assert s3_rules.check_bucket_encryption([ec2]) == []