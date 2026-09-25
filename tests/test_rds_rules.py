"""Unit tests for RDS security rules — pure functions, no AWS access."""

from src.inventory.inventory import Asset
from src.rules import rds_rules


def _instance(name="mydb", public=False, encrypted=True):
    return Asset(
        account_id="123456789012",
        service="RDS",
        resource_id=name,
        resource_type="RDS::Instance",
        name=name,
        metadata={"publicly_accessible": public, "storage_encrypted": encrypted},
    )


def test_public_rds_fail():
    findings = rds_rules.check_rds_public_access([_instance(public=True)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["rule_id"] == "RDS-001"
    assert f["severity"] == "Critical"
    assert f["cis_control"] == "2.3.2"
    assert f["resource"] == "mydb"


def test_private_rds_pass():
    findings = rds_rules.check_rds_public_access([_instance(public=False)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"


def test_rds_encryption_enabled_pass():
    findings = rds_rules.check_rds_encryption([_instance(encrypted=True)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert findings[0]["rule_id"] == "RDS-002"


def test_rds_encryption_disabled_fail():
    findings = rds_rules.check_rds_encryption([_instance(encrypted=False)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["severity"] == "High"
    assert f["cis_control"] == "2.3.1"


def test_non_rds_assets_ignored():
    kms = Asset(
        account_id="123456789012", service="KMS", resource_id="key-1",
        resource_type="KMS::Key", metadata={},
    )
    assert rds_rules.check_rds_public_access([kms]) == []
    assert rds_rules.check_rds_encryption([kms]) == []