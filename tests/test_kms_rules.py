"""Unit tests for KMS security rules."""

from src.inventory.inventory import Asset
from src.rules import kms_rules


def _kms_key(rotation_enabled=False):
    return Asset(
        account_id="123456789012",
        service="KMS",
        resource_id="key-1",
        resource_type="KMS::Key",
        name="my-key",
        metadata={"key_spec": "SYMMETRIC_DEFAULT", "rotation_enabled": rotation_enabled},
    )


def test_rotation_enabled_pass():
    findings = kms_rules.check_kms_key_rotation([_kms_key(rotation_enabled=True)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert findings[0]["rule_id"] == "KMS-001"


def test_rotation_disabled_fail():
    findings = kms_rules.check_kms_key_rotation([_kms_key(rotation_enabled=False)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["severity"] == "Medium"
    assert f["cis_control"] == "2.8"


def test_non_symmetric_keys_skipped():
    asset = Asset(
        account_id="123456789012",
        service="KMS",
        resource_id="key-2",
        resource_type="KMS::Key",
        name="asym",
        metadata={"key_spec": "RSA_2048", "rotation_enabled": False},
    )
    assert kms_rules.check_kms_key_rotation([asset]) == []