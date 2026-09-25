"""Unit tests for CloudTrail security rules."""

from src.inventory.inventory import Asset
from src.rules import cloudtrail_rules


def _trail(name="my-trail", multiregion=True, logging=True, validation=True):
    return Asset(
        account_id="123456789012",
        service="CloudTrail",
        resource_id=name,
        resource_type="CloudTrail::Trail",
        name=name,
        metadata={
            "is_multiregion": multiregion,
            "is_logging": logging,
            "log_validation_enabled": validation,
        },
    )


def test_cloudtrail_enabled_pass():
    findings = cloudtrail_rules.check_cloudtrail_enabled([_trail()])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert findings[0]["rule_id"] == "CT-001"


def test_cloudtrail_enabled_fail_when_no_trails():
    findings = cloudtrail_rules.check_cloudtrail_enabled([])
    assert len(findings) == 1
    assert findings[0]["status"] == "FAIL"
    assert findings[0]["severity"] == "High"


def test_cloudtrail_enabled_fail_when_not_logging():
    findings = cloudtrail_rules.check_cloudtrail_enabled([_trail(logging=False)])
    assert findings[0]["status"] == "FAIL"


def test_cloudtrail_enabled_fail_when_not_multiregion():
    findings = cloudtrail_rules.check_cloudtrail_enabled([_trail(multiregion=False)])
    assert findings[0]["status"] == "FAIL"


def test_cloudtrail_log_validation_pass():
    findings = cloudtrail_rules.check_cloudtrail_log_validation([_trail(validation=True)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert findings[0]["rule_id"] == "CT-002"


def test_cloudtrail_log_validation_fail():
    findings = cloudtrail_rules.check_cloudtrail_log_validation([_trail(validation=False)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["severity"] == "Medium"
    assert f["cis_control"] == "3.2"