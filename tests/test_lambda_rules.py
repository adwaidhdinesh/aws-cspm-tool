"""Unit tests for Lambda security rules."""

from src.inventory.inventory import Asset
from src.rules import lambda_rules


def _lambda_function(public=False):
    return Asset(
        account_id="123456789012",
        service="Lambda",
        resource_id="my-func",
        resource_type="Lambda::Function",
        name="my-func",
        metadata={"public": public, "runtime": "python3.12"},
    )


def test_public_lambda_fail():
    findings = lambda_rules.check_lambda_public_access([_lambda_function(public=True)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["rule_id"] == "LAMBDA-001"
    assert f["severity"] == "Critical"
    assert f["cis_control"] == "CUSTOM-1"


def test_private_lambda_pass():
    findings = lambda_rules.check_lambda_public_access([_lambda_function(public=False)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"


def test_non_lambda_assets_ignored():
    ec2 = Asset(
        account_id="123456789012", service="EC2", resource_id="i-1",
        resource_type="EC2::Instance", metadata={},
    )
    assert lambda_rules.check_lambda_public_access([ec2]) == []