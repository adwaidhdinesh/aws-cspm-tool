"""Unit tests for VPC security rules."""

from src.inventory.inventory import Asset
from src.rules import vpc_rules


def _default_sg(has_inbound=False):
    return Asset(
        account_id="123456789012",
        service="EC2",
        resource_id="sg-default",
        resource_type="EC2::SecurityGroup",
        name="default",
        metadata={"is_default": True, "has_inbound_rules": has_inbound},
    )


def _non_default_sg():
    return Asset(
        account_id="123456789012",
        service="EC2",
        resource_id="sg-app",
        resource_type="EC2::SecurityGroup",
        name="app-sg",
        metadata={"is_default": False, "has_inbound_rules": True},
    )


def _vpc(has_flow_logs=False):
    return Asset(
        account_id="123456789012",
        service="VPC",
        resource_id="vpc-1",
        resource_type="VPC::Vpc",
        metadata={"has_flow_logs": has_flow_logs},
    )


def test_default_sg_with_inbound_rules_fail():
    findings = vpc_rules.check_default_sg_restricts_traffic([_default_sg(has_inbound=True)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["rule_id"] == "VPC-001"
    assert f["severity"] == "Medium"
    assert f["cis_control"] == "5.3"


def test_default_sg_no_inbound_rules_pass():
    findings = vpc_rules.check_default_sg_restricts_traffic([_default_sg(has_inbound=False)])
    assert findings[0]["status"] == "PASS"


def test_non_default_sg_skipped():
    assert vpc_rules.check_default_sg_restricts_traffic([_non_default_sg()]) == []


def test_vpc_flow_logs_pass():
    findings = vpc_rules.check_vpc_flow_logs_enabled([_vpc(has_flow_logs=True)])
    assert findings[0]["status"] == "PASS"


def test_vpc_flow_logs_fail():
    findings = vpc_rules.check_vpc_flow_logs_enabled([_vpc(has_flow_logs=False)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["rule_id"] == "VPC-002"
    assert f["severity"] == "Medium"
    assert f["cis_control"] == "3.9"