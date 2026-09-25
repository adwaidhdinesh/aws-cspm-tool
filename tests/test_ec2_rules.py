"""Unit tests for EC2 security rules — pure functions, no AWS access."""

from src.inventory.inventory import Asset
from src.rules import ec2_rules


def _security_group(open_ports=None, name="app-sg"):
    return Asset(
        account_id="123456789012",
        service="EC2",
        resource_id="sg-123",
        resource_type="EC2::SecurityGroup",
        name=name,
        metadata={"open_sensitive_ports": open_ports or []},
    )


def _instance(instance_id="i-123", name="web", state="running", public_ip=None):
    return Asset(
        account_id="123456789012",
        service="EC2",
        resource_id=instance_id,
        resource_type="EC2::Instance",
        name=name,
        metadata={"state": state, "public_ip": public_ip},
    )


def test_open_security_group_fail():
    findings = ec2_rules.check_open_security_groups(
        [_security_group(open_ports=["SSH (22)", "RDP (3389)"])]
    )
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["rule_id"] == "EC2-001"
    assert f["severity"] == "Critical"
    assert f["cis_control"] == "5.2"
    assert f["resource"] == "sg-123"


def test_closed_security_group_pass():
    findings = ec2_rules.check_open_security_groups([_security_group(open_ports=[])])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert findings[0]["severity"] == "Low"


def test_instance_with_public_ip_fail():
    findings = ec2_rules.check_instance_public_ip(
        [_instance(public_ip="203.0.113.10")]
    )
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["rule_id"] == "EC2-002"
    assert f["severity"] == "Medium"
    assert f["resource"] == "i-123"


def test_instance_with_private_only_pass():
    findings = ec2_rules.check_instance_public_ip([_instance(public_ip=None)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"


def test_terminated_instance_skipped():
    assert ec2_rules.check_instance_public_ip(
        [_instance(state="terminated", public_ip="203.0.113.10")]
    ) == []


def test_non_ec2_assets_ignored():
    rds = Asset(
        account_id="123456789012", service="RDS", resource_id="mydb",
        resource_type="RDS::Instance", metadata={},
    )
    assert ec2_rules.check_open_security_groups([rds]) == []
    assert ec2_rules.check_instance_public_ip([rds]) == []