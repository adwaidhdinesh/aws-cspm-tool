"""Unit tests for IAM security rules.

These rules are pure functions operating on Asset objects only — no AWS
credentials or network access are required.
"""

from src.inventory.inventory import Asset
from src.rules import iam_rules

ACCOUNT_ID = "123456789012"


def _asset(resource_type, resource_id, metadata, **kwargs):
    defaults = {
        "account_id": ACCOUNT_ID,
        "service": "IAM",
        "resource_type": resource_type,
    }
    defaults.update(kwargs)
    return Asset(resource_id=resource_id, metadata=metadata, **defaults)


def _root_asset(mfa_enabled):
    return _asset("IAM::RootAccount", ACCOUNT_ID, {"mfa_enabled": mfa_enabled}, name="root")


def _user_asset(username, console=True, mfa=False):
    return _asset(
        "IAM::User",
        username,
        {"has_console_access": console, "mfa_enabled": mfa},
        name=username,
    )


def _policy_asset(name, is_wildcard):
    return _asset("IAM::Policy", name, {"is_wildcard_admin": is_wildcard}, name=name)


def test_root_mfa_pass():
    findings = iam_rules.check_root_mfa([_root_asset(mfa_enabled=True)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert findings[0]["rule_id"] == "IAM-001"


def test_root_mfa_fail():
    findings = iam_rules.check_root_mfa([_root_asset(mfa_enabled=False)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["rule_id"] == "IAM-001"
    assert f["severity"] == "Critical"
    assert f["cis_control"] == "1.5"


def test_iam_user_mfa_pass():
    findings = iam_rules.check_iam_user_mfa([_user_asset("alice", console=True, mfa=True)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert findings[0]["rule_id"] == "IAM-002"


def test_iam_user_mfa_fail():
    findings = iam_rules.check_iam_user_mfa([_user_asset("alice", console=True, mfa=False)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["rule_id"] == "IAM-002"
    assert f["severity"] == "High"


def test_iam_user_without_console_access_skipped():
    findings = iam_rules.check_iam_user_mfa([_user_asset("svc", console=False, mfa=False)])
    assert findings == []


def test_wildcard_admin_policy_fail():
    findings = iam_rules.check_wildcard_admin_policies([_policy_asset("admin", True)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "FAIL"
    assert f["rule_id"] == "IAM-003"
    assert f["severity"] == "Critical"


def test_scoped_policy_pass():
    findings = iam_rules.check_wildcard_admin_policies([_policy_asset("readonly", False)])
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"


def test_non_iam_assets_ignored():
    s3 = Asset(
        account_id=ACCOUNT_ID, service="S3", resource_id="bucket",
        resource_type="S3::Bucket", metadata={"public": True},
    )
    assert iam_rules.check_root_mfa([s3]) == []
    assert iam_rules.check_iam_user_mfa([s3]) == []
    assert iam_rules.check_wildcard_admin_policies([s3]) == []