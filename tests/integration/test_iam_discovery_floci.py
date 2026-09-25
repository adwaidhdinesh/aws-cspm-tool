"""Floci integration test for IAM asset discovery.

Tests that the CSPM IAM discoverer correctly finds and evaluates
IAM resources when run against Floci.
"""

import pytest

from src.inventory.aws_inventory import discover_iam_assets
from src.rules.iam_rules import check_root_mfa, check_iam_user_mfa, check_wildcard_admin_policies


@pytest.mark.integration
class TestIAMDiscoveryFloci:
    """Test IAM discovery against Floci."""

    def test_discover_iam_resources(self, session, account_id):
        """Test that discover_iam_assets finds seeded resources."""
        assets = discover_iam_assets(session, account_id)
        
        # Should find at least the seeded resources
        assert len(assets) > 0
        
        # Verify asset types present
        resource_types = {a.resource_type for a in assets}
        assert "IAM::RootAccount" in resource_types
        assert "IAM::User" in resource_types
        assert "IAM::Policy" in resource_types
        
        # Verify metadata
        for asset in assets:
            assert asset.service == "IAM"
            assert asset.resource_id
            if asset.resource_type == "IAM::User":
                assert "has_console_access" in asset.metadata
                assert "mfa_enabled" in asset.metadata
            elif asset.resource_type == "IAM::Policy":
                assert "is_wildcard_admin" in asset.metadata

    def test_root_mfa_check(self, session, account_id):
        """Test root MFA check (Floci default may vary)."""
        assets = discover_iam_assets(session, account_id)
        findings = check_root_mfa(assets)
        
        # Floci root may or may not have MFA - just verify it runs
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "IAM-001"
        assert findings[0]["cis_control"] == "1.5"

    def test_user_mfa_check(self, session, account_id):
        """Test IAM user MFA check."""
        assets = discover_iam_assets(session, account_id)
        findings = check_iam_user_mfa(assets)
        
        # Find users with console access - the check only triggers for users with console
        # Floci may not support create_login_profile, so this test may have limited findings
        for f in findings:
            assert f["rule_id"] == "IAM-002"
            assert f["severity"] == "High"
            # Either PASS or FAIL depending on whether MFA is enabled
            assert f["status"] in ("PASS", "FAIL")

    def test_wildcard_admin_policy_check(self, session, account_id):
        """Test wildcard admin policy detection."""
        assets = discover_iam_assets(session, account_id)
        findings = check_wildcard_admin_policies(assets)
        
        # Should find the wildcard admin policy
        wildcard_findings = [
            f for f in findings 
            if "wildcard-admin" in f["resource"]
        ]
        assert len(wildcard_findings) >= 1
        assert wildcard_findings[0]["status"] == "FAIL"
        assert wildcard_findings[0]["severity"] == "Critical"
        assert wildcard_findings[0]["rule_id"] == "IAM-003"
        assert wildcard_findings[0]["cis_control"] == "1.16"


@pytest.mark.integration
class TestIAMWithMixedProfile:
    """Test IAM with the mixed profile (both secure and insecure)."""
    
    def test_mixed_iam_resources_detected(self, session, account_id):
        """Verify both secure and insecure IAM resources are found."""
        assets = discover_iam_assets(session, account_id)
        
        # Find users
        users = {a.resource_id for a in assets if a.resource_type == "IAM::User"}
        assert "cspm-test-user-no-mfa" in users
        
        # Secure user may not exist if profile was insecure-only
        # Policies
        policies = {a.resource_id for a in assets if a.resource_type == "IAM::Policy"}
        assert "cspm-test-wildcard-admin" in policies