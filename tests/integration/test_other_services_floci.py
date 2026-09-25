"""Floci integration test for RDS, KMS, Lambda, and CloudTrail asset discovery."""

import pytest

from src.inventory.aws_inventory import (
    discover_rds_assets,
    discover_kms_assets,
    discover_lambda_assets,
    discover_cloudtrail_assets,
)
from src.rules.rds_rules import check_rds_public_access, check_rds_encryption
from src.rules.kms_rules import check_kms_key_rotation
from src.rules.lambda_rules import check_lambda_public_access
from src.rules.cloudtrail_rules import check_cloudtrail_enabled, check_cloudtrail_log_validation


@pytest.mark.integration
class TestRDSDiscoveryFloci:
    """Test RDS discovery against Floci."""

    def test_discover_rds_instances(self, session, account_id):
        """Test that discover_rds_assets finds RDS instances."""
        assets = discover_rds_assets(session, account_id)
        
        # RDS may not have instances in Floci - just verify it runs
        for asset in assets:
            assert asset.service == "RDS"
            assert asset.resource_type == "RDS::Instance"
            assert "publicly_accessible" in asset.metadata
            assert "storage_encrypted" in asset.metadata

    def test_rds_rules_run(self, session, account_id):
        """Test that RDS rules run without error."""
        assets = discover_rds_assets(session, account_id)
        
        public_findings = check_rds_public_access(assets)
        enc_findings = check_rds_encryption(assets)
        
        for f in public_findings:
            assert f["rule_id"] == "RDS-001"
            assert f["severity"] == "Critical"
        for f in enc_findings:
            assert f["rule_id"] == "RDS-002"
            assert f["severity"] == "High"


@pytest.mark.integration
class TestKMSDiscoveryFloci:
    """Test KMS discovery against Floci."""

    def test_discover_kms_keys(self, session, account_id):
        """Test that discover_kms_assets finds KMS keys."""
        assets = discover_kms_assets(session, account_id)
        
        for asset in assets:
            assert asset.service == "KMS"
            assert asset.resource_type == "KMS::Key"
            assert "key_spec" in asset.metadata
            assert "rotation_enabled" in asset.metadata

    def test_kms_rotation_check(self, session, account_id):
        """Test KMS key rotation check."""
        assets = discover_kms_assets(session, account_id)
        findings = check_kms_key_rotation(assets)
        
        for f in findings:
            assert f["rule_id"] == "KMS-001"
            assert f["severity"] == "Medium"
            assert f["cis_control"] == "2.8"


@pytest.mark.integration
class TestLambdaDiscoveryFloci:
    """Test Lambda discovery against Floci."""

    def test_discover_lambda_functions(self, session, account_id):
        """Test that discover_lambda_assets finds Lambda functions."""
        assets = discover_lambda_assets(session, account_id)
        
        for asset in assets:
            assert asset.service == "Lambda"
            assert asset.resource_type == "Lambda::Function"
            assert "runtime" in asset.metadata
            assert "public" in asset.metadata

    def test_lambda_public_access_check(self, session, account_id):
        """Test Lambda public access check."""
        assets = discover_lambda_assets(session, account_id)
        findings = check_lambda_public_access(assets)
        
        for f in findings:
            assert f["rule_id"] == "LAMBDA-001"
            assert f["severity"] == "Critical"
            assert f["cis_control"] == "CUSTOM-1"


@pytest.mark.integration
class TestCloudTrailDiscoveryFloci:
    """Test CloudTrail discovery against Floci."""

    def test_discover_cloudtrail_trails(self, session, account_id):
        """Test that discover_cloudtrail_assets finds trails."""
        assets = discover_cloudtrail_assets(session, account_id)
        
        for asset in assets:
            assert asset.service == "CloudTrail"
            assert asset.resource_type == "CloudTrail::Trail"
            assert "is_multiregion" in asset.metadata
            assert "is_logging" in asset.metadata
            assert "log_validation_enabled" in asset.metadata

    def test_cloudtrail_rules_run(self, session, account_id):
        """Test CloudTrail rules run without error."""
        assets = discover_cloudtrail_assets(session, account_id)
        
        enabled_findings = check_cloudtrail_enabled(assets)
        validation_findings = check_cloudtrail_log_validation(assets)
        
        for f in enabled_findings:
            assert f["rule_id"] == "CT-001"
            assert f["severity"] == "High"
        for f in validation_findings:
            assert f["rule_id"] == "CT-002"
            assert f["severity"] == "Medium"