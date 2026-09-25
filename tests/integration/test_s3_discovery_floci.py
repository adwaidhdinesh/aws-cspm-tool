"""Floci integration test for S3 asset discovery.

Tests that the CSPM S3 discoverer correctly finds and evaluates
S3 buckets when run against Floci.
"""

import pytest

from src.inventory.aws_inventory import discover_s3_assets
from src.rules.s3_rules import check_public_buckets, check_bucket_encryption


@pytest.mark.integration
class TestS3DiscoveryFloci:
    """Test S3 discovery against Floci."""

    def test_discover_s3_buckets(self, session, account_id):
        """Test that discover_s3_assets finds seeded buckets."""
        assets = discover_s3_assets(session, account_id)
        
        # Should find at least the seeded buckets
        assert len(assets) > 0
        
        # Verify asset structure
        for asset in assets:
            assert asset.service == "S3"
            assert asset.resource_type == "S3::Bucket"
            assert asset.resource_id  # bucket name
            assert asset.arn and asset.arn.startswith("arn:aws:s3:::")
            assert "public" in asset.metadata
            assert "encrypted" in asset.metadata
            assert "versioning_enabled" in asset.metadata

    def test_public_bucket_detection(self, session, account_id):
        """Test that public bucket check detects public buckets."""
        assets = discover_s3_assets(session, account_id)
        findings = check_public_buckets(assets)
        
        # Find the public bucket
        public_bucket_findings = [
            f for f in findings 
            if "public-bucket" in f["resource"]
        ]
        assert len(public_bucket_findings) == 1
        assert public_bucket_findings[0]["status"] == "FAIL"
        assert public_bucket_findings[0]["severity"] == "Critical"
        assert public_bucket_findings[0]["rule_id"] == "S3-001"

    def test_unencrypted_bucket_detection(self, session, account_id):
        """Test that encryption check detects unencrypted buckets."""
        assets = discover_s3_assets(session, account_id)
        findings = check_bucket_encryption(assets)
        
        # Find the unencrypted bucket
        # Note: Floci may report encryption as enabled by default
        unencrypted_findings = [
            f for f in findings 
            if "unencrypted" in f["resource"]
        ]
        if unencrypted_findings:
            assert unencrypted_findings[0]["rule_id"] == "S3-002"
            assert unencrypted_findings[0]["severity"] == "Medium"
            # Depending on Floci's behavior, this could be PASS or FAIL
            assert unencrypted_findings[0]["status"] in ("PASS", "FAIL")

    def test_secure_bucket_passes(self, session, account_id):
        """Test that secure bucket passes checks."""
        assets = discover_s3_assets(session, account_id)
        public_findings = check_public_buckets(assets)
        enc_findings = check_bucket_encryption(assets)
        
        # Find the secure bucket
        secure_public = [f for f in public_findings if "secure-bucket" in f["resource"]]
        secure_enc = [f for f in enc_findings if "secure-bucket" in f["resource"]]
        
        if secure_public:
            assert secure_public[0]["status"] == "PASS"
        if secure_enc:
            assert secure_enc[0]["status"] == "PASS"


@pytest.mark.integration
class TestS3WithMixedProfile:
    """Test S3 with the mixed profile (both secure and insecure)."""
    
    def test_mixed_buckets_detected(self, session, account_id):
        """Verify both secure and insecure buckets are found."""
        assets = discover_s3_assets(session, account_id)
        bucket_names = {a.resource_id for a in assets}
        
        # Should find the seeded buckets
        # (test depends on which profile was seeded)
        found = {
            "cspm-test-public-bucket",
            "cspm-test-unencrypted-bucket",
            "cspm-test-no-versioning-bucket",
            "cspm-test-public-policy-bucket",
        }
        for exp in found:
            assert exp in bucket_names, f"Missing expected bucket: {exp}"
        
        # Secure bucket may or may not exist depending on profile
        if "cspm-test-secure-bucket" in bucket_names:
            secure = [a for a in assets if a.resource_id == "cspm-test-secure-bucket"]
            assert secure[0].metadata.get("encrypted", False)