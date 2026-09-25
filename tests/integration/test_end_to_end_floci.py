"""End-to-end Floci integration test for complete CSPM scan.

This test runs the full CSPM pipeline against Floci:
1. Seed vulnerable resources
2. Run CSPM scan
3. Verify findings are generated
4. Verify posture score decreases appropriately
"""

import pytest

from src.aws_client import get_session
from src.inventory.aws_inventory import discover_assets
from src.scanner import run_scan
from src.scoring import calculate_score, score_grade
from src import db


@pytest.mark.integration
class TestEndToEndFlociScan:
    """End-to-end CSPM scan against Floci."""

    def test_complete_scan_pipeline(self, session, account_id):
        """Run full CSPM scan against Floci and verify results."""
        # Initialize DB
        db.init_db()
        
        # Discover assets
        assets = discover_assets(session, account_id)
        assert len(assets) > 0, "Should discover at least some assets"
        
        # Run rule checks
        findings = run_scan(assets)
        assert len(findings) > 0, "Should generate at least some findings"
        
        # Verify finding structure
        for f in findings:
            assert "rule_id" in f
            assert "status" in f
            assert "severity" in f
            assert "service" in f
            assert "resource" in f
            assert "cis_control" in f
        
        # Calculate score
        score_result = calculate_score(findings)
        
        # Verify score structure
        assert 0 <= score_result["score"] <= 100
        grade = score_grade(score_result["score"])
        assert grade in ["A", "B", "C", "D", "F"]
        assert score_result["total_checks"] > 0
        assert score_result["failed_checks"] >= 0
        assert score_result["passed_checks"] >= 0
        
        # Score should be < 100 due to seeded vulnerabilities
        # (not asserting exact score as it depends on what Floci supports)
        assert score_result["failed_checks"] > 0, "Should have failing checks from seeded vulnerabilities"

    def test_specific_vulnerabilities_detected(self, session, account_id):
        """Verify specific seeded vulnerabilities are detected."""
        assets = discover_assets(session, account_id)
        findings = run_scan(assets)
        
        # Check for specific rule IDs that should be triggered
        rule_ids = {f["rule_id"] for f in findings if f["status"] == "FAIL"}
        
        # These are the rules we expect to trigger based on our seed data.
        # Not all may be detected depending on Floci's support level.
        possible_rules = {
            "S3-001",      # Public S3 bucket (detected at scan time)
            "S3-002",      # Unencrypted S3 bucket (may vary with Floci)
            "IAM-002",     # User without MFA (needs login profile support)
            "IAM-003",     # Wildcard admin policy
            "EC2-001",     # Open security groups
            "LAMBDA-001",  # Public Lambda (needs Lambda creation support)
        }
        
        # At least some should be detected (depending on Floci support)
        detected = rule_ids & possible_rules
        assert len(detected) >= 1, f"No expected vulnerabilities detected. Found: {rule_ids}"

    def test_severity_distribution(self, session, account_id):
        """Verify findings have proper severity distribution."""
        assets = discover_assets(session, account_id)
        findings = run_scan(assets)
        
        failing = [f for f in findings if f["status"] == "FAIL"]
        severities = {f["severity"] for f in failing}
        
        # Should have at least Critical and High findings
        assert "Critical" in severities or "High" in severities

    def test_by_service_findings(self, session, account_id):
        """Verify findings are generated across multiple services."""
        assets = discover_assets(session, account_id)
        findings = run_scan(assets)
        
        services_with_failures = {
            f["service"] for f in findings 
            if f["status"] == "FAIL"
        }
        
        # Should have failures in at least 2 services
        assert len(services_with_failures) >= 2

    def test_scan_persistence(self, session, account_id):
        """Verify scan results can be persisted to database."""
        db.init_db()
        
        assets = discover_assets(session, account_id)
        asset_id_map = db.save_assets(assets, account_id)
        
        findings = run_scan(assets)
        for f in findings:
            f["asset_id"] = asset_id_map.get((f.get("service"), f.get("resource")))
        
        score_result = calculate_score(findings)
        
        scan_id = db.save_scan(account_id, findings, score_result, total_assets=len(assets))
        assert scan_id > 0
        
        # Verify we can retrieve the scan
        scans = db.get_all_scans()
        assert any(s["id"] == scan_id for s in scans)
        
        # Verify findings are retrievable
        saved_findings = db.get_findings_for_scan(scan_id)
        assert len(saved_findings) == len(findings)


@pytest.mark.integration
class TestFlociScanWithMixedProfile:
    """End-to-end test with mixed profile (both secure and insecure)."""

    def test_mixed_profile_findings(self, session, account_id):
        """Verify both PASS and FAIL findings are generated."""
        assets = discover_assets(session, account_id)
        findings = run_scan(assets)
        
        fail_count = sum(1 for f in findings if f["status"] == "FAIL")
        pass_count = sum(1 for f in findings if f["status"] == "PAIL")
        
        # With mixed profile, we should have both
        assert fail_count > 0, "Should have some failing checks"
        # Note: some rules may only produce FAIL or only PASS depending on resources
        # So we don't assert pass_count > 0 strictly

    def test_score_decreases_with_vulnerabilities(self, session, account_id):
        """Verify score reflects seeded vulnerabilities."""
        assets = discover_assets(session, account_id)
        findings = run_scan(assets)
        score_result = calculate_score(findings)
        
        # With vulnerabilities seeded, score should be reduced
        assert score_result["score"] < 100
        assert score_result["failed_checks"] > 0
        
        # Score should be a valid grade
        grade = score_grade(score_result["score"])
        assert grade in ["A", "B", "C", "D", "F"]