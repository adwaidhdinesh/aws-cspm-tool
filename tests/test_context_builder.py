"""Unit tests for AI context builder — no API calls required."""

import pytest

from src.ai.context_builder import build_context

SCAN_RECORD = {
    "id": 1,
    "account_id": "123456789012",
    "timestamp": "2026-08-17T12:00:00+00:00",
    "score": 84,
    "total_checks": 4,
    "passed_checks": 1,
    "failed_checks": 3,
    "total_assets": 10,
}

FINDINGS = [
    {
        "rule_id": "S3-001",
        "title": "S3 bucket 'prod-bucket' is publicly accessible",
        "severity": "Critical",
        "service": "S3",
        "resource": "prod-bucket",
        "cis_control": "2.1.5",
        "status": "FAIL",
        "description": "S3 buckets should not allow public access.",
        "remediation": "Enable Block Public Access.",
    },
    {
        "rule_id": "CT-001",
        "title": "No active multi-region CloudTrail found",
        "severity": "High",
        "service": "CloudTrail",
        "resource": "cloudtrail",
        "cis_control": "3.1",
        "status": "FAIL",
        "description": "CloudTrail should be enabled.",
        "remediation": "Create a multi-region trail.",
    },
    {
        "rule_id": "S3-002",
        "title": "S3 bucket 'log-bucket' not encrypted",
        "severity": "Medium",
        "service": "S3",
        "resource": "log-bucket",
        "cis_control": "2.1.1",
        "status": "PASS",
        "description": "S3 default encryption.",
        "remediation": "Enable default encryption.",
    },
]


def test_build_context_basic(monkeypatch):
    monkeypatch.setattr("src.ai.context_builder.db.get_all_scans", lambda: [SCAN_RECORD])
    monkeypatch.setattr("src.ai.context_builder.db.get_findings_for_scan", lambda sid: FINDINGS)

    ctx = build_context(1)

    assert ctx["account_id"] == "123456789012"
    assert ctx["score"] == 84
    assert ctx["grade"] == "B"
    assert ctx["total_assets"] == 10
    assert ctx["total_checks"] == 4
    assert ctx["failed_checks"] == 3
    assert ctx["passed_checks"] == 1


def test_build_context_only_includes_failing(monkeypatch):
    monkeypatch.setattr("src.ai.context_builder.db.get_all_scans", lambda: [SCAN_RECORD])
    monkeypatch.setattr("src.ai.context_builder.db.get_findings_for_scan", lambda sid: FINDINGS)

    ctx = build_context(1)

    failing_only = ctx["failing_findings"]
    severities = [f["severity"] for f in failing_only]
    # Only FAIL findings should appear
    assert severities == ["Critical", "High"]
    assert len(failing_only) == 2


def test_build_context_worst_first_ordering(monkeypatch):
    monkeypatch.setattr("src.ai.context_builder.db.get_all_scans", lambda: [SCAN_RECORD])
    # Mix severities
    mixed = [
        {"rule_id": "X", "status": "FAIL", "severity": "Low", "title": "l", "service": "S3",
         "resource": "r", "cis_control": "1.1", "description": "", "remediation": ""},
        {"rule_id": "Y", "status": "FAIL", "severity": "Critical", "title": "c", "service": "S3",
         "resource": "r", "cis_control": "1.1", "description": "", "remediation": ""},
        {"rule_id": "Z", "status": "FAIL", "severity": "High", "title": "h", "service": "S3",
         "resource": "r", "cis_control": "1.1", "description": "", "remediation": ""},
        {"rule_id": "P", "status": "PASS", "severity": "Medium", "title": "p", "service": "S3",
         "resource": "r", "cis_control": "1.1", "description": "", "remediation": ""},
    ]
    monkeypatch.setattr("src.ai.context_builder.db.get_findings_for_scan", lambda sid: mixed)

    ctx = build_context(1)
    sevs = [f["severity"] for f in ctx["failing_findings"]]
    assert sevs == ["Critical", "High", "Low"]


def test_build_context_truncates_at_max_findings(monkeypatch):
    monkeypatch.setattr("src.ai.context_builder.db.get_all_scans", lambda: [SCAN_RECORD])
    many = [
        {"rule_id": f"R-{i}", "status": "FAIL", "severity": "Low", "title": f"f{i}",
         "service": "EC2", "resource": f"sg-{i}", "cis_control": "5.2",
         "description": "", "remediation": ""}
        for i in range(60)
    ]
    monkeypatch.setattr("src.ai.context_builder.db.get_findings_for_scan", lambda sid: many)

    ctx = build_context(1, max_findings=20)
    assert len(ctx["failing_findings"]) == 20
    assert ctx["truncated"] is True


def test_build_context_no_truncation_when_under_limit(monkeypatch):
    monkeypatch.setattr("src.ai.context_builder.db.get_all_scans", lambda: [SCAN_RECORD])
    monkeypatch.setattr("src.ai.context_builder.db.get_findings_for_scan", lambda sid: FINDINGS)

    ctx = build_context(1, max_findings=50)
    assert ctx["truncated"] is False


def test_build_context_missing_scan_raises(monkeypatch):
    monkeypatch.setattr("src.ai.context_builder.db.get_all_scans", lambda: [])
    with pytest.raises(ValueError, match="No scan found"):
        build_context(999)


def test_build_context_failures_by_service(monkeypatch):
    monkeypatch.setattr("src.ai.context_builder.db.get_all_scans", lambda: [SCAN_RECORD])
    monkeypatch.setattr("src.ai.context_builder.db.get_findings_for_scan", lambda sid: FINDINGS)

    ctx = build_context(1)
    assert ctx["failures_by_service"] == {"S3": 1, "CloudTrail": 1}