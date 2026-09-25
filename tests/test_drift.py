"""Unit tests for drift detection module."""

from src.drift import compare_scans, summarize_drift, CHANGE_TYPES


def _finding(rule_id, service, resource, status="FAIL", severity="Medium"):
    return {
        "rule_id": rule_id,
        "service": service,
        "resource": resource,
        "status": status,
        "title": f"Test {rule_id}",
        "severity": severity,
    }


def test_new_fail_detected():
    prev = [_finding("S3-001", "S3", "bucket", status="PASS")]
    curr = [_finding("S3-001", "S3", "bucket", status="FAIL")]
    changes = compare_scans(prev, curr)
    assert len(changes) == 1
    assert changes[0]["type"] == "NEW_FAIL"


def test_resolved_detected():
    prev = [_finding("S3-001", "S3", "bucket", status="FAIL")]
    curr = [_finding("S3-001", "S3", "bucket", status="PASS")]
    changes = compare_scans(prev, curr)
    assert len(changes) == 1
    assert changes[0]["type"] == "RESOLVED"


def test_new_resource_detected():
    prev = []
    curr = [_finding("S3-001", "S3", "new-bucket", status="FAIL")]
    changes = compare_scans(prev, curr)
    assert len(changes) == 1
    assert changes[0]["type"] == "NEW_RESOURCE"


def test_removed_resource_detected():
    prev = [_finding("S3-001", "S3", "old-bucket", status="PASS")]
    curr = []
    changes = compare_scans(prev, curr)
    assert len(changes) == 1
    assert changes[0]["type"] == "REMOVED_RESOURCE"


def test_mixed_changes():
    prev = [
        _finding("S3-001", "S3", "bucket1", status="PASS"),
        _finding("S3-001", "S3", "bucket2", status="FAIL"),
        _finding("EC2-001", "EC2", "sg-1", status="FAIL"),
    ]
    curr = [
        _finding("S3-001", "S3", "bucket1", status="FAIL"),   # NEW_FAIL
        _finding("S3-001", "S3", "bucket2", status="PASS"),   # RESOLVED
        _finding("S3-001", "S3", "bucket3", status="FAIL"),   # NEW_RESOURCE
    ]
    changes = compare_scans(prev, curr)
    types = {c["type"] for c in changes}
    assert "NEW_FAIL" in types
    assert "RESOLVED" in types
    assert "NEW_RESOURCE" in types
    assert "REMOVED_RESOURCE" in types  # EC2-001 removed


def test_no_changes_returns_empty():
    prev = [_finding("S3-001", "S3", "bucket", status="FAIL")]
    curr = [_finding("S3-001", "S3", "bucket", status="FAIL")]
    assert compare_scans(prev, curr) == []


def test_summarize_drift_counts_correctly():
    changes = [
        {"type": "NEW_FAIL"},
        {"type": "NEW_FAIL"},
        {"type": "RESOLVED"},
        {"type": "NEW_RESOURCE"},
    ]
    counts = summarize_drift(changes)
    assert counts["NEW_FAIL"] == 2
    assert counts["RESOLVED"] == 1
    assert counts["NEW_RESOURCE"] == 1
    assert counts["REMOVED_RESOURCE"] == 0


def test_summarize_drift_always_returns_all_keys():
    counts = summarize_drift([])
    for ct in CHANGE_TYPES:
        assert ct in counts