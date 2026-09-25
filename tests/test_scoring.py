"""Unit tests for scoring module."""

from src.scoring import calculate_score, score_grade


def test_no_failures_score_100():
    findings = [
        {"status": "PASS", "severity": "Critical"},
        {"status": "PASS", "severity": "High"},
        {"status": "PASS", "severity": "Medium"},
        {"status": "PASS", "severity": "Low"},
    ]
    result = calculate_score(findings)
    assert result["score"] == 100
    assert result["passed_checks"] == 4
    assert result["failed_checks"] == 0


def test_weighted_percentage_calculation():
    findings = [
        {"status": "FAIL", "severity": "Critical"},  # weight 15
        {"status": "PASS", "severity": "Critical"},  # weight 15
    ]
    # Total weight = 30, passed weight = 15 -> 50%
    result = calculate_score(findings)
    assert result["score"] == 50
    assert result["failed_checks"] == 1


def test_multiple_severities_calculate_correctly():
    findings = [
        {"status": "PASS", "severity": "Medium"},    # weight 4
        {"status": "FAIL", "severity": "Low"},       # weight 1
    ]
    result = calculate_score(findings)
    # Total weight = 5, passed = 4 -> 80%
    assert result["score"] == 80
    assert result["by_severity"]["Medium"]["pass"] == 1
    assert result["by_severity"]["Low"]["fail"] == 1


def test_score_never_below_zero():
    findings = [{"status": "FAIL", "severity": "Critical"} for _ in range(10)]
    result = calculate_score(findings)
    assert result["score"] == 0


def test_score_never_above_100():
    findings = [{"status": "PASS", "severity": "Critical"} for _ in range(10)]
    result = calculate_score(findings)
    assert result["score"] == 100


def test_grade_boundaries():
    assert score_grade(100) == "A"
    assert score_grade(95) == "A"
    assert score_grade(90) == "A"
    assert score_grade(89) == "B"
    assert score_grade(85) == "B"
    assert score_grade(80) == "B"
    assert score_grade(79) == "C"
    assert score_grade(75) == "C"
    assert score_grade(70) == "C"
    assert score_grade(69) == "D"
    assert score_grade(65) == "D"
    assert score_grade(60) == "D"
    assert score_grade(59) == "F"
    assert score_grade(0) == "F"


def test_severity_breakdown_present():
    findings = [{"status": "FAIL", "severity": "High"}]
    result = calculate_score(findings)
    assert "by_severity" in result
    assert result["by_severity"]["High"]["fail"] == 1
    assert result["by_severity"]["Critical"]["pass"] == 0


def test_unknown_severity_defaults_to_low_weight():
    findings = [
        {"status": "PASS", "severity": "Critical"},  # weight 15
        {"status": "FAIL", "severity": "UNKNOWN"}    # defaults to Low, weight 1
    ]
    result = calculate_score(findings)
    # Total weight = 16, passed weight = 15 -> int((15/16) * 100) = int(93.75) = 93
    assert result["score"] == 93