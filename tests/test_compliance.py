"""Unit tests for compliance mapping module."""

from src.compliance import (
    get_mapped_controls,
    format_mapped_controls,
    compliance_summary,
    framework_score,
    FRAMEWORKS,
)


def test_known_cis_control_returns_mappings():
    mapped = get_mapped_controls("1.5")  # Root MFA
    assert "NIST 800-53" in mapped
    assert "PCI DSS v4.0" in mapped
    assert "ISO 27001:2022" in mapped
    assert "IA-2(1)" in mapped["NIST 800-53"]


def test_unknown_cis_control_returns_empty_lists():
    mapped = get_mapped_controls("99.99")
    for fw in FRAMEWORKS:
        assert mapped[fw] == []


def test_custom_cis_control_returns_empty():
    mapped = get_mapped_controls("CUSTOM-1")
    for fw in FRAMEWORKS:
        assert mapped[fw] == []


def test_format_mapped_controls_joins_strings():
    mapped = format_mapped_controls("1.5")
    nist = mapped["NIST 800-53"]
    assert isinstance(nist, str)
    assert "IA-2(1)" in nist
    assert "AC-6(5)" in nist


def test_format_unknown_returns_dash():
    mapped = format_mapped_controls("99.99")
    for fw in FRAMEWORKS:
        assert mapped[fw] == "—"


def test_compliance_summary_rolls_up_correctly():
    findings = [
        {"cis_control": "1.5", "status": "FAIL"},   # Root MFA
        {"cis_control": "1.5", "status": "PASS"},   # Same control
        {"cis_control": "2.1.5", "status": "FAIL"}, # Public S3
    ]
    summary = compliance_summary(findings)
    nist = summary["NIST 800-53"]
    # IA-2(1) has 1 fail, 1 pass -> fail > 0
    assert nist["IA-2(1)"]["fail"] == 1
    assert nist["IA-2(1)"]["pass"] == 1
    # AC-3 from 2.1.5 has 1 fail
    assert nist["AC-3"]["fail"] == 1
    assert nist["AC-3"]["pass"] == 0


def test_framework_score_all_pass_returns_100():
    findings = [{"cis_control": "1.5", "status": "PASS"}]
    summary = compliance_summary(findings)
    score = framework_score(summary["NIST 800-53"])
    assert score == 100


def test_framework_score_any_fail_returns_less():
    findings = [{"cis_control": "1.5", "status": "FAIL"}]
    summary = compliance_summary(findings)
    score = framework_score(summary["NIST 800-53"])
    assert score < 100


def test_framework_score_empty_returns_100():
    score = framework_score({})
    assert score == 100


def test_multiple_controls_calculates_percentage():
    findings = [
        {"cis_control": "1.5", "status": "PASS"},
        {"cis_control": "1.10", "status": "FAIL"},
    ]
    summary = compliance_summary(findings)
    # Two controls, one has fail -> 50%
    score = framework_score(summary["NIST 800-53"])
    assert score == 50