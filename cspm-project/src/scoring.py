"""
Converts a list of findings into a single 0-100 security posture score.

Approach: start at 100 and deduct points for each FAILED finding, weighted
by severity. This is intentionally simple and easy to explain/defend in a
presentation — feel free to tune the weights or switch to a percentage-of-
checks-passed model instead.
"""

SEVERITY_WEIGHTS = {
    "Critical": 15,
    "High": 8,
    "Medium": 4,
    "Low": 1,
}


def calculate_score(findings: list[dict]) -> dict:
    """Calculate an overall posture score and a per-severity breakdown.

    Returns:
        {
            "score": int (0-100),
            "total_checks": int,
            "failed_checks": int,
            "passed_checks": int,
            "by_severity": {"Critical": {"fail": n, "pass": n}, ...}
        }
    """
    score = 100
    by_severity = {sev: {"fail": 0, "pass": 0} for sev in SEVERITY_WEIGHTS}

    for finding in findings:
        severity = finding.get("severity", "Low")
        status = finding.get("status", "PASS")

        if status == "FAIL":
            by_severity[severity]["fail"] += 1
            score -= SEVERITY_WEIGHTS.get(severity, 1)
        else:
            by_severity[severity]["pass"] += 1

    score = max(0, min(100, score))
    failed_checks = sum(v["fail"] for v in by_severity.values())
    passed_checks = sum(v["pass"] for v in by_severity.values())

    return {
        "score": score,
        "total_checks": failed_checks + passed_checks,
        "failed_checks": failed_checks,
        "passed_checks": passed_checks,
        "by_severity": by_severity,
    }


def score_grade(score: int) -> str:
    """Map a numeric score to a letter grade for quick readability."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"
