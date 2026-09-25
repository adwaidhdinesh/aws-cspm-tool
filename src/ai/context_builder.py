"""
Builds a compact, token-cheap JSON summary of one scan for the AI Security
Copilot to use as its only source of truth. The model never sees the raw
database or talks to AWS — it only ever sees what this function returns.
"""

from src import db
from src.compliance import get_mapped_controls
from src.scoring import score_grade

# Worst-first ordering so, if a scan has many failures, the most important
# ones are the ones that survive being trimmed down to max_findings.
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def build_context(scan_id: int, max_findings: int = 30) -> dict:
    """Return a compact dict summarizing one scan: score, breakdowns, and
    the most important failing findings (trimmed to max_findings so the
    prompt sent to the model stays small and cheap).

    Raises ValueError if the scan_id doesn't exist.
    """
    scan = next((s for s in db.get_all_scans() if s["id"] == scan_id), None)
    if scan is None:
        raise ValueError(f"No scan found with id {scan_id}")

    findings = db.get_findings_for_scan(scan_id)
    failing = [f for f in findings if f["status"] == "FAIL"]

    by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    by_service = {}
    for f in failing:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        by_service[f["service"]] = by_service.get(f["service"], 0) + 1

    worst_first = sorted(failing, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    finding_summaries = [
        {
            "rule_id": f["rule_id"],
            "title": f["title"],
            "severity": f["severity"],
            "service": f["service"],
            "resource": f["resource"],
            "cis_control": f["cis_control"],
            "description": f.get("description", ""),
            "remediation": f["remediation"],
            "compliance_mappings": get_mapped_controls(f["cis_control"]),
        }
        for f in worst_first[:max_findings]
    ]

    return {
        "account_id": scan["account_id"],
        "scan_timestamp": scan["timestamp"],
        "score": scan["score"],
        "grade": score_grade(scan["score"]),
        "total_assets": scan.get("total_assets") or 0,
        "total_checks": scan["total_checks"],
        "passed_checks": scan["passed_checks"],
        "failed_checks": scan["failed_checks"],
        "failures_by_severity": by_severity,
        "failures_by_service": by_service,
        "failing_findings": finding_summaries,
        "truncated": len(failing) > max_findings,
    }
