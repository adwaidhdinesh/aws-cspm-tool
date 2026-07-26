"""
CloudTrail-related CSPM checks, mapped to CIS AWS Foundations Benchmark
controls.
"""


def check_cloudtrail_enabled(session):
    """CIS 3.1 — CloudTrail should be enabled, multi-region, and logging."""
    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]

    has_multiregion_active_trail = False

    for trail in trails:
        if not trail.get("IsMultiRegionTrail"):
            continue
        status = ct.get_trail_status(Name=trail["TrailARN"])
        if status.get("IsLogging"):
            has_multiregion_active_trail = True
            break

    return [{
        "rule_id": "CT-001",
        "cis_control": "3.1",
        "title": "No active multi-region CloudTrail found",
        "severity": "High",
        "resource": "cloudtrail",
        "status": "PASS" if has_multiregion_active_trail else "FAIL",
        "description": "CloudTrail should be enabled across all regions and "
                        "actively logging to provide a full audit history of "
                        "API activity in the account.",
        "remediation": "Create a multi-region CloudTrail trail and confirm "
                        "logging is enabled in the CloudTrail console.",
    }]


def check_cloudtrail_log_validation(session):
    """CIS 3.2 — CloudTrail log file validation should be enabled."""
    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]
    findings = []

    for trail in trails:
        name = trail["Name"]
        validation_enabled = trail.get("LogFileValidationEnabled", False)

        findings.append({
            "rule_id": "CT-002",
            "cis_control": "3.2",
            "title": f"CloudTrail '{name}' does not have log file validation enabled",
            "severity": "Medium",
            "resource": name,
            "status": "PASS" if validation_enabled else "FAIL",
            "description": "Log file validation creates a digitally signed "
                            "digest so tampering with log files can be detected.",
            "remediation": f"Enable log file validation on trail '{name}' "
                            "in the CloudTrail console or via update-trail CLI.",
        })

    return findings
