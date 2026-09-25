"""
CloudTrail-related CSPM checks, mapped to CIS AWS Foundations Benchmark
controls.

These operate purely on already-discovered Asset objects — no boto3
calls happen here.
"""


def check_cloudtrail_enabled(assets):
    """CIS 3.1 — CloudTrail should be enabled, multi-region, and logging."""
    trail_assets = [a for a in assets if a.resource_type == "CloudTrail::Trail"]

    has_active_multiregion_trail = any(
        a.metadata.get("is_multiregion") and a.metadata.get("is_logging")
        for a in trail_assets
    )

    # This is an account-level check (at least one qualifying trail), so
    # it isn't tied to a single asset's resource_id — same as before.
    return [{
        "rule_id": "CT-001",
        "cis_control": "3.1",
        "title": "No active multi-region CloudTrail found",
        "severity": "High",
        "service": "CloudTrail",
        "resource": "cloudtrail",
        "status": "PASS" if has_active_multiregion_trail else "FAIL",
        "description": "CloudTrail should be enabled across all regions and "
                        "actively logging to provide a full audit history of "
                        "API activity in the account.",
        "remediation": "Create a multi-region CloudTrail trail and confirm "
                        "logging is enabled in the CloudTrail console.",
    }]


def check_cloudtrail_log_validation(assets):
    """CIS 3.2 — CloudTrail log file validation should be enabled."""
    findings = []

    for asset in assets:
        if asset.resource_type != "CloudTrail::Trail":
            continue

        validation_enabled = asset.metadata.get("log_validation_enabled", False)

        findings.append({
            "rule_id": "CT-002",
            "cis_control": "3.2",
            "title": f"CloudTrail '{asset.name}' does not have log file validation enabled",
            "severity": "Medium",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "PASS" if validation_enabled else "FAIL",
            "description": "Log file validation creates a digitally signed "
                            "digest so tampering with log files can be detected.",
            "remediation": f"Enable log file validation on trail '{asset.name}' "
                            "in the CloudTrail console or via update-trail CLI.",
        })

    return findings
