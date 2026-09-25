"""
IAM-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls.

These operate purely on already-discovered Asset objects (see
src/inventory/aws_inventory.py) — no boto3 calls happen here.
"""


def check_root_mfa(assets):
    """CIS 1.5 — Root account should have MFA enabled."""
    findings = []

    for asset in assets:
        if asset.resource_type != "IAM::RootAccount":
            continue

        mfa_enabled = asset.metadata.get("mfa_enabled", False)

        findings.append({
            "rule_id": "IAM-001",
            "cis_control": "1.5",
            "title": "Root account MFA is not enabled",
            "severity": "Critical",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "PASS" if mfa_enabled else "FAIL",
            "description": "The AWS root account should always have multi-factor "
                            "authentication enabled since it has unrestricted access.",
            "remediation": "Enable a virtual or hardware MFA device for the root "
                            "user in the IAM console under 'My Security Credentials'.",
        })

    return findings


def check_iam_user_mfa(assets):
    """CIS 1.10 — IAM users with console access should have MFA enabled."""
    findings = []

    for asset in assets:
        if asset.resource_type != "IAM::User":
            continue
        if not asset.metadata.get("has_console_access", False):
            continue  # No password login = not applicable

        mfa_enabled = asset.metadata.get("mfa_enabled", False)

        findings.append({
            "rule_id": "IAM-002",
            "cis_control": "1.10",
            "title": f"IAM user '{asset.name}' has console access without MFA",
            "severity": "High",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "PASS" if mfa_enabled else "FAIL",
            "description": "IAM users with console passwords should have "
                            "MFA enabled to prevent credential compromise.",
            "remediation": f"Enable an MFA device for user '{asset.name}' in "
                            "the IAM console.",
        })

    return findings


def check_wildcard_admin_policies(assets):
    """CIS 1.16 — Customer-managed policies should not grant '*:*' full admin."""
    findings = []

    for asset in assets:
        if asset.resource_type != "IAM::Policy":
            continue

        is_wildcard_admin = asset.metadata.get("is_wildcard_admin", False)

        findings.append({
            "rule_id": "IAM-003",
            "cis_control": "1.16",
            "title": f"IAM policy '{asset.name}' grants full admin access",
            "severity": "Critical",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "FAIL" if is_wildcard_admin else "PASS",
            "description": "Policies granting 'Action: *' on 'Resource: *' "
                            "violate least privilege and should be scoped down.",
            "remediation": "Replace the wildcard policy with a scoped-down "
                            "policy granting only the required actions and resources.",
        })

    return findings
