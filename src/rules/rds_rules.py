"""
RDS-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls.

These operate purely on already-discovered Asset objects — no boto3
calls happen here.
"""


def check_rds_public_access(assets):
    """CIS 2.3.2 — RDS instances should not be publicly accessible."""
    findings = []

    for asset in assets:
        if asset.resource_type != "RDS::Instance":
            continue

        is_public = asset.metadata.get("publicly_accessible", False)

        findings.append({
            "rule_id": "RDS-001",
            "cis_control": "2.3.2",
            "title": f"RDS instance '{asset.name}' is publicly accessible",
            "severity": "Critical",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "FAIL" if is_public else "PASS",
            "description": "RDS instances should not be reachable from "
                            "the public internet; database access should "
                            "go through application servers inside the VPC.",
            "remediation": f"Disable 'Publicly Accessible' on RDS instance "
                            f"'{asset.name}' and restrict access via security groups.",
        })

    return findings


def check_rds_encryption(assets):
    """CIS 2.3.1 — RDS instances should have storage encryption enabled."""
    findings = []

    for asset in assets:
        if asset.resource_type != "RDS::Instance":
            continue

        is_encrypted = asset.metadata.get("storage_encrypted", False)

        findings.append({
            "rule_id": "RDS-002",
            "cis_control": "2.3.1",
            "title": f"RDS instance '{asset.name}' does not have storage encryption enabled",
            "severity": "High",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "PASS" if is_encrypted else "FAIL",
            "description": "RDS storage should be encrypted at rest using "
                            "KMS to protect data if underlying storage is compromised.",
            "remediation": f"Encryption can't be enabled on an existing "
                            f"instance — create an encrypted snapshot of "
                            f"'{asset.name}' and restore it as a new encrypted instance.",
        })

    return findings
