"""
RDS-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls.
"""


def check_rds_public_access(session):
    """CIS 2.3.2 — RDS instances should not be publicly accessible."""
    rds = session.client("rds")
    findings = []

    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for instance in page["DBInstances"]:
            identifier = instance["DBInstanceIdentifier"]
            is_public = instance.get("PubliclyAccessible", False)

            findings.append({
                "rule_id": "RDS-001",
                "cis_control": "2.3.2",
                "title": f"RDS instance '{identifier}' is publicly accessible",
                "severity": "Critical",
                "resource": identifier,
                "status": "FAIL" if is_public else "PASS",
                "description": "RDS instances should not be reachable from "
                                "the public internet; database access should "
                                "go through application servers inside the VPC.",
                "remediation": f"Disable 'Publicly Accessible' on RDS instance "
                                f"'{identifier}' and restrict access via security groups.",
            })

    return findings


def check_rds_encryption(session):
    """CIS 2.3.1 — RDS instances should have storage encryption enabled."""
    rds = session.client("rds")
    findings = []

    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for instance in page["DBInstances"]:
            identifier = instance["DBInstanceIdentifier"]
            is_encrypted = instance.get("StorageEncrypted", False)

            findings.append({
                "rule_id": "RDS-002",
                "cis_control": "2.3.1",
                "title": f"RDS instance '{identifier}' does not have storage encryption enabled",
                "severity": "High",
                "resource": identifier,
                "status": "PASS" if is_encrypted else "FAIL",
                "description": "RDS storage should be encrypted at rest using "
                                "KMS to protect data if underlying storage is compromised.",
                "remediation": f"Encryption can't be enabled on an existing "
                                f"instance — create an encrypted snapshot of "
                                f"'{identifier}' and restore it as a new encrypted instance.",
            })

    return findings
