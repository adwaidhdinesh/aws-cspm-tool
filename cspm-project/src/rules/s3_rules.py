"""
S3-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls.

These operate purely on already-discovered Asset objects — no boto3
calls happen here.
"""


def check_public_buckets(assets):
    """CIS 2.1.5 — S3 buckets should not be publicly accessible."""
    findings = []

    for asset in assets:
        if asset.resource_type != "S3::Bucket":
            continue

        is_public = asset.metadata.get("public", False)

        findings.append({
            "rule_id": "S3-001",
            "cis_control": "2.1.5",
            "title": f"S3 bucket '{asset.name}' is publicly accessible",
            "severity": "Critical",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "FAIL" if is_public else "PASS",
            "description": "S3 buckets should not allow public read/write "
                            "access unless explicitly required (e.g. static "
                            "website hosting).",
            "remediation": f"Enable 'Block Public Access' for bucket '{asset.name}' "
                            "and remove public grants from its ACL/policy.",
        })

    return findings


def check_bucket_encryption(assets):
    """CIS 2.1.1 — S3 buckets should have default encryption enabled."""
    findings = []

    for asset in assets:
        if asset.resource_type != "S3::Bucket":
            continue

        is_encrypted = asset.metadata.get("encrypted", False)

        findings.append({
            "rule_id": "S3-002",
            "cis_control": "2.1.1",
            "title": f"S3 bucket '{asset.name}' does not have default encryption enabled",
            "severity": "Medium",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "PASS" if is_encrypted else "FAIL",
            "description": "S3 buckets should use default server-side "
                            "encryption (SSE-S3 or SSE-KMS) to protect data at rest.",
            "remediation": f"Enable default encryption on bucket '{asset.name}' "
                            "in the S3 console under Properties > Default encryption.",
        })

    return findings
