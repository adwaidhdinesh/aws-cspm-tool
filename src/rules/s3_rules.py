"""
S3-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls.
"""

from botocore.exceptions import ClientError


def check_public_buckets(session):
    """CIS 2.1.5 — S3 buckets should not be publicly accessible."""
    s3 = session.client("s3")
    findings = []

    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        name = bucket["Name"]
        is_public = False

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    is_public = True
        except ClientError:
            pass

        try:
            policy_status = s3.get_bucket_policy_status(Bucket=name)
            if policy_status["PolicyStatus"]["IsPublic"]:
                is_public = True
        except ClientError:
            # No bucket policy set, or access denied — not public via policy
            pass

        findings.append({
            "rule_id": "S3-001",
            "cis_control": "2.1.5",
            "title": f"S3 bucket '{name}' is publicly accessible",
            "severity": "Critical",
            "resource": name,
            "status": "FAIL" if is_public else "PASS",
            "description": "S3 buckets should not allow public read/write "
                            "access unless explicitly required (e.g. static "
                            "website hosting).",
            "remediation": f"Enable 'Block Public Access' for bucket '{name}' "
                            "and remove public grants from its ACL/policy.",
        })

    return findings


def check_bucket_encryption(session):
    """CIS 2.1.1 — S3 buckets should have default encryption enabled."""
    s3 = session.client("s3")
    findings = []

    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        name = bucket["Name"]
        encrypted = True

        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            encrypted = False

        findings.append({
            "rule_id": "S3-002",
            "cis_control": "2.1.1",
            "title": f"S3 bucket '{name}' does not have default encryption enabled",
            "severity": "Medium",
            "resource": name,
            "status": "PASS" if encrypted else "FAIL",
            "description": "S3 buckets should use default server-side "
                            "encryption (SSE-S3 or SSE-KMS) to protect data at rest.",
            "remediation": f"Enable default encryption on bucket '{name}' "
                            "in the S3 console under Properties > Default encryption.",
        })

    return findings
