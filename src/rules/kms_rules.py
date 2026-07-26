"""
KMS-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls.
"""

from botocore.exceptions import ClientError


def check_kms_key_rotation(session):
    """CIS 2.8 — Customer-managed symmetric KMS keys should have automatic
    annual rotation enabled.
    """
    kms = session.client("kms")
    findings = []

    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page["Keys"]:
            key_id = key["KeyId"]

            try:
                metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            except ClientError:
                continue

            # Only customer-managed symmetric keys support automatic rotation
            if metadata.get("KeyManager") != "CUSTOMER":
                continue
            if metadata.get("KeySpec") != "SYMMETRIC_DEFAULT":
                continue
            if metadata.get("KeyState") != "Enabled":
                continue

            try:
                rotation_enabled = kms.get_key_rotation_status(
                    KeyId=key_id
                )["KeyRotationEnabled"]
            except ClientError:
                rotation_enabled = False

            alias = metadata.get("Description") or key_id

            findings.append({
                "rule_id": "KMS-001",
                "cis_control": "2.8",
                "title": f"KMS key '{alias}' does not have rotation enabled",
                "severity": "Medium",
                "resource": key_id,
                "status": "PASS" if rotation_enabled else "FAIL",
                "description": "Customer-managed KMS keys should have "
                                "automatic annual key rotation enabled to "
                                "limit the impact of key compromise.",
                "remediation": f"Enable key rotation for '{key_id}' in the "
                                "KMS console or via enable-key-rotation CLI.",
            })

    return findings
