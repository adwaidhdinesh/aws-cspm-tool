"""
KMS-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls.

These operate purely on already-discovered Asset objects — no boto3
calls happen here.
"""


def check_kms_key_rotation(assets):
    """CIS 2.8 — Customer-managed symmetric KMS keys should have automatic
    annual rotation enabled.
    """
    findings = []

    for asset in assets:
        if asset.resource_type != "KMS::Key":
            continue
        if asset.metadata.get("key_spec") != "SYMMETRIC_DEFAULT":
            continue  # Only symmetric keys support rotation

        rotation_enabled = asset.metadata.get("rotation_enabled", False)

        findings.append({
            "rule_id": "KMS-001",
            "cis_control": "2.8",
            "title": f"KMS key '{asset.name}' does not have rotation enabled",
            "severity": "Medium",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "PASS" if rotation_enabled else "FAIL",
            "description": "Customer-managed KMS keys should have "
                            "automatic annual key rotation enabled to "
                            "limit the impact of key compromise.",
            "remediation": f"Enable key rotation for '{asset.resource_id}' in the "
                            "KMS console or via enable-key-rotation CLI.",
        })

    return findings
