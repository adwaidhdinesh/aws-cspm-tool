"""
Lambda-related CSPM checks. Not part of the core CIS AWS Foundations
Benchmark, so this is a custom check without a cis_control mapping (it
still contributes to the posture score, just won't appear under the
NIST/PCI/ISO Compliance tab).

Operates purely on already-discovered Asset objects — no boto3 calls
happen here.
"""


def check_lambda_public_access(assets):
    """Custom check — Lambda functions should not have a resource policy
    that grants invoke access to '*' (anyone) or unauthenticated callers.
    """
    findings = []

    for asset in assets:
        if asset.resource_type != "Lambda::Function":
            continue

        is_public = asset.metadata.get("public", False)

        findings.append({
            "rule_id": "LAMBDA-001",
            "cis_control": "CUSTOM-1",
            "title": f"Lambda function '{asset.name}' allows public invocation",
            "severity": "Critical",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "FAIL" if is_public else "PASS",
            "description": "A Lambda function's resource policy should "
                            "not grant invoke permission to everyone ('*'); "
                            "this can expose it to unauthenticated callers.",
            "remediation": f"Review the resource policy on '{asset.name}' and "
                            "scope the Principal to specific accounts, "
                            "roles, or services instead of '*'.",
        })

    return findings
