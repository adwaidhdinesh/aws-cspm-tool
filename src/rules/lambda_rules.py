"""
Lambda-related CSPM checks. Not part of the core CIS AWS Foundations
Benchmark, so these are treated as custom checks without a cis_control
mapping (they still contribute to the posture score, just won't appear
under the NIST/PCI/ISO Compliance tab).
"""

import json

from botocore.exceptions import ClientError


def check_lambda_public_access(session):
    """Custom check — Lambda functions should not have a resource policy
    that grants invoke access to '*' (anyone) or unauthenticated callers.
    """
    lam = session.client("lambda")
    findings = []

    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page["Functions"]:
            name = fn["FunctionName"]
            is_public = False

            try:
                policy_doc = json.loads(lam.get_policy(FunctionName=name)["Policy"])
                for stmt in policy_doc.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal")
                    if principal == "*":
                        is_public = True
                    elif isinstance(principal, dict) and principal.get("AWS") == "*":
                        is_public = True
            except ClientError:
                pass  # No resource policy attached — not public

            findings.append({
                "rule_id": "LAMBDA-001",
                "cis_control": "CUSTOM-1",
                "title": f"Lambda function '{name}' allows public invocation",
                "severity": "Critical",
                "resource": name,
                "status": "FAIL" if is_public else "PASS",
                "description": "A Lambda function's resource policy should "
                                "not grant invoke permission to everyone ('*'); "
                                "this can expose it to unauthenticated callers.",
                "remediation": f"Review the resource policy on '{name}' and "
                                "scope the Principal to specific accounts, "
                                "roles, or services instead of '*'.",
            })

    return findings
