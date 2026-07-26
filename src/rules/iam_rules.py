"""
IAM-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls.
"""


def check_root_mfa(session):
    """CIS 1.5 — Root account should have MFA enabled."""
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    root_mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1

    return [{
        "rule_id": "IAM-001",
        "cis_control": "1.5",
        "title": "Root account MFA is not enabled",
        "severity": "Critical",
        "resource": "root-account",
        "status": "PASS" if root_mfa_enabled else "FAIL",
        "description": "The AWS root account should always have multi-factor "
                        "authentication enabled since it has unrestricted access.",
        "remediation": "Enable a virtual or hardware MFA device for the root "
                        "user in the IAM console under 'My Security Credentials'.",
    }]


def check_iam_user_mfa(session):
    """CIS 1.10 — IAM users with console access should have MFA enabled."""
    iam = session.client("iam")
    findings = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]

            # Skip users without console login (no login profile = no password)
            try:
                iam.get_login_profile(UserName=username)
            except iam.exceptions.NoSuchEntityException:
                continue

            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            has_mfa = len(mfa_devices) > 0

            findings.append({
                "rule_id": "IAM-002",
                "cis_control": "1.10",
                "title": f"IAM user '{username}' has console access without MFA",
                "severity": "High",
                "resource": username,
                "status": "PASS" if has_mfa else "FAIL",
                "description": "IAM users with console passwords should have "
                                "MFA enabled to prevent credential compromise.",
                "remediation": f"Enable an MFA device for user '{username}' in "
                                "the IAM console.",
            })

    return findings


def check_wildcard_admin_policies(session):
    """CIS 1.16 — Customer-managed policies should not grant '*:*' full admin."""
    iam = session.client("iam")
    findings = []

    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):  # Local = customer-managed only
        for policy in page["Policies"]:
            policy_arn = policy["Arn"]
            version_id = policy["DefaultVersionId"]
            policy_doc = iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )["PolicyVersion"]["Document"]

            is_wildcard_admin = _has_full_wildcard(policy_doc)

            findings.append({
                "rule_id": "IAM-003",
                "cis_control": "1.16",
                "title": f"IAM policy '{policy['PolicyName']}' grants full admin access",
                "severity": "Critical",
                "resource": policy["PolicyName"],
                "status": "FAIL" if is_wildcard_admin else "PASS",
                "description": "Policies granting 'Action: *' on 'Resource: *' "
                                "violate least privilege and should be scoped down.",
                "remediation": "Replace the wildcard policy with a scoped-down "
                                "policy granting only the required actions and resources.",
            })

    return findings


def _has_full_wildcard(policy_doc: dict) -> bool:
    """Return True if a policy document contains an Allow statement with
    Action: '*' and Resource: '*'.
    """
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources

        if "*" in actions and "*" in resources:
            return True

    return False
