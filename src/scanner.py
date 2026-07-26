"""
Orchestrates running every registered rule check against an AWS account
and collecting the results into a flat list of findings.
"""

import boto3

from src.rules import (
    cloudtrail_rules,
    ec2_rules,
    iam_rules,
    kms_rules,
    lambda_rules,
    rds_rules,
    s3_rules,
    vpc_rules,
)

# Register every rule function here. Each must accept a boto3 session
# and return a list of finding dicts.
ALL_RULES = [
    iam_rules.check_root_mfa,
    iam_rules.check_iam_user_mfa,
    iam_rules.check_wildcard_admin_policies,
    s3_rules.check_public_buckets,
    s3_rules.check_bucket_encryption,
    ec2_rules.check_open_security_groups,
    cloudtrail_rules.check_cloudtrail_enabled,
    cloudtrail_rules.check_cloudtrail_log_validation,
    rds_rules.check_rds_public_access,
    rds_rules.check_rds_encryption,
    kms_rules.check_kms_key_rotation,
    vpc_rules.check_default_sg_restricts_traffic,
    vpc_rules.check_vpc_flow_logs_enabled,
    lambda_rules.check_lambda_public_access,
]


def run_scan(session: boto3.Session, verbose: bool = True) -> list:
    """Run every rule in ALL_RULES and return the combined findings list.

    A rule that raises an exception (e.g. due to missing permissions) is
    skipped with a warning rather than crashing the whole scan.
    """
    all_findings = []

    for rule_fn in ALL_RULES:
        rule_name = rule_fn.__name__
        try:
            if verbose:
                print(f"  Running {rule_name}...")
            findings = rule_fn(session)
            all_findings.extend(findings)
        except Exception as e:
            if verbose:
                print(f"  ⚠️  Skipped {rule_name} due to error: {e}")

    return all_findings
