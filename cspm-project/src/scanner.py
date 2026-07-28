"""
Orchestrates running every registered rule check against the discovered
asset inventory (see src/inventory/) and collecting the results into a
flat list of findings.
"""

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

# Register every rule function here. Each must accept a list[Asset] and
# return a list of finding dicts. Rules never call boto3 directly — all
# AWS access happens once, up front, during asset discovery.
ALL_RULES = [
    iam_rules.check_root_mfa,
    iam_rules.check_iam_user_mfa,
    iam_rules.check_wildcard_admin_policies,
    s3_rules.check_public_buckets,
    s3_rules.check_bucket_encryption,
    ec2_rules.check_open_security_groups,
    ec2_rules.check_instance_public_ip,
    cloudtrail_rules.check_cloudtrail_enabled,
    cloudtrail_rules.check_cloudtrail_log_validation,
    rds_rules.check_rds_public_access,
    rds_rules.check_rds_encryption,
    kms_rules.check_kms_key_rotation,
    vpc_rules.check_default_sg_restricts_traffic,
    vpc_rules.check_vpc_flow_logs_enabled,
    lambda_rules.check_lambda_public_access,
]


def run_scan(assets: list, verbose: bool = True) -> list:
    """Run every rule in ALL_RULES against the asset inventory and return
    the combined findings list.

    A rule that raises an exception is skipped with a warning rather than
    crashing the whole scan — assets are already in memory at this point,
    so a bug in one rule can't take down asset discovery or other rules.
    """
    all_findings = []

    for rule_fn in ALL_RULES:
        rule_name = rule_fn.__name__
        try:
            if verbose:
                print(f"  Running {rule_name}...")
            findings = rule_fn(assets)
            all_findings.extend(findings)
        except Exception as e:
            if verbose:
                print(f"  ⚠️  Skipped {rule_name} due to error: {e}")

    return all_findings
