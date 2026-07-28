"""
VPC-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls.

These operate purely on already-discovered Asset objects — no boto3
calls happen here.
"""


def check_default_sg_restricts_traffic(assets):
    """CIS 5.3 — The default security group of every VPC should restrict
    all traffic (i.e. have no inbound rules).
    """
    findings = []

    for asset in assets:
        if asset.resource_type != "EC2::SecurityGroup":
            continue
        if not asset.metadata.get("is_default", False):
            continue

        has_inbound_rules = asset.metadata.get("has_inbound_rules", False)

        findings.append({
            "rule_id": "VPC-001",
            "cis_control": "5.3",
            "title": f"Default security group '{asset.resource_id}' allows inbound traffic",
            "severity": "Medium",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "FAIL" if has_inbound_rules else "PASS",
            "description": "The default security group of every VPC should "
                            "have no inbound rules so that resources "
                            "accidentally left in it aren't exposed.",
            "remediation": f"Remove all inbound rules from the default "
                            f"security group '{asset.resource_id}' and use "
                            "dedicated, purpose-built security groups instead.",
        })

    return findings


def check_vpc_flow_logs_enabled(assets):
    """CIS 3.9 — VPC flow logging should be enabled for every VPC."""
    findings = []

    for asset in assets:
        if asset.resource_type != "VPC::Vpc":
            continue

        has_flow_logs = asset.metadata.get("has_flow_logs", False)

        findings.append({
            "rule_id": "VPC-002",
            "cis_control": "3.9",
            "title": f"VPC '{asset.resource_id}' does not have flow logging enabled",
            "severity": "Medium",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "PASS" if has_flow_logs else "FAIL",
            "description": "VPC flow logs capture network traffic metadata, "
                            "which is essential for incident response and "
                            "detecting unusual traffic patterns.",
            "remediation": f"Enable a VPC flow log for '{asset.resource_id}' in "
                            "the VPC console, sending logs to CloudWatch Logs or S3.",
        })

    return findings
