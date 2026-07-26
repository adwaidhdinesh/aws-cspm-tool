"""
VPC-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls.
"""


def check_default_sg_restricts_traffic(session):
    """CIS 5.3 — The default security group of every VPC should restrict
    all traffic (i.e. have no inbound rules).
    """
    ec2 = session.client("ec2")
    findings = []

    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]

    for sg in sgs:
        sg_id = sg["GroupId"]
        vpc_id = sg.get("VpcId", "unknown-vpc")
        has_inbound_rules = len(sg.get("IpPermissions", [])) > 0

        findings.append({
            "rule_id": "VPC-001",
            "cis_control": "5.3",
            "title": f"Default security group in VPC '{vpc_id}' allows inbound traffic",
            "severity": "Medium",
            "resource": f"{sg_id} ({vpc_id})",
            "status": "FAIL" if has_inbound_rules else "PASS",
            "description": "The default security group of every VPC should "
                            "have no inbound rules so that resources "
                            "accidentally left in it aren't exposed.",
            "remediation": f"Remove all inbound rules from the default "
                            f"security group '{sg_id}' and use dedicated, "
                            "purpose-built security groups instead.",
        })

    return findings


def check_vpc_flow_logs_enabled(session):
    """CIS 3.9 — VPC flow logging should be enabled for every VPC."""
    ec2 = session.client("ec2")
    findings = []

    vpcs = ec2.describe_vpcs()["Vpcs"]
    flow_logs = ec2.describe_flow_logs()["FlowLogs"]
    vpcs_with_logs = {
        fl["ResourceId"] for fl in flow_logs if fl.get("ResourceType") == "VPC"
    }

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        has_flow_logs = vpc_id in vpcs_with_logs

        findings.append({
            "rule_id": "VPC-002",
            "cis_control": "3.9",
            "title": f"VPC '{vpc_id}' does not have flow logging enabled",
            "severity": "Medium",
            "resource": vpc_id,
            "status": "PASS" if has_flow_logs else "FAIL",
            "description": "VPC flow logs capture network traffic metadata, "
                            "which is essential for incident response and "
                            "detecting unusual traffic patterns.",
            "remediation": f"Enable a VPC flow log for '{vpc_id}' in the VPC "
                            "console, sending logs to CloudWatch Logs or S3.",
        })

    return findings
