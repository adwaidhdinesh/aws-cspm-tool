"""
EC2 / networking-related CSPM checks, mapped to CIS AWS Foundations Benchmark
controls.
"""

# Ports that should never be open to the world (0.0.0.0/0)
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
}


def check_open_security_groups(session):
    """CIS 5.2 / 5.3 — Security groups should not allow unrestricted ingress
    on sensitive ports from 0.0.0.0/0 or ::/0.
    """
    ec2 = session.client("ec2")
    findings = []

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", sg_id)

            open_ports = _find_open_sensitive_ports(sg.get("IpPermissions", []))

            findings.append({
                "rule_id": "EC2-001",
                "cis_control": "5.2",
                "title": f"Security group '{sg_name}' allows unrestricted "
                         f"access on sensitive ports",
                "severity": "Critical" if open_ports else "Low",
                "resource": f"{sg_name} ({sg_id})",
                "status": "FAIL" if open_ports else "PASS",
                "description": "Security groups should not allow inbound "
                                f"traffic from 0.0.0.0/0 on sensitive ports. "
                                f"Open ports found: {', '.join(open_ports) if open_ports else 'none'}.",
                "remediation": f"Restrict inbound rules on '{sg_name}' to "
                                "specific trusted IP ranges instead of 0.0.0.0/0.",
            })

    return findings


def _find_open_sensitive_ports(ip_permissions):
    """Return a list of human-readable sensitive ports open to the world."""
    open_ports = []

    for perm in ip_permissions:
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        is_world_open = any(
            r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])
        ) or any(
            r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])
        )

        if not is_world_open or from_port is None or to_port is None:
            continue

        for port, name in SENSITIVE_PORTS.items():
            if from_port <= port <= to_port:
                open_ports.append(f"{name} ({port})")

    return open_ports
