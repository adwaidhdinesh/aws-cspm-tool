"""
EC2-related CSPM checks, mapped to CIS AWS Foundations Benchmark controls
where applicable.

These operate purely on already-discovered Asset objects — no boto3
calls happen here.
"""


def check_open_security_groups(assets):
    """CIS 5.2 / 5.3 — Security groups should not allow unrestricted ingress
    on sensitive ports from 0.0.0.0/0 or ::/0.
    """
    findings = []

    for asset in assets:
        if asset.resource_type != "EC2::SecurityGroup":
            continue

        open_ports = asset.metadata.get("open_sensitive_ports", [])

        findings.append({
            "rule_id": "EC2-001",
            "cis_control": "5.2",
            "title": f"Security group '{asset.name}' allows unrestricted "
                     f"access on sensitive ports",
            "severity": "Critical" if open_ports else "Low",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "FAIL" if open_ports else "PASS",
            "description": "Security groups should not allow inbound "
                            "traffic from 0.0.0.0/0 on sensitive ports. "
                            f"Open ports found: {', '.join(open_ports) if open_ports else 'none'}.",
            "remediation": f"Restrict inbound rules on '{asset.name}' to "
                            "specific trusted IP ranges instead of 0.0.0.0/0.",
        })

    return findings


def check_instance_public_ip(assets):
    """Custom check — flag EC2 instances with a public IP address so they
    show up for review. Not a CIS control on its own (a public IP isn't
    automatically a misconfiguration), so it isn't mapped to a compliance
    framework — it's inventory-driven visibility rather than a hard rule.
    """
    findings = []

    for asset in assets:
        if asset.resource_type != "EC2::Instance":
            continue
        if asset.metadata.get("state") == "terminated":
            continue

        has_public_ip = bool(asset.metadata.get("public_ip"))

        findings.append({
            "rule_id": "EC2-002",
            "cis_control": "CUSTOM-2",
            "title": f"EC2 instance '{asset.name}' has a public IP address",
            "severity": "Medium",
            "service": asset.service,
            "resource": asset.resource_id,
            "status": "FAIL" if has_public_ip else "PASS",
            "description": "Instances with a public IP are directly reachable "
                            "from the internet. Confirm this is intentional "
                            "(e.g. a bastion or load balancer), not accidental exposure.",
            "remediation": f"If '{asset.name}' doesn't need to be internet-facing, "
                            "move it to a private subnet or remove its public IP.",
        })

    return findings
