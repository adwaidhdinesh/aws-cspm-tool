def make_finding(
    asset,
    rule_id: str,
    title: str,
    severity: str,
    status: str,
    description: str,
    remediation: str,
    cis_control: str = None
) -> dict:
    """Helper to consistently construct finding dictionaries across all rules."""
    finding = {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "service": asset.service,
        "resource": asset.resource_id,
        "status": status,
        "description": description,
        "remediation": remediation,
    }
    if cis_control:
        finding["cis_control"] = cis_control
        
    return finding
