"""
Maps the CIS AWS Foundations Benchmark control IDs used by this tool's
rules to equivalent controls in other common compliance frameworks:
NIST 800-53 Rev. 5, PCI DSS v4.0, and ISO/IEC 27001:2022.

IMPORTANT: These mappings are simplified for illustrative / educational
use. They are NOT an official crosswalk. For real compliance audits, use
your framework's published control mapping documentation or a certified
GRC tool.
"""

FRAMEWORKS = ["NIST 800-53", "PCI DSS v4.0", "ISO 27001:2022"]

# Keyed by the cis_control value already present on each finding.
CIS_TO_FRAMEWORKS = {
    "1.5": {  # Root account MFA
        "NIST 800-53": ["IA-2(1)", "AC-6(5)"],
        "PCI DSS v4.0": ["8.4.2"],
        "ISO 27001:2022": ["A.9.4.2"],
    },
    "1.10": {  # IAM user MFA
        "NIST 800-53": ["IA-2(1)"],
        "PCI DSS v4.0": ["8.4.2"],
        "ISO 27001:2022": ["A.9.4.2"],
    },
    "1.16": {  # Wildcard admin IAM policy
        "NIST 800-53": ["AC-6", "AC-6(1)"],
        "PCI DSS v4.0": ["7.2.1"],
        "ISO 27001:2022": ["A.9.2.3"],
    },
    "2.1.5": {  # Public S3 bucket
        "NIST 800-53": ["AC-3", "SC-7"],
        "PCI DSS v4.0": ["1.3.1"],
        "ISO 27001:2022": ["A.13.1.3"],
    },
    "2.1.1": {  # S3 default encryption
        "NIST 800-53": ["SC-28"],
        "PCI DSS v4.0": ["3.5.1"],
        "ISO 27001:2022": ["A.10.1.1"],
    },
    "5.2": {  # Security groups open to the world
        "NIST 800-53": ["SC-7", "AC-4"],
        "PCI DSS v4.0": ["1.2.1"],
        "ISO 27001:2022": ["A.13.1.1"],
    },
    "3.1": {  # CloudTrail enabled, multi-region
        "NIST 800-53": ["AU-2", "AU-12"],
        "PCI DSS v4.0": ["10.2.1"],
        "ISO 27001:2022": ["A.12.4.1"],
    },
    "3.2": {  # CloudTrail log file validation
        "NIST 800-53": ["AU-9"],
        "PCI DSS v4.0": ["10.5.2"],
        "ISO 27001:2022": ["A.12.4.2"],
    },
    "2.3.2": {  # RDS publicly accessible
        "NIST 800-53": ["AC-3", "SC-7"],
        "PCI DSS v4.0": ["1.3.1"],
        "ISO 27001:2022": ["A.13.1.3"],
    },
    "2.3.1": {  # RDS storage encryption
        "NIST 800-53": ["SC-28"],
        "PCI DSS v4.0": ["3.5.1"],
        "ISO 27001:2022": ["A.10.1.1"],
    },
    "2.8": {  # KMS key rotation
        "NIST 800-53": ["SC-12", "SC-13"],
        "PCI DSS v4.0": ["3.6.1"],
        "ISO 27001:2022": ["A.10.1.2"],
    },
    "5.3": {  # Default security group restricts traffic
        "NIST 800-53": ["SC-7", "CM-7"],
        "PCI DSS v4.0": ["1.2.1"],
        "ISO 27001:2022": ["A.13.1.1"],
    },
    "3.9": {  # VPC flow logs enabled
        "NIST 800-53": ["AU-2", "SI-4"],
        "PCI DSS v4.0": ["10.2.1"],
        "ISO 27001:2022": ["A.12.4.1"],
    },
}


def get_mapped_controls(cis_control: str) -> dict:
    """Return {framework_name: [control_ids]} for a given CIS control id.

    Frameworks with no known mapping for this control get an empty list
    rather than being omitted, so callers can rely on all FRAMEWORKS keys
    always being present.
    """
    mapping = CIS_TO_FRAMEWORKS.get(cis_control, {})
    return {fw: mapping.get(fw, []) for fw in FRAMEWORKS}


def format_mapped_controls(cis_control: str) -> dict:
    """Same as get_mapped_controls but values are comma-joined strings —
    convenient for storing in a single DB column or displaying in a table.
    """
    mapped = get_mapped_controls(cis_control)
    return {
        fw: ", ".join(controls) if controls else "—"
        for fw, controls in mapped.items()
    }


def compliance_summary(findings: list) -> dict:
    """Roll findings up into per-framework, per-control pass/fail counts.

    Returns:
        {
          "NIST 800-53": {
              "IA-2(1)": {"pass": 2, "fail": 1},
              ...
          },
          "PCI DSS v4.0": {...},
          "ISO 27001:2022": {...},
        }
    """
    summary = {fw: {} for fw in FRAMEWORKS}

    for finding in findings:
        cis_control = finding.get("cis_control", "")
        status = finding.get("status", "PASS")
        mapped = get_mapped_controls(cis_control)

        for fw, controls in mapped.items():
            for control_id in controls:
                bucket = summary[fw].setdefault(control_id, {"pass": 0, "fail": 0})
                if status == "FAIL":
                    bucket["fail"] += 1
                else:
                    bucket["pass"] += 1

    return summary


def framework_score(framework_controls: dict) -> int:
    """Given one framework's control bucket (a value from compliance_summary),
    compute the percent of mapped controls with zero failing findings.

    Returns an integer 0-100. A framework with no mapped findings yet
    returns 100 (nothing observed as failing).
    """
    if not framework_controls:
        return 100
    compliant = sum(1 for c in framework_controls.values() if c["fail"] == 0)
    return round(100 * compliant / len(framework_controls))
