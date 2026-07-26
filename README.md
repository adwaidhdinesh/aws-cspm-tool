# CSPM Tool — AWS Cloud Security Posture Management

A lightweight Cloud Security Posture Management (CSPM) tool that scans an AWS
account for misconfigurations mapped to CIS AWS Foundations Benchmark
controls, scores the account's overall security posture, and displays
findings in an interactive Streamlit dashboard.

## Features

- Scans IAM, S3, EC2 Security Groups, CloudTrail, RDS, KMS, VPC, and
  Lambda for common misconfigurations (14 checks total)
- Each check is mapped to a CIS AWS Benchmark control ID
- Findings are scored by severity (Critical / High / Medium / Low)
- Overall posture score (0-100) per scan
- Every finding is also mapped to equivalent controls in NIST 800-53,
  PCI DSS v4.0, and ISO/IEC 27001:2022, with a per-framework compliance
  view and exportable reports
- Drift detection compares each scan to the previous one for the same
  account and flags newly-failing checks, resolved checks, and new or
  removed resources
- Scan history stored in SQLite so you can track posture over time
- Interactive dashboard to filter, explore, and export findings

## Project Structure

```
cspm-project/
├── main.py                 # CLI entry point — runs a scan
├── dashboard.py             # Streamlit dashboard
├── requirements.txt
└── src/
    ├── aws_client.py         # boto3 session/client helpers
    ├── scanner.py             # Orchestrates rule checks
    ├── scoring.py             # Posture score calculation
    ├── compliance.py          # CIS -> NIST/PCI/ISO control mapping
    ├── drift.py                # Compares findings between scans
    ├── db.py                  # SQLite storage for scan history
    └── rules/
        ├── iam_rules.py
        ├── s3_rules.py
        ├── ec2_rules.py
        ├── cloudtrail_rules.py
        ├── rds_rules.py
        ├── kms_rules.py
        ├── vpc_rules.py
        └── lambda_rules.py
```

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure AWS credentials (any of the standard boto3 methods work):
   ```bash
   aws configure
   # or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
   ```

   The IAM identity you use needs **read-only** permissions. The
   `SecurityAudit` AWS managed policy covers everything this tool needs.

3. Run a scan from the CLI:
   ```bash
   python main.py
   ```
   This prints a summary, saves findings to `cspm.db`, and writes
   `latest_findings.json`.

4. Launch the dashboard:
   ```bash
   streamlit run dashboard.py
   ```

## Adding New Rules

Each rule lives in `src/rules/<service>_rules.py` and is a function that:

1. Takes a boto3 `session` as input
2. Returns a list of finding dicts with this shape:

```python
{
    "rule_id": "S3-001",
    "cis_control": "2.1.5",
    "title": "S3 bucket allows public read access",
    "severity": "Critical",   # Critical | High | Medium | Low
    "resource": "my-bucket-name",
    "status": "FAIL",          # FAIL | PASS
    "description": "...",
    "remediation": "..."
}
```

Register the function in `src/scanner.py`'s `ALL_RULES` list and it will
automatically be included in every scan and scored.

If your new rule's `cis_control` isn't already in
`src/compliance.py`'s `CIS_TO_FRAMEWORKS` dict, add an entry there too —
otherwise it just won't show up under NIST/PCI/ISO in the Compliance tab
(it will still appear normally under Findings and in the posture score).

## Compliance Framework Mapping

Every finding carries a `cis_control` field (e.g. `1.5`, `2.1.5`). The
`src/compliance.py` module maps each of these to equivalent controls in:

- **NIST 800-53 Rev. 5**
- **PCI DSS v4.0**
- **ISO/IEC 27001:2022**

These mappings are stored per-finding when a scan is saved (`db.py`
adds `nist_controls`, `pci_controls`, `iso_controls` columns), and the
dashboard's **Compliance** tab rolls findings up per framework into a
per-control pass/fail table plus a rough "% of controls clean" score,
with CSV export per framework.

**Important:** these mappings are simplified for illustrative /
educational purposes — they are not an official crosswalk and shouldn't
be used as the sole basis for a real compliance audit. For that, use
your framework's published control mapping documentation or a
certified GRC tool.

## Drift Detection

Each finding is uniquely identified by `(rule_id, resource)`. When you
view a scan in the dashboard's **Drift** tab, `src/drift.py` compares
its findings against the immediately preceding scan for the same
account and classifies every change:

- **NEW_FAIL** — a check that used to pass now fails (regression)
- **RESOLVED** — a check that used to fail now passes
- **NEW_RESOURCE** — a resource that wasn't seen in the previous scan
- **REMOVED_RESOURCE** — a resource from the previous scan no longer exists

This only requires running `python main.py` more than once against the
same account — no extra setup needed. It's useful for catching
accidental or unauthorized configuration changes between scans.

## Suggested Next Steps (for extending the project)

- Add more rule modules: RDS, KMS, Lambda, VPC flow logs
- Add a PDF/HTML compliance report generator (good for a "deliverable" demo)
- Add scheduled scanning (cron / Lambda) for continuous monitoring
- Add Slack/email alerting on new Critical findings
- Support scanning multiple AWS accounts/roles (cross-account IAM role assumption)
