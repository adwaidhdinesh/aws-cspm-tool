# CSPM Tool — AWS Cloud Security Posture Management

A CSPM tool that discovers your AWS resources into an asset inventory,
runs security checks against that inventory (mapped to CIS AWS
Foundations Benchmark controls), scores your account's posture, and
displays everything in an interactive Streamlit dashboard.

## Architecture

Asset discovery is a separate step from rule checking — this is the
same "what exists?" vs "what's wrong?" split commercial CSPM tools use:

```
AWS
 │
 ▼
Asset Discovery  (src/inventory/) ── every boto3 call happens here
 │
 ├── Store Assets  (SQLite: assets table)
 │
 ▼
Rule Engine  (src/rules/) ── reads Asset objects, never calls AWS
 │
 ▼
Findings  (linked to the asset that produced them)
 │
 ▼
Scoring + Compliance mapping + Drift detection
 │
 ▼
Dashboard  (Streamlit, reads only from SQLite)
```

Because rules only ever read from an `Asset` object's `.metadata` dict,
they can be tested with plain Python objects — no AWS credentials
needed — and adding a new check never means adding a new boto3 call
somewhere unexpected.

## Features

- Discovers assets across IAM, S3, EC2 (security groups + instances),
  CloudTrail, RDS, KMS, VPC, and Lambda, and keeps a persistent
  inventory (`assets` table) with first-seen/last-seen timestamps
- Deleted resources are soft-deleted (`status = 'DELETED'`), not
  removed — you keep historical visibility into what used to exist
- 15 security checks, each mapped to a CIS AWS Benchmark control ID,
  each linked to the specific asset it evaluated
- Findings are scored by severity (Critical / High / Medium / Low) into
  an overall 0-100 posture score
- Every finding is also mapped to equivalent controls in NIST 800-53,
  PCI DSS v4.0, and ISO/IEC 27001:2022, with a per-framework compliance
  view and exportable reports
- Drift detection compares each scan to the previous one for the same
  account and flags newly-failing checks, resolved checks, and new or
  removed resources/assets
- Dashboard tabs: **Assets** (inventory browser, per-service drill-down,
  asset growth), **Findings**, **Compliance**, **Drift**

## Database Schema

```
Accounts (implicit via account_id)
    │
    ├── Assets        current + historical inventory
    │      │
    │      └── Findings   via asset_id (an asset can have many findings)
    │
    └── Scans          one row per scan run
           │
           └── Findings   via scan_id
```

## Project Structure

```
cspm-project/
├── main.py                  # CLI entry point — runs a scan
├── dashboard.py              # Streamlit dashboard
├── requirements.txt
└── src/
    ├── aws_client.py          # boto3 session/client helpers
    ├── scanner.py              # Orchestrates rule checks over assets
    ├── scoring.py               # Posture score calculation
    ├── compliance.py            # CIS -> NIST/PCI/ISO control mapping
    ├── drift.py                  # Compares findings between scans
    ├── db.py                      # SQLite: assets, scans, findings
    ├── inventory/
    │   ├── inventory.py            # Asset dataclass
    │   └── aws_inventory.py         # All boto3 calls live here — discovers
    │                                  assets for every supported service
    └── rules/                     # Pure functions: Asset list -> findings
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
   This discovers your asset inventory, runs every rule against it,
   prints a summary, saves everything to `cspm.db`, and writes
   `latest_findings.json`.

4. Launch the dashboard:
   ```bash
   streamlit run dashboard.py
   ```

**Note:** the database schema changed in this version (new `assets`
table, new columns on `findings`/`scans`). If you have a `cspm.db` from
before this update, delete it and re-run `python main.py` — SQLite
won't auto-migrate an existing file.

## Adding a New Service

1. Add a `discover_<service>_assets(session, account_id)` function to
   `src/inventory/aws_inventory.py` that returns a `list[Asset]`, with
   whatever config the rules will need in `Asset.metadata`. Register it
   in `ALL_DISCOVERERS`.
2. Add a new `src/rules/<service>_rules.py` with functions that take
   `assets: list[Asset]`, filter by `resource_type`, and return finding
   dicts (see shape below). Register each in `scanner.py`'s `ALL_RULES`.
3. If the check has a real CIS control, add it to `compliance.py`'s
   `CIS_TO_FRAMEWORKS` so it shows up in the Compliance tab. Custom
   checks with no CIS equivalent (like the Lambda public-access check)
   can use a placeholder like `"CUSTOM-1"` and skip this step — they'll
   still be scored, just won't appear under NIST/PCI/ISO.

Finding dict shape (unchanged from before, plus a `service` field):

```python
{
    "rule_id": "S3-001",
    "cis_control": "2.1.5",
    "title": "S3 bucket allows public read access",
    "severity": "Critical",   # Critical | High | Medium | Low
    "service": "S3",
    "resource": "my-bucket-name",   # must equal the Asset's resource_id
    "status": "FAIL",          # FAIL | PASS
    "description": "...",
    "remediation": "..."
}
```

`resource` must exactly match the `resource_id` used when the asset was
discovered — that's how findings get linked back to their asset.

## Compliance Framework Mapping

Every finding carries a `cis_control` field (e.g. `1.5`, `2.1.5`). The
`src/compliance.py` module maps each of these to equivalent controls in:

- **NIST 800-53 Rev. 5**
- **PCI DSS v4.0**
- **ISO/IEC 27001:2022**

These mappings are stored per-finding when a scan is saved, and the
dashboard's **Compliance** tab rolls findings up per framework into a
per-control pass/fail table plus a rough "% of controls clean" score,
with CSV export per framework.

**Important:** these mappings are simplified for illustrative /
educational purposes — they are not an official crosswalk and shouldn't
be used as the sole basis for a real compliance audit. For that, use
your framework's published control mapping documentation or a
certified GRC tool.

## Drift Detection

Findings are matched across scans by `(rule_id, service, resource)`.
The dashboard's **Drift** tab compares the selected scan against the
immediately preceding scan for the same account and classifies every
change:

- **NEW_FAIL** — a check that used to pass now fails (regression)
- **RESOLVED** — a check that used to fail now passes
- **NEW_RESOURCE** — a resource that wasn't seen in the previous scan
- **REMOVED_RESOURCE** — a resource from the previous scan no longer exists

This only requires running `python main.py` more than once against the
same account — no extra setup needed.

## Asset Inventory

The **Assets** dashboard tab shows:

- Total active assets, number of distinct services, number of regions
- Asset growth vs. the previous scan (e.g. "73, +5 since last scan")
- A per-service asset count table
- A drill-down: pick a service, pick an asset, see its full config
  (`metadata`), tags, and every finding ever recorded against it

Deleted resources aren't erased — they stay in the `assets` table with
`status = 'DELETED'`, visible via the "include deleted assets" checkbox,
so you retain a history of what used to exist in the account.

## Suggested Next Steps (for extending the project)

- REST API (FastAPI) in front of the SQLite data, so the scanner,
  database, and dashboard become independently deployable components
- Asset search/filtering by tag (e.g. "everything owned by team X")
- Scheduled scanning (cron / Lambda) for continuous monitoring
- Slack/email alerting on new Critical findings
- Multi-account support (would mean adding an `accounts` table and an
  assumed-role credential flow — a real architecture change, not a
  bolt-on)
