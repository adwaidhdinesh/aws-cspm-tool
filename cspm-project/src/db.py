"""
SQLite persistence for the asset inventory, scan runs, and findings.

Schema relationships:

    Accounts (implicit via account_id)
        |
        +-- Assets  (current + historical inventory)
        |      |
        |      +-- Findings  (via asset_id)
        |
        +-- Scans   (one row per scan run)
               |
               +-- Findings  (via scan_id)

An asset row is never deleted once seen — if a resource disappears from
a scan, it's marked status='DELETED' instead, so the dashboard retains
historical visibility ("this bucket existed until March 3rd").
"""

import json
import sqlite3
from datetime import datetime, timezone

from src import compliance

DB_PATH = "cspm.db"


def init_db(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id TEXT NOT NULL,
            service TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            arn TEXT,
            region TEXT,
            resource_type TEXT,
            name TEXT,
            tags TEXT,
            metadata TEXT,
            status TEXT DEFAULT 'ACTIVE',
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            UNIQUE(account_id, service, resource_id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id TEXT,
            timestamp TEXT,
            score INTEGER,
            total_checks INTEGER,
            failed_checks INTEGER,
            passed_checks INTEGER,
            total_assets INTEGER
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            asset_id INTEGER,
            rule_id TEXT,
            cis_control TEXT,
            title TEXT,
            severity TEXT,
            service TEXT,
            resource TEXT,
            status TEXT,
            description TEXT,
            remediation TEXT,
            nist_controls TEXT,
            pci_controls TEXT,
            iso_controls TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id),
            FOREIGN KEY (asset_id) REFERENCES assets (id)
        )
    """)

    conn.commit()
    conn.close()


def save_assets(assets: list, account_id: str, db_path: str = DB_PATH) -> dict:
    """Upsert discovered assets into the assets table.

    - New (service, resource_id) pairs are inserted with first_seen = now.
    - Previously-seen assets get last_seen and metadata refreshed, and are
      marked status='ACTIVE' (in case they were previously DELETED and
      have since reappeared).
    - Any asset that was ACTIVE for this account but wasn't in this scan's
      results is marked status='DELETED' — never removed from the table.

    Returns {(service, resource_id): asset_db_id} for the assets just
    discovered, so callers can link findings to their asset row.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    seen_keys = set()
    asset_id_map = {}

    for asset in assets:
        key = (asset.service, asset.resource_id)
        seen_keys.add(key)

        existing = cur.execute(
            "SELECT id FROM assets WHERE account_id = ? AND service = ? AND resource_id = ?",
            (account_id, asset.service, asset.resource_id),
        ).fetchone()

        tags_json = json.dumps(asset.tags or {})
        metadata_json = json.dumps(asset.metadata or {})

        if existing:
            asset_db_id = existing[0]
            cur.execute(
                """UPDATE assets
                   SET arn = ?, region = ?, resource_type = ?, name = ?,
                       tags = ?, metadata = ?, last_seen = ?, status = 'ACTIVE'
                   WHERE id = ?""",
                (asset.arn, asset.region, asset.resource_type, asset.name,
                 tags_json, metadata_json, now, asset_db_id),
            )
        else:
            cur.execute(
                """INSERT INTO assets
                   (account_id, service, resource_id, arn, region, resource_type,
                    name, tags, metadata, status, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)""",
                (account_id, asset.service, asset.resource_id, asset.arn,
                 asset.region, asset.resource_type, asset.name,
                 tags_json, metadata_json, now, now),
            )
            asset_db_id = cur.lastrowid

        asset_id_map[key] = asset_db_id

    # Mark anything previously ACTIVE for this account that wasn't seen
    # in this scan as DELETED (soft delete — row stays for history).
    previously_active = cur.execute(
        "SELECT id, service, resource_id FROM assets WHERE account_id = ? AND status = 'ACTIVE'",
        (account_id,),
    ).fetchall()

    for row_id, service, resource_id in previously_active:
        if (service, resource_id) not in seen_keys:
            cur.execute("UPDATE assets SET status = 'DELETED' WHERE id = ?", (row_id,))

    conn.commit()
    conn.close()
    return asset_id_map


def get_assets_for_account(account_id: str, db_path: str = DB_PATH) -> list:
    """Return every asset ever seen for this account (including DELETED),
    with tags/metadata parsed back into dicts."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM assets WHERE account_id = ? ORDER BY service, name",
        (account_id,),
    ).fetchall()
    conn.close()

    assets = []
    for row in rows:
        asset = dict(row)
        asset["tags"] = json.loads(asset["tags"]) if asset["tags"] else {}
        asset["metadata"] = json.loads(asset["metadata"]) if asset["metadata"] else {}
        assets.append(asset)
    return assets


def get_asset(asset_id: int, db_path: str = DB_PATH):
    """Return a single asset by id, with tags/metadata parsed, or None."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    conn.close()

    if row is None:
        return None

    asset = dict(row)
    asset["tags"] = json.loads(asset["tags"]) if asset["tags"] else {}
    asset["metadata"] = json.loads(asset["metadata"]) if asset["metadata"] else {}
    return asset


def get_findings_for_asset(asset_id: int, db_path: str = DB_PATH) -> list:
    """Return every finding ever recorded against a given asset, most
    recent scan first — this is the "Asset -> Finding 1, Finding 2..." link."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """SELECT findings.*, scans.timestamp AS scan_timestamp
           FROM findings
           JOIN scans ON findings.scan_id = scans.id
           WHERE findings.asset_id = ?
           ORDER BY scans.timestamp DESC, scans.id DESC""",
        (asset_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_scan(account_id: str, findings: list, score_result: dict,
              total_assets: int = 0, db_path: str = DB_PATH) -> int:
    """Persist a scan run and its findings. Returns the new scan id.

    Each finding dict may carry an 'asset_id' (set by the caller after
    save_assets()) linking it back to the assets table; findings without
    a matching asset (e.g. account-level checks) get asset_id = NULL.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute(
        """INSERT INTO scans
           (account_id, timestamp, score, total_checks, failed_checks,
            passed_checks, total_assets)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            account_id,
            datetime.now(timezone.utc).isoformat(),
            score_result["score"],
            score_result["total_checks"],
            score_result["failed_checks"],
            score_result["passed_checks"],
            total_assets,
        ),
    )
    scan_id = cur.lastrowid

    for f in findings:
        mapped = compliance.format_mapped_controls(f.get("cis_control", ""))
        cur.execute(
            """INSERT INTO findings
               (scan_id, asset_id, rule_id, cis_control, title, severity,
                service, resource, status, description, remediation,
                nist_controls, pci_controls, iso_controls)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                f.get("asset_id"),
                f.get("rule_id"),
                f.get("cis_control"),
                f.get("title"),
                f.get("severity"),
                f.get("service"),
                f.get("resource"),
                f.get("status"),
                f.get("description"),
                f.get("remediation"),
                mapped["NIST 800-53"],
                mapped["PCI DSS v4.0"],
                mapped["ISO 27001:2022"],
            ),
        )

    conn.commit()
    conn.close()
    return scan_id


def get_all_scans(db_path: str = DB_PATH) -> list:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM scans ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_findings_for_scan(scan_id: int, db_path: str = DB_PATH) -> list:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_previous_scan(scan_id: int, db_path: str = DB_PATH):
    """Return the scan immediately before the given scan for the same
    account (by timestamp), or None if this is that account's earliest scan.
    Used for drift detection and asset growth comparisons.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    current = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if current is None:
        conn.close()
        return None

    previous = conn.execute(
        """SELECT * FROM scans
           WHERE account_id = ? AND timestamp < ?
           ORDER BY timestamp DESC LIMIT 1""",
        (current["account_id"], current["timestamp"]),
    ).fetchone()

    conn.close()
    return dict(previous) if previous else None
