"""PostgreSQL persistence for assets, scans, and findings.

Set ``DATABASE_URL`` before running the scanner or API, for example::

    postgresql://cspm:cspm@localhost:5432/cspm

Assets are soft-deleted when absent from a later scan so their historical
findings remain available.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row

from src import compliance


def get_database_url(database_url: str | None = None) -> str:
    """Return an explicit or environment-provided PostgreSQL connection URL."""
    url = database_url or os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is required. Set it to a PostgreSQL URL, e.g. "
            "postgresql://cspm:cspm@localhost:5432/cspm"
        )
    if not url.startswith(("postgresql://", "postgres://")):
        raise ValueError("DATABASE_URL must be a PostgreSQL connection URL")
    return url


def _connect(database_url: str | None = None) -> psycopg.Connection:
    return psycopg.connect(get_database_url(database_url), row_factory=dict_row)



def init_db(database_url: str | None = None) -> None:
    """Create the schema and indexes when they do not already exist."""
    with _connect(database_url) as conn, conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id BIGSERIAL PRIMARY KEY,
                account_id TEXT NOT NULL,
                service TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                arn TEXT,
                region TEXT,
                resource_type TEXT,
                name TEXT,
                tags JSONB NOT NULL DEFAULT '{}'::jsonb,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                first_seen TIMESTAMPTZ,
                last_seen TIMESTAMPTZ,
                UNIQUE(account_id, service, resource_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id BIGSERIAL PRIMARY KEY,
                account_id TEXT,
                timestamp TIMESTAMPTZ NOT NULL,
                score INTEGER,
                total_checks INTEGER,
                failed_checks INTEGER,
                passed_checks INTEGER,
                total_assets INTEGER
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id BIGSERIAL PRIMARY KEY,
                scan_id BIGINT REFERENCES scans(id),
                asset_id BIGINT REFERENCES assets(id),
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
                iso_controls TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_account_timestamp ON scans(account_id, timestamp DESC)")


def save_assets(assets: list, account_id: str, database_url: str | None = None) -> dict:
    """Upsert assets and return ``(service, resource_id) -> database id``."""
    now = datetime.now(timezone.utc)
    seen_keys: set[tuple[str, str]] = set()
    asset_id_map: dict[tuple[str, str], int] = {}

    with _connect(database_url) as conn, conn.cursor() as cur:
        for asset in assets:
            key = (asset.service, asset.resource_id)
            seen_keys.add(key)
            cur.execute(
                """INSERT INTO assets
                   (account_id, service, resource_id, arn, region, resource_type, name,
                    tags, metadata, status, first_seen, last_seen)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb,
                           'ACTIVE', %s, %s)
                   ON CONFLICT (account_id, service, resource_id) DO UPDATE SET
                     arn = EXCLUDED.arn, region = EXCLUDED.region,
                     resource_type = EXCLUDED.resource_type, name = EXCLUDED.name,
                     tags = EXCLUDED.tags, metadata = EXCLUDED.metadata,
                     last_seen = EXCLUDED.last_seen, status = 'ACTIVE'
                   RETURNING id""",
                (
                    account_id, asset.service, asset.resource_id, asset.arn, asset.region,
                    asset.resource_type, asset.name, json.dumps(asset.tags or {}),
                    json.dumps(asset.metadata or {}), now, now,
                ),
            )
            asset_id_map[key] = cur.fetchone()["id"]

        cur.execute(
            "SELECT id, service, resource_id FROM assets "
            "WHERE account_id = %s AND status = 'ACTIVE'",
            (account_id,),
        )
        for row in cur.fetchall():
            if (row["service"], row["resource_id"]) not in seen_keys:
                cur.execute("UPDATE assets SET status = 'DELETED' WHERE id = %s", (row["id"],))

    return asset_id_map


def _decode_asset(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    row = dict(row)
    for field in ("tags", "metadata"):
        if isinstance(row.get(field), str):
            row[field] = json.loads(row[field]) if row[field] else {}
        elif row.get(field) is None:
            row[field] = {}
    return row


def get_assets_for_account(account_id: str, database_url: str | None = None) -> list:
    with _connect(database_url) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM assets WHERE account_id = %s ORDER BY service, name", (account_id,))
        return [_decode_asset(row) for row in cur.fetchall()]


def get_asset(asset_id: int, database_url: str | None = None) -> dict | None:
    with _connect(database_url) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM assets WHERE id = %s", (asset_id,))
        return _decode_asset(cur.fetchone())


def get_findings_for_asset(asset_id: int, database_url: str | None = None) -> list:
    with _connect(database_url) as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT findings.*, scans.timestamp AS scan_timestamp
               FROM findings JOIN scans ON findings.scan_id = scans.id
               WHERE findings.asset_id = %s
               ORDER BY scans.timestamp DESC, scans.id DESC""",
            (asset_id,),
        )
        return [dict(row) for row in cur.fetchall()]


def save_scan(
    account_id: str,
    findings: list,
    score_result: dict,
    total_assets: int = 0,
    database_url: str | None = None,
) -> int:
    """Persist one scan and all of its findings, returning the scan id."""
    with _connect(database_url) as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO scans
               (account_id, timestamp, score, total_checks, failed_checks, passed_checks, total_assets)
               VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (
                account_id, datetime.now(timezone.utc), score_result["score"],
                score_result["total_checks"], score_result["failed_checks"],
                score_result["passed_checks"], total_assets,
            ),
        )
        scan_id = cur.fetchone()["id"]
        for finding in findings:
            mapped = compliance.format_mapped_controls(finding.get("cis_control", ""))
            cur.execute(
                """INSERT INTO findings
                   (scan_id, asset_id, rule_id, cis_control, title, severity, service, resource,
                    status, description, remediation, nist_controls, pci_controls, iso_controls)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    scan_id, finding.get("asset_id"), finding.get("rule_id"),
                    finding.get("cis_control"), finding.get("title"), finding.get("severity"),
                    finding.get("service"), finding.get("resource"), finding.get("status"),
                    finding.get("description"), finding.get("remediation"),
                    mapped["NIST 800-53"], mapped["PCI DSS v4.0"], mapped["ISO 27001:2022"],
                ),
            )
    return scan_id


def get_all_scans(database_url: str | None = None) -> list:
    with _connect(database_url) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM scans ORDER BY timestamp DESC")
        return [dict(row) for row in cur.fetchall()]


def get_scan(scan_id: int, database_url: str | None = None) -> dict | None:
    """Return one scan without loading the full account scan history."""
    with _connect(database_url) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_findings_for_scan(scan_id: int, database_url: str | None = None) -> list:
    with _connect(database_url) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM findings WHERE scan_id = %s", (scan_id,))
        return [dict(row) for row in cur.fetchall()]


def get_previous_scan(scan_id: int, database_url: str | None = None) -> dict | None:
    """Return the immediately preceding scan for the same account."""
    with _connect(database_url) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
        current = cur.fetchone()
        if current is None:
            return None
        cur.execute(
            """SELECT * FROM scans
               WHERE account_id = %s AND timestamp < %s
               ORDER BY timestamp DESC LIMIT 1""",
            (current["account_id"], current["timestamp"]),
        )
        previous = cur.fetchone()
        return dict(previous) if previous else None
