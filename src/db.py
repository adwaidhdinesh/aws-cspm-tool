"""
SQLite persistence for scan runs and findings, so the dashboard can show
posture trends over time.
"""

import sqlite3
from datetime import datetime, timezone

from src import compliance

DB_PATH = "cspm.db"


def init_db(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id TEXT,
            timestamp TEXT,
            score INTEGER,
            total_checks INTEGER,
            failed_checks INTEGER,
            passed_checks INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            rule_id TEXT,
            cis_control TEXT,
            title TEXT,
            severity TEXT,
            resource TEXT,
            status TEXT,
            description TEXT,
            remediation TEXT,
            nist_controls TEXT,
            pci_controls TEXT,
            iso_controls TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    """)
    conn.commit()
    conn.close()


def save_scan(account_id: str, findings: list, score_result: dict, db_path: str = DB_PATH) -> int:
    """Persist a scan run and its findings. Returns the new scan id."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute(
        """INSERT INTO scans
           (account_id, timestamp, score, total_checks, failed_checks, passed_checks)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            account_id,
            datetime.now(timezone.utc).isoformat(),
            score_result["score"],
            score_result["total_checks"],
            score_result["failed_checks"],
            score_result["passed_checks"],
        ),
    )
    scan_id = cur.lastrowid

    for f in findings:
        mapped = compliance.format_mapped_controls(f.get("cis_control", ""))
        cur.execute(
            """INSERT INTO findings
               (scan_id, rule_id, cis_control, title, severity, resource,
                status, description, remediation,
                nist_controls, pci_controls, iso_controls)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                f.get("rule_id"),
                f.get("cis_control"),
                f.get("title"),
                f.get("severity"),
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
    Used for drift detection.
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
