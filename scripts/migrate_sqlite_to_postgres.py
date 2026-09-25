"""One-time import of historical CSPM data from SQLite into PostgreSQL.

Usage:
    DATABASE_URL=postgresql://cspm:cspm@localhost:5432/cspm \
      python scripts/migrate_sqlite_to_postgres.py --sqlite-path cspm.db
"""

import argparse
import sqlite3
import sys
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src import db  # noqa: E402


TABLES = ("assets", "scans", "findings")


def main() -> None:
    parser = argparse.ArgumentParser(description="Import CSPM SQLite history into PostgreSQL")
    parser.add_argument("--sqlite-path", default="cspm.db", help="Path to the existing SQLite database")
    args = parser.parse_args()

    sqlite_path = Path(args.sqlite_path)
    if not sqlite_path.is_file():
        raise SystemExit(f"SQLite database not found: {sqlite_path}")

    db.init_db()
    source = sqlite3.connect(sqlite_path)
    source.row_factory = sqlite3.Row

    with psycopg.connect(db.get_database_url()) as destination, destination.cursor() as cur:
        for table in TABLES:
            rows = source.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
            if not rows:
                continue
            columns = list(rows[0].keys())
            fields = ", ".join(columns)
            values = ", ".join(["%s"] * len(columns))
            for row in rows:
                cur.execute(
                    f"INSERT INTO {table} ({fields}) VALUES ({values}) ON CONFLICT (id) DO NOTHING",
                    tuple(row[column] for column in columns),
                )
            cur.execute(
                "SELECT setval(pg_get_serial_sequence(%s, 'id'), "
                "COALESCE((SELECT MAX(id) FROM " + table + "), 1), true)",
                (table,),
            )
            print(f"Imported {len(rows)} {table} rows")

    source.close()


if __name__ == "__main__":
    main()
