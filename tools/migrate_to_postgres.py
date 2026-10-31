"""Copy every existing SQLite record into PostgreSQL — idempotently.

Usage:
    python migrate_to_postgres.py [postgresql://user:pass@host/db]

The source defaults to instance/share.db (override with MAKROTIK_SQLITE_PATH).
Nothing is deleted from the SQLite file, so it remains a rollback copy.
File bytes are not copied; keep uploads/ available to the target app.
"""

import os
import sqlite3
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)
from db import Database

SQLITE_PATH = os.environ.get(
    "MAKROTIK_SQLITE_PATH", os.path.join(BASE_DIR, "instance", "share.db")
)
URL = (
    (sys.argv[1] if len(sys.argv) > 1 else "")
    or os.environ.get("MAKROTIK_DATABASE_URL")
    or os.environ.get("DATABASE_URL")
    or ""
)

USER_COLUMNS = "id, username, email, password_hash, created_at"
FILE_COLUMNS = (
    "token, owner_id, original_name, stored_name, size, mimetype, downloads, "
    "delete_key, created_at, expires_at, sha256, deleted_at, delete_reason"
)
AUDIT_COLUMNS = "id, created_at, actor, action, token, detail"


def placeholders(count):
    return ", ".join(["?"] * count)


def main():
    if not URL.lower().startswith(("postgres://", "postgresql://")):
        raise SystemExit("Pass a PostgreSQL URL or set MAKROTIK_DATABASE_URL.")
    if not os.path.exists(SQLITE_PATH):
        raise SystemExit(f"SQLite source not found: {SQLITE_PATH}")

    source = sqlite3.connect(SQLITE_PATH)
    source.row_factory = sqlite3.Row
    try:
        # Upgrade the source schema in place (additive only) so every column
        # exists even if this is an older database.
        source_db = Database("", SQLITE_PATH)
        source_conn = source_db.connect()
        source_db.ensure_schema(source_conn)
        source_conn.close()
    finally:
        source.close()

    source = sqlite3.connect(SQLITE_PATH)
    source.row_factory = sqlite3.Row
    target = Database(URL, SQLITE_PATH)
    if not target.is_postgres:
        raise SystemExit(
            f"PostgreSQL connection failed: {target.fallback_reason}"
        )
    dest = target.connect()
    target.ensure_schema(dest)

    copied = {"users": 0, "files": 0, "audit_log": 0, "settings": 0}

    for row in source.execute(f"SELECT {USER_COLUMNS} FROM users"):
        cur = dest.execute(
            f"INSERT INTO users ({USER_COLUMNS}) "
            f"VALUES ({placeholders(5)}) ON CONFLICT (id) DO NOTHING",
            tuple(row),
        )
        copied["users"] += max(cur.rowcount, 0)

    for row in source.execute(f"SELECT {FILE_COLUMNS} FROM files"):
        cur = dest.execute(
            f"INSERT INTO files ({FILE_COLUMNS}) "
            f"VALUES ({placeholders(13)}) ON CONFLICT (token) DO NOTHING",
            tuple(row),
        )
        copied["files"] += max(cur.rowcount, 0)

    for row in source.execute(f"SELECT {AUDIT_COLUMNS} FROM audit_log"):
        cur = dest.execute(
            f"INSERT INTO audit_log ({AUDIT_COLUMNS}) "
            f"VALUES ({placeholders(6)}) ON CONFLICT (id) DO NOTHING",
            tuple(row),
        )
        copied["audit_log"] += max(cur.rowcount, 0)

    for row in source.execute("SELECT key, value, updated_at FROM settings"):
        cur = dest.execute(
            "INSERT INTO settings (key, value, updated_at) "
            "VALUES (?, ?, ?) ON CONFLICT (key) DO NOTHING",
            tuple(row),
        )
        copied["settings"] += max(cur.rowcount, 0)

    # Advance sequences past every explicitly copied id.
    dest.execute(
        "SELECT setval(pg_get_serial_sequence('users', 'id'), "
        "COALESCE((SELECT MAX(id) FROM users), 1), "
        "(SELECT COUNT(*) FROM users) > 0)"
    )
    dest.execute(
        "SELECT setval(pg_get_serial_sequence('audit_log', 'id'), "
        "COALESCE((SELECT MAX(id) FROM audit_log), 1), "
        "(SELECT COUNT(*) FROM audit_log) > 0)"
    )
    dest.commit()

    print("Migration complete.")
    for table, count in copied.items():
        print(f"  {table}: {count} new row(s)")
    for table in ("users", "files", "audit_log"):
        n = dest.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
        print(f"  PostgreSQL {table}: {n} total row(s)")
    print(f"Source kept untouched at {SQLITE_PATH}")
    dest.close()
    source.close()


if __name__ == "__main__":
    main()