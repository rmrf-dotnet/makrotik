"""Durable database layer for Makrotik Share.

PostgreSQL is the preferred backend; SQLite is kept as a safe local fallback so
the service never refuses to boot just because Postgres is unreachable.

Design rules
------------
* Every write is committed explicitly. A failed commit is rolled back.
* Records are never hard-deleted by the application: files are soft-deleted
  (archived) and can be restored. Only an explicit admin purge removes a row.
* Every meaningful action is appended to ``audit_log``.
* Schema changes are additive and idempotent — existing databases are upgraded
  in place, never recreated.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import datetime

try:  # psycopg is optional so the app still runs on a machine without it.
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - exercised on SQLite-only installs
    psycopg = None
    dict_row = None

SCHEMA_VERSION = 3


def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds")


def is_postgres_url(url):
    return (url or "").lower().startswith(("postgres://", "postgresql://"))


class Connection:
    """Thin adapter that gives SQLite and PostgreSQL the same tiny API."""

    def __init__(self, raw, engine):
        self.raw = raw
        self.engine = engine

    def execute(self, sql, params=()):
        if self.engine == "postgres":
            sql = sql.replace("?", "%s")
        return self.raw.execute(sql, params)

    def insert(self, sql, params=()):
        """INSERT and return the new integer primary key."""
        if self.engine == "postgres":
            sql = sql.replace("?", "%s")
            cur = self.raw.execute(sql.rstrip().rstrip(";") + " RETURNING id", params)
            row = cur.fetchone()
            return row["id"] if row else None
        cur = self.raw.execute(sql, params)
        return cur.lastrowid

    def commit(self):
        self.raw.commit()

    def rollback(self):
        try:
            self.raw.rollback()
        except Exception:
            pass

    def close(self):
        try:
            self.raw.close()
        except Exception:
            pass


class Database:
    def __init__(self, url, sqlite_path, logger=None):
        self.url = (url or "").strip()
        self.sqlite_path = sqlite_path
        self.logger = logger
        self.requested_engine = "postgres" if is_postgres_url(self.url) else "sqlite"
        self.engine = self.requested_engine
        self.fallback_reason = None

        if self.engine == "postgres":
            if psycopg is None:
                self.fallback_reason = (
                    "psycopg is not installed. Install it with "
                    "'pip install \"psycopg[binary]>=3.1\"'."
                )
                self._fallback()
            else:
                try:
                    conn = self.connect()
                    conn.close()
                except Exception as exc:  # noqa: BLE001 - report any connect failure
                    self.fallback_reason = str(exc)
                    self._fallback()

        if self.engine == "sqlite":
            os.makedirs(os.path.dirname(self.sqlite_path) or ".", exist_ok=True)

    def _fallback(self):
        self.engine = "sqlite"
        if self.logger:
            self.logger.warning(
                "PostgreSQL unavailable, using durable SQLite fallback: %s",
                self.fallback_reason,
            )

    @property
    def is_postgres(self):
        return self.engine == "postgres"

    def connect(self):
        if self.engine == "postgres":
            raw = psycopg.connect(
                self.url,
                connect_timeout=5,
                application_name="makrotik-share",
                row_factory=dict_row,
            )
            raw.execute("SET synchronous_commit TO on")
            raw.execute("SET statement_timeout TO '120s'")
            return Connection(raw, "postgres")

        raw = sqlite3.connect(self.sqlite_path, timeout=20)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("PRAGMA synchronous=FULL")
        raw.execute("PRAGMA foreign_keys=ON")
        raw.execute("PRAGMA busy_timeout=20000")
        return Connection(raw, "sqlite")

    def maintenance(self):
        """VACUUM/ANALYZE must run outside an explicit transaction."""
        if self.is_postgres:
            raw = psycopg.connect(
                self.url, autocommit=True, connect_timeout=5
            )
            try:
                raw.execute("VACUUM (ANALYZE)")
            finally:
                raw.close()
            return
        raw = sqlite3.connect(self.sqlite_path, timeout=20)
        raw.isolation_level = None
        try:
            raw.execute("VACUUM")
            raw.execute("ANALYZE")
        finally:
            raw.close()

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #
    def ensure_schema(self, conn):
        if self.is_postgres:
            self._ensure_postgres(conn)
        else:
            self._ensure_sqlite(conn)
        conn.commit()

    def _ensure_postgres(self, conn):
        statements = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id            BIGSERIAL PRIMARY KEY,
                username      TEXT NOT NULL,
                email         TEXT,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            )
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username
                ON users (LOWER(username))
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
                ON users (LOWER(email))
                WHERE email IS NOT NULL AND email <> ''
            """,
            """
            CREATE TABLE IF NOT EXISTS files (
                token         TEXT PRIMARY KEY,
                owner_id      BIGINT REFERENCES users(id) ON DELETE SET NULL,
                original_name TEXT NOT NULL,
                stored_name   TEXT NOT NULL,
                size          BIGINT NOT NULL,
                mimetype      TEXT,
                downloads     BIGINT NOT NULL DEFAULT 0,
                delete_key    TEXT NOT NULL,
                created_at    TEXT NOT NULL,
                expires_at    TEXT,
                sha256        TEXT,
                deleted_at    TEXT,
                delete_reason TEXT
            )
            """,
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS owner_id BIGINT",
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS sha256 TEXT",
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS deleted_at TEXT",
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS delete_reason TEXT",
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS tags TEXT",
            "CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id)",
            """
            CREATE INDEX IF NOT EXISTS idx_files_active
                ON files(deleted_at, expires_at)
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id         BIGSERIAL PRIMARY KEY,
                created_at TEXT NOT NULL,
                actor      TEXT NOT NULL,
                action     TEXT NOT NULL,
                token      TEXT,
                detail     TEXT,
                severity   TEXT NOT NULL DEFAULT 'info',
                category   TEXT NOT NULL DEFAULT 'system',
                prev_hash  TEXT,
                entry_hash TEXT
            )
            """,
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'info'",
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'system'",
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT",
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash TEXT",
            "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)",
            "CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity)",
            "CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category)",
            """
            CREATE TABLE IF NOT EXISTS settings (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_chain (
                id         INTEGER PRIMARY KEY,
                last_hash  TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS admin_accounts (
                id              BIGSERIAL PRIMARY KEY,
                username        TEXT NOT NULL,
                password_hash   TEXT NOT NULL,
                role            TEXT NOT NULL DEFAULT 'read_only',
                active          INTEGER NOT NULL DEFAULT 1,
                totp_secret     TEXT,
                totp_enabled    INTEGER NOT NULL DEFAULT 0,
                recovery_codes  TEXT,
                created_at      TEXT NOT NULL,
                last_login_at   TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    TEXT
            )
            """,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_accounts_username ON admin_accounts(LOWER(username))",
            """
            CREATE TABLE IF NOT EXISTS admin_sessions (
                id         TEXT PRIMARY KEY,
                account_id BIGINT REFERENCES admin_accounts(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                last_seen  TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip         TEXT,
                user_agent TEXT,
                revoked_at TEXT
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_admin_sessions_account ON admin_sessions(account_id)",
            "CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry ON admin_sessions(expires_at)",
            """
            CREATE TABLE IF NOT EXISTS backup_targets (
                id         BIGSERIAL PRIMARY KEY,
                name       TEXT NOT NULL,
                kind       TEXT NOT NULL DEFAULT 'local',
                config     TEXT NOT NULL DEFAULT '{}',
                enabled    INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS backup_schedules (
                id               BIGSERIAL PRIMARY KEY,
                name             TEXT NOT NULL,
                target_id        BIGINT REFERENCES backup_targets(id) ON DELETE SET NULL,
                interval_minutes INTEGER NOT NULL DEFAULT 1440,
                retention_days   INTEGER NOT NULL DEFAULT 30,
                enabled          INTEGER NOT NULL DEFAULT 1,
                last_run_at      TEXT,
                next_run_at      TEXT,
                created_at       TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS backup_runs (
                id          BIGSERIAL PRIMARY KEY,
                backup_name TEXT,
                target_id   BIGINT,
                status      TEXT NOT NULL,
                detail      TEXT,
                started_at  TEXT NOT NULL,
                finished_at TEXT
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_backup_runs_started ON backup_runs(started_at)",
            """
            CREATE TABLE IF NOT EXISTS lifecycle_rules (
                id              BIGSERIAL PRIMARY KEY,
                name            TEXT NOT NULL,
                condition_type  TEXT NOT NULL,
                condition_value TEXT NOT NULL,
                action          TEXT NOT NULL DEFAULT 'archive',
                enabled         INTEGER NOT NULL DEFAULT 1,
                last_run_at     TEXT,
                created_at      TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS traffic_events (
                id         BIGSERIAL PRIMARY KEY,
                created_at TEXT NOT NULL,
                direction  TEXT NOT NULL,
                token      TEXT,
                bytes      BIGINT NOT NULL DEFAULT 0,
                actor      TEXT,
                owner_id   BIGINT
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_traffic_created ON traffic_events(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_direction ON traffic_events(direction)",
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version    INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """,
        ]
        for sql in statements:
            conn.execute(sql)
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?) "
            "ON CONFLICT (version) DO NOTHING",
            (SCHEMA_VERSION, now_iso()),
        )

    def _ensure_sqlite(self, conn):
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL,
                email         TEXT,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            )
            """
        )
        for index_sql in (
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username "
            "ON users(username COLLATE NOCASE)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email "
            "ON users(email COLLATE NOCASE) "
            "WHERE email IS NOT NULL AND email <> ''",
        ):
            try:
                conn.execute(index_sql)
            except sqlite3.IntegrityError:
                # Pre-existing duplicates: fall back to app-level uniqueness.
                pass
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                token         TEXT PRIMARY KEY,
                owner_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
                original_name TEXT NOT NULL,
                stored_name   TEXT NOT NULL,
                size          INTEGER NOT NULL,
                mimetype      TEXT,
                downloads     INTEGER NOT NULL DEFAULT 0,
                delete_key    TEXT NOT NULL,
                created_at    TEXT NOT NULL,
                expires_at    TEXT,
                sha256        TEXT,
                deleted_at    TEXT,
                delete_reason TEXT,
                tags          TEXT
            )
            """
        )
        self._sqlite_add_missing_columns(conn)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_files_active "
            "ON files(deleted_at, expires_at)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                actor      TEXT NOT NULL,
                action     TEXT NOT NULL,
                token      TEXT,
                detail     TEXT,
                severity   TEXT NOT NULL DEFAULT 'info',
                category   TEXT NOT NULL DEFAULT 'system',
                prev_hash  TEXT,
                entry_hash TEXT
            )
            """
        )
        self._sqlite_add_audit_columns(conn)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_chain (
                id         INTEGER PRIMARY KEY,
                last_hash  TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_accounts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT NOT NULL,
                password_hash   TEXT NOT NULL,
                role            TEXT NOT NULL DEFAULT 'read_only',
                active          INTEGER NOT NULL DEFAULT 1,
                totp_secret     TEXT,
                totp_enabled    INTEGER NOT NULL DEFAULT 0,
                recovery_codes  TEXT,
                created_at      TEXT NOT NULL,
                last_login_at   TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    TEXT
            )
            """
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_accounts_username "
            "ON admin_accounts(username COLLATE NOCASE)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_sessions (
                id         TEXT PRIMARY KEY,
                account_id INTEGER REFERENCES admin_accounts(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                last_seen  TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip         TEXT,
                user_agent TEXT,
                revoked_at TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_admin_sessions_account "
            "ON admin_sessions(account_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry "
            "ON admin_sessions(expires_at)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_targets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                kind       TEXT NOT NULL DEFAULT 'local',
                config     TEXT NOT NULL DEFAULT '{}',
                enabled    INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_schedules (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                name             TEXT NOT NULL,
                target_id        INTEGER REFERENCES backup_targets(id) ON DELETE SET NULL,
                interval_minutes INTEGER NOT NULL DEFAULT 1440,
                retention_days   INTEGER NOT NULL DEFAULT 30,
                enabled          INTEGER NOT NULL DEFAULT 1,
                last_run_at      TEXT,
                next_run_at      TEXT,
                created_at       TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                backup_name TEXT,
                target_id   INTEGER,
                status      TEXT NOT NULL,
                detail      TEXT,
                started_at  TEXT NOT NULL,
                finished_at TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_backup_runs_started "
            "ON backup_runs(started_at)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lifecycle_rules (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL,
                condition_type  TEXT NOT NULL,
                condition_value TEXT NOT NULL,
                action          TEXT NOT NULL DEFAULT 'archive',
                enabled         INTEGER NOT NULL DEFAULT 1,
                last_run_at     TEXT,
                created_at      TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                direction  TEXT NOT NULL,
                token      TEXT,
                bytes      INTEGER NOT NULL DEFAULT 0,
                actor      TEXT,
                owner_id   INTEGER
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_traffic_created "
            "ON traffic_events(created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_traffic_direction "
            "ON traffic_events(direction)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version    INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, applied_at) "
            "VALUES (?, ?)",
            (SCHEMA_VERSION, now_iso()),
        )

    def _sqlite_add_missing_columns(self, conn):
        file_cols = {row[1] for row in conn.execute("PRAGMA table_info(files)")}
        for column, ddl in (
            ("owner_id", "ALTER TABLE files ADD COLUMN owner_id INTEGER"),
            ("sha256", "ALTER TABLE files ADD COLUMN sha256 TEXT"),
            ("deleted_at", "ALTER TABLE files ADD COLUMN deleted_at TEXT"),
            ("delete_reason", "ALTER TABLE files ADD COLUMN delete_reason TEXT"),
            ("tags", "ALTER TABLE files ADD COLUMN tags TEXT"),
        ):
            if column not in file_cols:
                conn.execute(ddl)
        user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        if "email" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")

    def _sqlite_add_audit_columns(self, conn):
        columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)")}
        for column, ddl in (
            ("severity", "ALTER TABLE audit_log ADD COLUMN severity TEXT NOT NULL DEFAULT 'info'"),
            ("category", "ALTER TABLE audit_log ADD COLUMN category TEXT NOT NULL DEFAULT 'system'"),
            ("prev_hash", "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT"),
            ("entry_hash", "ALTER TABLE audit_log ADD COLUMN entry_hash TEXT"),
        ):
            if column not in columns:
                conn.execute(ddl)


# --------------------------------------------------------------------------- #
# Small helpers shared by the app and the admin dashboard
# --------------------------------------------------------------------------- #
def get_setting(conn, key, default=None):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn, key, value):
    if conn.engine == "postgres":
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, "
            "updated_at = EXCLUDED.updated_at",
            (key, str(value), now_iso()),
        )
    else:
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value, "
            "updated_at = excluded.updated_at",
            (key, str(value), now_iso()),
        )


def _audit_hash(created_at, actor, action, token, detail, severity, category, prev_hash):
    payload = "\x1f".join(
        [
            created_at or "",
            actor or "",
            action or "",
            token or "",
            detail or "",
            severity or "",
            category or "",
            prev_hash or "",
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(conn, actor, action, token=None, detail="", severity=None, category=None):
    """Append an audit event and extend the tamper-evident hash chain."""
    from audit_service import category_for, severity_for

    created_at = now_iso()
    severity = severity or severity_for(action)
    category = category or category_for(action)
    state = conn.execute(
        "SELECT last_hash FROM audit_chain WHERE id = 1"
    ).fetchone()
    prev_hash = state["last_hash"] if state else "GENESIS"
    if not state:
        last = conn.execute(
            "SELECT entry_hash FROM audit_log "
            "WHERE entry_hash IS NOT NULL AND entry_hash <> '' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if last:
            prev_hash = last["entry_hash"]
    entry_hash = _audit_hash(
        created_at,
        actor or "system",
        action,
        token,
        detail or "",
        severity,
        category,
        prev_hash,
    )
    conn.execute(
        "INSERT INTO audit_log "
        "(created_at, actor, action, token, detail, severity, category, "
        "prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            created_at,
            actor or "system",
            action,
            token,
            detail or "",
            severity,
            category,
            prev_hash,
            entry_hash,
        ),
    )
    conn.execute(
        "INSERT INTO audit_chain (id, last_hash, updated_at) VALUES (1, ?, ?) "
        "ON CONFLICT (id) DO UPDATE SET last_hash = excluded.last_hash, "
        "updated_at = excluded.updated_at",
        (entry_hash, created_at),
    )
    return entry_hash
