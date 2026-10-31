"""Admin accounts, roles, server-side sessions and account security."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

from werkzeug.security import check_password_hash, generate_password_hash

from db import now_iso

ROLES = ("super_admin", "auditor", "read_only")

ROLE_LABELS = {
    "super_admin": "Super admin",
    "auditor": "Auditor",
    "read_only": "Read only",
}

PERMISSIONS = (
    "view_dashboard",
    "view_files",
    "manage_files",
    "view_audit",
    "export_audit",
    "manage_audit",
    "view_backups",
    "manage_backups",
    "view_settings",
    "manage_settings",
    "manage_admins",
    "manage_sessions",
    "manage_2fa",
    "view_lifecycle",
    "manage_lifecycle",
    "view_analytics",
    "view_infrastructure",
)

ROLE_PERMISSIONS = {
    "super_admin": set(PERMISSIONS),
    "auditor": {
        "view_dashboard",
        "view_files",
        "view_audit",
        "export_audit",
        "view_backups",
        "view_lifecycle",
        "view_analytics",
        "view_infrastructure",
        "view_settings",
    },
    "read_only": {
        "view_dashboard",
        "view_files",
        "view_audit",
        "view_backups",
        "view_analytics",
        "view_infrastructure",
    },
}


def permissions_for(role):
    return sorted(ROLE_PERMISSIONS.get(role, set()))


def has_permission(account, permission):
    if not account:
        return False
    role = account["role"] if not isinstance(account, dict) else account.get("role")
    return permission in ROLE_PERMISSIONS.get(role, set())


def _dict(row):
    return dict(row) if row is not None else None


def list_accounts(conn):
    rows = conn.execute(
        "SELECT * FROM admin_accounts ORDER BY LOWER(username)"
    ).fetchall()
    return [dict(row) for row in rows]


def get_account(conn, account_id):
    return _dict(
        conn.execute(
            "SELECT * FROM admin_accounts WHERE id = ?", (account_id,)
        ).fetchone()
    )


def get_account_by_username(conn, username):
    return _dict(
        conn.execute(
            "SELECT * FROM admin_accounts WHERE LOWER(username) = LOWER(?)",
            ((username or "").strip(),),
        ).fetchone()
    )


def username_exists(conn, username, exclude_id=None):
    sql = "SELECT 1 FROM admin_accounts WHERE LOWER(username) = LOWER(?)"
    params = [(username or "").strip()]
    if exclude_id is not None:
        sql += " AND id <> ?"
        params.append(exclude_id)
    return conn.execute(sql, params).fetchone() is not None


def create_account(conn, username, password, role, active=True):
    return conn.insert(
        "INSERT INTO admin_accounts "
        "(username, password_hash, role, active, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            (username or "").strip(),
            generate_password_hash(password),
            role,
            1 if active else 0,
            now_iso(),
        ),
    )


def update_account(conn, account_id, role=None, active=None, password=None):
    account = get_account(conn, account_id)
    if not account:
        return False
    if role is not None:
        conn.execute(
            "UPDATE admin_accounts SET role = ? WHERE id = ?", (role, account_id)
        )
    if active is not None:
        conn.execute(
            "UPDATE admin_accounts SET active = ? WHERE id = ?",
            (1 if active else 0, account_id),
        )
    if password:
        conn.execute(
            "UPDATE admin_accounts SET password_hash = ? WHERE id = ?",
            (generate_password_hash(password), account_id),
        )
    return True


def delete_account(conn, account_id):
    conn.execute("DELETE FROM admin_accounts WHERE id = ?", (account_id,))


def super_admin_count(conn):
    return conn.execute(
        "SELECT COUNT(*) AS n FROM admin_accounts "
        "WHERE role = 'super_admin' AND active = 1"
    ).fetchone()["n"]


def ensure_primary_account(conn, username, password_hash):
    account = get_account_by_username(conn, username)
    if account:
        if account["role"] != "super_admin" or not account["active"]:
            conn.execute(
                "UPDATE admin_accounts SET role = 'super_admin', active = 1 "
                "WHERE id = ?",
                (account["id"],),
            )
        return account["id"]
    return conn.insert(
        "INSERT INTO admin_accounts "
        "(username, password_hash, role, active, created_at) "
        "VALUES (?, ?, 'super_admin', 1, ?)",
        (username, password_hash, now_iso()),
    )


def verify_password(account, password):
    if not account or not account.get("password_hash"):
        return False
    return check_password_hash(account["password_hash"], password or "")


def record_failed_login(conn, account, max_failures=5, lock_minutes=15):
    if not account:
        return
    failures = int(account.get("failed_attempts") or 0) + 1
    locked_until = None
    if failures >= max_failures:
        locked_until = (
            datetime.utcnow() + timedelta(minutes=lock_minutes)
        ).isoformat(timespec="seconds")
        failures = 0
    conn.execute(
        "UPDATE admin_accounts SET failed_attempts = ?, locked_until = ? "
        "WHERE id = ?",
        (failures, locked_until, account["id"]),
    )


def account_locked(account):
    locked_until = account.get("locked_until") if account else None
    return bool(locked_until and locked_until > now_iso())


def record_login(conn, account_id):
    conn.execute(
        "UPDATE admin_accounts SET failed_attempts = 0, locked_until = NULL, "
        "last_login_at = ? WHERE id = ?",
        (now_iso(), account_id),
    )


def set_totp_secret(conn, account_id, secret):
    conn.execute(
        "UPDATE admin_accounts SET totp_secret = ?, totp_enabled = 0 "
        "WHERE id = ?",
        (secret, account_id),
    )


def enable_totp(conn, account_id, recovery_codes):
    conn.execute(
        "UPDATE admin_accounts SET totp_enabled = 1, recovery_codes = ? "
        "WHERE id = ?",
        (recovery_codes, account_id),
    )


def disable_totp(conn, account_id):
    conn.execute(
        "UPDATE admin_accounts SET totp_enabled = 0, totp_secret = NULL, "
        "recovery_codes = NULL WHERE id = ?",
        (account_id,),
    )


def set_recovery_codes(conn, account_id, recovery_codes):
    conn.execute(
        "UPDATE admin_accounts SET recovery_codes = ? WHERE id = ?",
        (recovery_codes, account_id),
    )


def create_session(conn, account_id, ip="", user_agent="", hours=12):
    token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    expires = (now + timedelta(hours=hours)).isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO admin_sessions "
        "(id, account_id, created_at, last_seen, expires_at, ip, user_agent) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            token,
            account_id,
            now.isoformat(timespec="seconds"),
            now.isoformat(timespec="seconds"),
            expires,
            (ip or "")[:120],
            (user_agent or "")[:400],
        ),
    )
    return token, expires


def get_session(conn, token):
    if not token:
        return None
    return _dict(
        conn.execute(
            "SELECT s.*, a.username, a.role, a.active, a.totp_enabled "
            "FROM admin_sessions s "
            "JOIN admin_accounts a ON a.id = s.account_id "
            "WHERE s.id = ?",
            (token,),
        ).fetchone()
    )


def active_session(conn, token):
    session_row = get_session(conn, token)
    if not session_row:
        return None
    if session_row["revoked_at"] or not session_row["active"]:
        return None
    if session_row["expires_at"] <= now_iso():
        return None
    conn.execute(
        "UPDATE admin_sessions SET last_seen = ? WHERE id = ?",
        (now_iso(), token),
    )
    return session_row


def revoke_session(conn, token, account_id=None):
    if account_id is None:
        conn.execute(
            "UPDATE admin_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (now_iso(), token),
        )
    else:
        conn.execute(
            "UPDATE admin_sessions SET revoked_at = ? WHERE id = ? "
            "AND account_id = ? AND revoked_at IS NULL",
            (now_iso(), token, account_id),
        )


def revoke_other_sessions(conn, account_id, keep_token=None):
    if keep_token:
        conn.execute(
            "UPDATE admin_sessions SET revoked_at = ? WHERE account_id = ? "
            "AND id <> ? AND revoked_at IS NULL",
            (now_iso(), account_id, keep_token),
        )
    else:
        conn.execute(
            "UPDATE admin_sessions SET revoked_at = ? WHERE account_id = ? "
            "AND revoked_at IS NULL",
            (now_iso(), account_id),
        )


def list_sessions(conn, account_id=None, limit=100):
    sql = (
        "SELECT s.*, a.username, a.role FROM admin_sessions s "
        "JOIN admin_accounts a ON a.id = s.account_id"
    )
    params = []
    if account_id is not None:
        sql += " WHERE s.account_id = ?"
        params.append(account_id)
    sql += " ORDER BY s.last_seen DESC LIMIT ?"
    params.append(limit)
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


def purge_expired_sessions(conn):
    conn.execute(
        "DELETE FROM admin_sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL",
        (now_iso(),),
    )
