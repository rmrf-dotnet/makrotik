"""Audit querying, hash-chain verification and export helpers."""

from __future__ import annotations

import csv
import hashlib
import io
import json

from db import log_event, now_iso

SEVERITIES = ("info", "notice", "warning", "critical")
CATEGORIES = (
    "auth",
    "file",
    "backup",
    "lifecycle",
    "security",
    "settings",
    "system",
)


def severity_for(action):
    action = (action or "").lower()
    if any(part in action for part in ("fail", "error", "locked", "denied")):
        return "warning"
    if any(part in action for part in ("purge", "delete", "revoke", "disable")):
        return "critical"
    if any(part in action for part in ("login", "logout", "password", "2fa")):
        return "notice"
    return "info"


def category_for(action):
    action = (action or "").lower()
    if action.startswith("admin_") or action in ("login", "logout", "register"):
        return "auth"
    if action in ("upload", "download", "archive", "restore", "purge"):
        return "file"
    if "backup" in action:
        return "backup"
    if "lifecycle" in action:
        return "lifecycle"
    if "setting" in action or "retention" in action:
        return "settings"
    if any(part in action for part in ("2fa", "session", "security", "account")):
        return "security"
    return "system"


def _canonical(created_at, actor, action, token, detail, severity, category, prev_hash):
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


def append_event(conn, actor, action, token=None, detail="", severity=None, category=None):
    """Append a chained audit event using the db layer's canonical writer."""
    return log_event(
        conn,
        actor,
        action,
        token=token,
        detail=detail,
        severity=severity,
        category=category,
    )


def verify_chain(conn, limit=20000):
    rows = conn.execute(
        "SELECT id, created_at, actor, action, token, detail, severity, category, "
        "prev_hash, entry_hash FROM audit_log "
        "WHERE entry_hash IS NOT NULL AND entry_hash <> '' "
        "ORDER BY id ASC LIMIT ?",
        (limit,),
    ).fetchall()
    legacy = conn.execute(
        "SELECT COUNT(*) AS n FROM audit_log "
        "WHERE entry_hash IS NULL OR entry_hash = ''"
    ).fetchone()["n"]
    expected_prev = "GENESIS"
    checked = 0
    broken = []
    for row in rows:
        checked += 1
        if row["prev_hash"] != expected_prev:
            broken.append(
                {
                    "id": row["id"],
                    "reason": "previous hash does not match",
                    "expected": expected_prev,
                    "actual": row["prev_hash"],
                }
            )
            break
        computed = _canonical(
            row["created_at"],
            row["actor"],
            row["action"],
            row["token"],
            row["detail"],
            row["severity"],
            row["category"],
            row["prev_hash"],
        )
        if computed != row["entry_hash"]:
            broken.append(
                {
                    "id": row["id"],
                    "reason": "entry hash does not match content",
                    "expected": computed,
                    "actual": row["entry_hash"],
                }
            )
            break
        expected_prev = row["entry_hash"]
    state = conn.execute(
        "SELECT last_hash FROM audit_chain WHERE id = 1"
    ).fetchone()
    chain_head = state["last_hash"] if state else None
    if rows and chain_head and chain_head != expected_prev:
        broken.append(
            {
                "id": rows[-1]["id"],
                "reason": "chain head does not match the audit chain state",
                "expected": expected_prev,
                "actual": chain_head,
            }
        )
    return {
        "ok": not broken,
        "checked": checked,
        "legacy": legacy or 0,
        "head": chain_head or expected_prev,
        "broken": broken,
        "checked_at": now_iso(),
        "limited": len(rows) >= limit,
    }


def _filters(args):
    where = []
    params = []

    def add(column, value, operator="="):
        if value not in (None, ""):
            where.append(f"{column} {operator} ?")
            params.append(value)

    add("LOWER(actor)", (args.get("actor") or "").strip().lower(), "LIKE")
    if args.get("actor"):
        params[-1] = f"%{params[-1]}%"
    add("action", (args.get("action") or "").strip())
    add("severity", (args.get("severity") or "").strip())
    add("category", (args.get("category") or "").strip())
    add("token", (args.get("token") or "").strip())
    if args.get("q"):
        where.append(
            "(LOWER(detail) LIKE LOWER(?) OR LOWER(actor) LIKE LOWER(?) "
            "OR LOWER(action) LIKE LOWER(?) OR LOWER(token) LIKE LOWER(?))"
        )
        term = f"%{args.get('q').strip()}%"
        params.extend([term, term, term, term])
    if args.get("start"):
        where.append("created_at >= ?")
        params.append(args.get("start").strip())
    if args.get("end"):
        where.append("created_at <= ?")
        params.append(args.get("end").strip())
    return where, params


def query_events(conn, args, limit=500):
    where, params = _filters(args)
    sql = "SELECT * FROM audit_log"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


def export_rows(conn, args, fmt="json", limit=10000):
    where, params = _filters(args)
    sql = "SELECT * FROM audit_log"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id ASC LIMIT ?"
    params.append(limit)
    rows = [dict(row) for row in conn.execute(sql, params).fetchall()]
    if fmt == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "id",
                "created_at",
                "actor",
                "action",
                "token",
                "detail",
                "severity",
                "category",
                "prev_hash",
                "entry_hash",
            ],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue(), "text/csv"
    return json.dumps(rows, indent=2), "application/json"
