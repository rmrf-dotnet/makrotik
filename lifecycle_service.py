"""Safe lifecycle rules: automatic soft-archive based on age, tags or size."""

from __future__ import annotations

from datetime import datetime, timedelta

from db import log_event, now_iso

CONDITION_TYPES = ("age_days", "tag", "size_mb")


def list_rules(conn):
    rows = conn.execute(
        "SELECT * FROM lifecycle_rules ORDER BY id"
    ).fetchall()
    return [dict(row) for row in rows]


def create_rule(conn, name, condition_type, condition_value, action="archive"):
    if condition_type not in CONDITION_TYPES:
        raise ValueError("Unsupported lifecycle condition.")
    if action != "archive":
        raise ValueError("Only the safe archive action is supported.")
    return conn.insert(
        "INSERT INTO lifecycle_rules "
        "(name, condition_type, condition_value, action, enabled, created_at) "
        "VALUES (?, ?, ?, ?, 1, ?)",
        (
            (name or "").strip() or "Lifecycle rule",
            condition_type,
            str(condition_value or "").strip(),
            action,
            now_iso(),
        ),
    )


def delete_rule(conn, rule_id):
    conn.execute("DELETE FROM lifecycle_rules WHERE id = ?", (rule_id,))


def toggle_rule(conn, rule_id):
    row = conn.execute(
        "SELECT enabled FROM lifecycle_rules WHERE id = ?", (rule_id,)
    ).fetchone()
    if not row:
        return False
    enabled = 0 if row["enabled"] else 1
    conn.execute(
        "UPDATE lifecycle_rules SET enabled = ? WHERE id = ?",
        (enabled, rule_id),
    )
    return bool(enabled)


def _matches(row, rule):
    condition = rule["condition_type"]
    value = rule["condition_value"]
    if condition == "age_days":
        try:
            days = max(0, int(value))
        except (TypeError, ValueError):
            return False
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat(
            timespec="seconds"
        )
        return (row["created_at"] or "") <= cutoff
    if condition == "tag":
        wanted = (value or "").strip().lower()
        tags = [tag.strip().lower() for tag in (row["tags"] or "").split(",")]
        return bool(wanted) and wanted in tags
    if condition == "size_mb":
        try:
            minimum = max(0, float(value)) * 1024 * 1024
        except (TypeError, ValueError):
            return False
        return int(row["size"] or 0) >= minimum
    return False


def update_tags(conn, token, tags, actor):
    cleaned = ",".join(
        dict.fromkeys(
            tag.strip()[:40]
            for tag in (tags or "").split(",")
            if tag.strip()
        )
    )
    conn.execute("UPDATE files SET tags = ? WHERE token = ?", (cleaned, token))
    log_event(
        conn,
        actor,
        "tags_changed",
        token,
        cleaned or "(cleared)",
        category="file",
    )
    return cleaned


def run_rules(conn, actor="system"):
    rules = [
        rule
        for rule in list_rules(conn)
        if rule["enabled"] and rule["action"] == "archive"
    ]
    if not rules:
        return {"rules": 0, "matched": 0, "files": []}
    rows = conn.execute(
        "SELECT * FROM files WHERE deleted_at IS NULL ORDER BY created_at"
    ).fetchall()
    archived = []
    now = now_iso()
    for row in rows:
        matched_rule = next((rule for rule in rules if _matches(row, rule)), None)
        if not matched_rule:
            continue
        conn.execute(
            "UPDATE files SET deleted_at = ?, delete_reason = ? "
            "WHERE token = ? AND deleted_at IS NULL",
            (now, f"lifecycle:{matched_rule['name']}", row["token"]),
        )
        log_event(
            conn,
            actor,
            "lifecycle_archive",
            row["token"],
            f"{matched_rule['name']}: {row['original_name']}",
            category="lifecycle",
        )
        archived.append(
            {
                "token": row["token"],
                "name": row["original_name"],
                "rule": matched_rule["name"],
            }
        )
    for rule in rules:
        conn.execute(
            "UPDATE lifecycle_rules SET last_run_at = ? WHERE id = ?",
            (now, rule["id"]),
        )
    if archived:
        log_event(
            conn,
            actor,
            "lifecycle_run",
            detail=f"archived {len(archived)} file(s) across {len(rules)} rule(s)",
            category="lifecycle",
        )
    return {"rules": len(rules), "matched": len(archived), "files": archived}
