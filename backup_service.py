"""Backup targets, schedules, delivery, verification and retention."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
from datetime import datetime, timedelta

from db import now_iso


def parse_config(raw):
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def list_targets(conn):
    rows = conn.execute(
        "SELECT * FROM backup_targets ORDER BY LOWER(name)"
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["config_data"] = parse_config(item.get("config"))
        result.append(item)
    return result


def get_target(conn, target_id):
    row = conn.execute(
        "SELECT * FROM backup_targets WHERE id = ?", (target_id,)
    ).fetchone()
    if not row:
        return None
    item = dict(row)
    item["config_data"] = parse_config(item.get("config"))
    return item


def create_target(conn, name, kind, config):
    return conn.insert(
        "INSERT INTO backup_targets (name, kind, config, enabled, created_at) "
        "VALUES (?, ?, ?, 1, ?)",
        ((name or "").strip(), kind, json.dumps(config or {}), now_iso()),
    )


def delete_target(conn, target_id):
    conn.execute("DELETE FROM backup_targets WHERE id = ?", (target_id,))


def list_schedules(conn):
    rows = conn.execute(
        "SELECT s.*, t.name AS target_name, t.kind AS target_kind "
        "FROM backup_schedules s LEFT JOIN backup_targets t ON t.id = s.target_id "
        "ORDER BY s.id"
    ).fetchall()
    return [dict(row) for row in rows]


def create_schedule(conn, name, target_id, interval_minutes, retention_days):
    interval_minutes = max(5, min(int(interval_minutes), 525600))
    retention_days = max(0, min(int(retention_days), 3650))
    next_run = (
        datetime.utcnow() + timedelta(minutes=interval_minutes)
    ).isoformat(timespec="seconds")
    return conn.insert(
        "INSERT INTO backup_schedules "
        "(name, target_id, interval_minutes, retention_days, enabled, "
        "next_run_at, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
        (
            (name or "").strip() or "Scheduled backup",
            target_id,
            interval_minutes,
            retention_days,
            next_run,
            now_iso(),
        ),
    )


def delete_schedule(conn, schedule_id):
    conn.execute("DELETE FROM backup_schedules WHERE id = ?", (schedule_id,))


def toggle_schedule(conn, schedule_id):
    row = conn.execute(
        "SELECT enabled FROM backup_schedules WHERE id = ?", (schedule_id,)
    ).fetchone()
    if not row:
        return False
    enabled = 0 if row["enabled"] else 1
    conn.execute(
        "UPDATE backup_schedules SET enabled = ? WHERE id = ?",
        (enabled, schedule_id),
    )
    return bool(enabled)


def due_schedules(conn):
    rows = conn.execute(
        "SELECT s.*, t.name AS target_name, t.kind AS target_kind, "
        "t.config AS target_config FROM backup_schedules s "
        "LEFT JOIN backup_targets t ON t.id = s.target_id "
        "WHERE s.enabled = 1 AND s.next_run_at IS NOT NULL "
        "AND s.next_run_at <= ? ORDER BY s.next_run_at",
        (now_iso(),),
    ).fetchall()
    return [dict(row) for row in rows]


def mark_schedule_run(conn, schedule_id, interval_minutes):
    next_run = (
        datetime.utcnow() + timedelta(minutes=max(5, int(interval_minutes)))
    ).isoformat(timespec="seconds")
    conn.execute(
        "UPDATE backup_schedules SET last_run_at = ?, next_run_at = ? "
        "WHERE id = ?",
        (now_iso(), next_run, schedule_id),
    )


def record_run(conn, backup_name, target_id, status, detail, started_at):
    return conn.insert(
        "INSERT INTO backup_runs "
        "(backup_name, target_id, status, detail, started_at, finished_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            backup_name,
            target_id,
            status,
            (detail or "")[:2000],
            started_at,
            now_iso(),
        ),
    )


def list_runs(conn, limit=50):
    rows = conn.execute(
        "SELECT * FROM backup_runs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(row) for row in rows]


def deliver_backup(source_path, target):
    """Copy/upload a backup to a configured target. Returns a human detail."""
    if not target:
        return "Stored locally only"
    config = target.get("config_data") or parse_config(target.get("config"))
    kind = target.get("kind")
    name = os.path.basename(source_path)
    if kind == "local":
        destination = os.path.abspath(
            os.path.expanduser(config.get("path") or "")
        )
        if not destination:
            raise RuntimeError("Local target has no path configured.")
        os.makedirs(destination, exist_ok=True)
        dest = os.path.join(destination, name)
        if os.path.abspath(dest) == os.path.abspath(source_path):
            return f"Already in local target: {destination}"
        shutil.copy2(source_path, dest)
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        return f"Copied to local target: {destination}"
    if kind == "s3":
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "S3 target needs boto3. Install it with 'pip install boto3'."
            ) from exc
        bucket = config.get("bucket")
        if not bucket:
            raise RuntimeError("S3 target has no bucket configured.")
        prefix = (config.get("prefix") or "").strip("/")
        key = f"{prefix}/{name}" if prefix else name
        client_kwargs = {}
        if config.get("region"):
            client_kwargs["region_name"] = config["region"]
        if config.get("endpoint_url"):
            client_kwargs["endpoint_url"] = config["endpoint_url"]
        client = boto3.client("s3", **client_kwargs)
        client.upload_file(source_path, bucket, key)
        return f"Uploaded to s3://{bucket}/{key}"
    if kind == "sftp":
        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "SFTP target needs paramiko. Install it with 'pip install paramiko'."
            ) from exc
        host = config.get("host")
        username = config.get("username")
        if not host or not username:
            raise RuntimeError("SFTP target needs host and username.")
        remote_dir = (config.get("path") or "/").rstrip("/") or "/"
        transport = paramiko.Transport((host, int(config.get("port") or 22)))
        try:
            if config.get("key_path"):
                key = paramiko.RSAKey.from_private_key_file(
                    os.path.expanduser(config["key_path"])
                )
                transport.connect(username=username, pkey=key)
            else:
                transport.connect(
                    username=username, password=config.get("password") or ""
                )
            sftp = paramiko.SFTPClient.from_transport(transport)
            try:
                sftp.put(source_path, f"{remote_dir}/{name}")
            finally:
                sftp.close()
        finally:
            transport.close()
        return f"Uploaded to sftp://{host}{remote_dir}/{name}"
    raise RuntimeError(f"Unsupported backup target kind: {kind}")


def test_backup(path, name):
    """Verify a backup archive without restoring it over live data."""
    if name.endswith(".sqlite"):
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                result = conn.execute("PRAGMA integrity_check").fetchone()[0]
                tables = conn.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'"
                ).fetchone()[0]
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001 - surface the real failure
            return False, f"SQLite verification failed: {exc}"
        if str(result).lower() != "ok":
            return False, f"SQLite integrity_check returned: {result}"
        return True, f"SQLite integrity_check ok; {tables} tables present."
    if name.endswith(".dump"):
        try:
            result = subprocess.run(
                ["pg_restore", "--list", path],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return False, "pg_restore is not installed; cannot verify the dump."
        except subprocess.TimeoutExpired:
            return False, "pg_restore --list timed out."
        if result.returncode != 0:
            return False, result.stderr.strip() or "pg_restore --list failed."
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        return True, f"pg_restore parsed the archive; {len(lines)} entries."
    return False, "Unknown backup format."


def prune_backups(folder, days, keep_name=None):
    if not days or days <= 0:
        return []
    cutoff = datetime.utcnow() - timedelta(days=days)
    removed = []
    try:
        names = os.listdir(folder)
    except OSError:
        return removed
    for name in names:
        if name == keep_name:
            continue
        if not (name.endswith(".sqlite") or name.endswith(".dump")):
            continue
        path = os.path.join(folder, name)
        try:
            mtime = datetime.utcfromtimestamp(os.path.getmtime(path))
        except OSError:
            continue
        if mtime >= cutoff:
            continue
        try:
            os.remove(path)
            removed.append(name)
        except OSError:
            pass
    return removed
