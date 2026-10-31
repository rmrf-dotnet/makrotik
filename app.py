"""Makrotik Share.

Anonymous file sharing, with *optional* accounts.

Operating principles
--------------------
* No account is ever required to upload or download. A signed-in user simply
  gains a dashboard (transfer history, stats, one-click delete).
* Every file gets an unguessable 128-bit random token. The token *is* the
  permission — share links only with people you trust.
* Files expire from public links at the chosen lifetime but are archived, not
  destroyed. Only an explicit admin purge removes archived bytes.
* One request can carry up to MAX_UPLOAD_BYTES (default 200 GB). Uploads
  stream to disk, so memory stays flat no matter the file size.
* Passwords are hashed (scrypt) — the user table stores no plaintext.
* CSRF tokens guard every state-changing request; delete links also carry a
  secret capability key for anonymous owners.
* The /admin/ control room is separate from the user dashboard and uses a
  durable PostgreSQL store when configured, with a hardened SQLite fallback.
"""

import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlsplit, urlunsplit

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    Response,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from db import (
    Database,
    get_setting,
    log_event,
    now_iso,
    set_setting,
)
import admin_services
import analytics_service
import audit_service
import backup_service
import infra_service
import lifecycle_service
import totp

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _load_dotenv(path):
    """Tiny .env loader so Postgres/admin settings can live next to the app."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip("\"'"))
    except OSError:
        pass


_load_dotenv(os.path.join(BASE_DIR, ".env"))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
INSTANCE_FOLDER = os.path.join(BASE_DIR, "instance")
BACKUP_FOLDER = os.path.join(BASE_DIR, "backups")
SQLITE_PATH = os.environ.get(
    "MAKROTIK_SQLITE_PATH", os.path.join(INSTANCE_FOLDER, "share.db")
)
DATABASE_URL = (
    os.environ.get("MAKROTIK_DATABASE_URL")
    or os.environ.get("DATABASE_URL")
    or ""
)
ADMIN_USERNAME = os.environ.get("MAKROTIK_ADMIN_USER", "admin")
ADMIN_PASSWORD_ENV = os.environ.get("MAKROTIK_ADMIN_PASSWORD", "")
ADMIN_CREDENTIALS_FILE = os.path.join(INSTANCE_FOLDER, "admin_credentials.txt")
ADMIN_MAX_FAILURES = 5
ADMIN_LOCKOUT_SECONDS = 300
ADMIN_SESSION_HOURS = int(os.environ.get("MAKROTIK_ADMIN_SESSION_HOURS", "12") or 12)
_ADMIN_FAILURES = {}
_SCHEDULER_STARTED = False
_LAST_LIFECYCLE_RUN = 0

MAX_UPLOAD_BYTES = 200 * 1024 * 1024 * 1024  # 200 GB per request
DEFAULT_EXPIRY = "7d"

# Optional soft storage quota for the meter on the dashboard / status page.
# When 0 (the default) the meter reports real disk usage of the uploads volume.
STORAGE_QUOTA_BYTES = int(os.environ.get("MAKROTIK_STORAGE_QUOTA_BYTES", "0") or 0)

# When the process started — used to report uptime on the status page.
APP_START = datetime.utcnow()

# Site identity / legal pages. Override the contact address with the
# MAKROTIK_CONTACT_EMAIL environment variable before going live.
SITE_NAME = "Makrotik Share"
CONTACT_EMAIL = os.environ.get("MAKROTIK_CONTACT_EMAIL", "privacy@makrotik.bg")
LEGAL_UPDATED = "11 October 2026"
EXPIRY_CHOICES = {
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "never": None,
}

USERNAME_RE_MSG = "Usernames may only contain letters, numbers, _ and -."
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(INSTANCE_FOLDER, exist_ok=True)
os.makedirs(BACKUP_FOLDER, exist_ok=True)


def _load_or_create_secret():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(INSTANCE_FOLDER, "secret_key")
    try:
        with open(path, "r") as fh:
            return fh.read().strip() or secrets.token_hex(32)
    except OSError:
        key = secrets.token_hex(32)
        try:
            with open(path, "w") as fh:
                fh.write(key)
        except OSError:
            pass
        return key


app = Flask(__name__)
app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SECRET_KEY=_load_or_create_secret(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    JSON_SORT_KEYS=False,
    SEND_FILE_MAX_AGE_DEFAULT=0,
)

database = Database(DATABASE_URL, SQLITE_PATH, logger=app.logger)
_schema_ready = False
_admin_seeded = False


# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
def get_db():
    global _schema_ready, _admin_seeded
    if "db" not in g:
        g.db = database.connect()
        if not _schema_ready:
            try:
                database.ensure_schema(g.db)
                _schema_ready = True
            except Exception:
                g.db.rollback()
                raise
        if not _admin_seeded:
            seed_admin(g.db)
            _admin_seeded = True
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create/upgrade the schema eagerly, then seed admin credentials."""
    conn = database.connect()
    try:
        database.ensure_schema(conn)
        seed_admin(conn)
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Utilities
# --------------------------------------------------------------------------- #
def human_size(num_bytes):
    size = float(num_bytes or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def clean_filename(name):
    name = (name or "").replace("\\", "_").replace("/", "_")
    name = "".join(
        ch for ch in name
        if ch.isprintable() and ch not in '<>:"/\\|?*'
    )
    name = re.sub(r"\s+", " ", name).strip(" .")
    return (name or "file")[:180]


def expiry_for(value):
    delta = EXPIRY_CHOICES.get(value, EXPIRY_CHOICES[DEFAULT_EXPIRY])
    if delta is None:
        return None
    return (datetime.utcnow() + delta).isoformat(timespec="seconds")


def register_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)


def wants_json():
    return (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )


def _remove_safely(path):
    """Best-effort file removal — never raises, never crashes the request."""
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def file_path(row):
    return os.path.join(app.config["UPLOAD_FOLDER"], row["stored_name"])


def store_upload(upload, dest):
    """Stream an upload to disk durably and return (size, sha256).

    The bytes are written to a sibling .part file, flushed to stable storage,
    then atomically renamed into place. A crash can therefore never leave a
    half-written file under its final name.
    """
    tmp = dest + ".part"
    digest = hashlib.sha256()
    size = 0
    try:
        with open(tmp, "wb") as fh:
            while True:
                chunk = upload.stream.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, dest)
        _fsync_dir(os.path.dirname(dest))
    except Exception:
        _remove_safely(tmp)
        raise
    return size, digest.hexdigest()


def actor_label():
    try:
        admin = getattr(g, "admin_session", None)
        if admin:
            return f"admin:{admin['username']}"
        if session.get("admin_authenticated"):
            return f"admin:{session.get('admin_username', ADMIN_USERNAME)}"
    except RuntimeError:
        pass
    try:
        user = getattr(g, "user", None)
    except RuntimeError:
        user = None
    if user:
        return f"user:{user['username']}"
    return "anonymous"


def archive_file(row, reason="user", actor=None, commit=True):
    """Soft-delete a file: the link dies, the record and bytes stay safe."""
    db = get_db()
    if row["deleted_at"]:
        return False
    db.execute(
        "UPDATE files SET deleted_at = ?, delete_reason = ? "
        "WHERE token = ? AND deleted_at IS NULL",
        (now_iso(), reason, row["token"]),
    )
    log_event(
        db,
        actor or actor_label(),
        "archive",
        row["token"],
        f"{reason}: {row['original_name']}",
    )
    if commit:
        db.commit()
    return True


def purge_file(row, actor=None):
    """Permanently remove a file and its row. Only explicit admin action."""
    db = get_db()
    db.execute("DELETE FROM files WHERE token = ?", (row["token"],))
    log_event(
        db,
        actor or actor_label(),
        "purge",
        row["token"],
        f"permanent: {row['original_name']}",
    )
    db.commit()
    _remove_safely(file_path(row))
    return True


def fetch_file(token):
    row = get_db().execute(
        "SELECT * FROM files WHERE token = ? AND deleted_at IS NULL", (token,)
    ).fetchone()
    if row is None:
        return None
    if row["expires_at"] and row["expires_at"] < now_iso():
        archive_file(row, reason="expired", actor="system")
        return None
    return row


# --------------------------------------------------------------------------- #
# Admin authentication
# --------------------------------------------------------------------------- #
def seed_admin(conn):
    password_hash = get_setting(conn, "admin_password_hash")
    if password_hash is None:
        password = ADMIN_PASSWORD_ENV or secrets.token_urlsafe(18)
        set_setting(conn, "admin_username", ADMIN_USERNAME)
        set_setting(conn, "admin_password_hash", generate_password_hash(password))
        if not ADMIN_PASSWORD_ENV:
            try:
                fd = os.open(
                    ADMIN_CREDENTIALS_FILE,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o600,
                )
                with os.fdopen(fd, "w") as fh:
                    fh.write(
                        "Makrotik Share — generated admin credentials\n"
                        f"username: {ADMIN_USERNAME}\n"
                        f"password: {password}\n"
                        "url: http://127.0.0.1:5000/admin/\n"
                        "\nChange this password from Admin → Settings.\n"
                    )
            except OSError:
                pass
            app.logger.warning(
                "Admin credentials generated. See %s (or set "
                "MAKROTIK_ADMIN_PASSWORD before first start).",
                ADMIN_CREDENTIALS_FILE,
            )
    if get_setting(conn, "archive_retention_days") is None:
        set_setting(conn, "archive_retention_days", "0")
    expected_user = get_setting(conn, "admin_username", ADMIN_USERNAME) or ADMIN_USERNAME
    primary_hash = get_setting(conn, "admin_password_hash")
    if primary_hash:
        admin_services.ensure_primary_account(conn, expected_user, primary_hash)
    conn.commit()


def _clear_admin_auth():
    session.pop("admin_authenticated", None)
    session.pop("admin_username", None)
    session.pop("admin_session_id", None)
    session.pop("admin_account_id", None)


def load_admin_identity():
    g.admin_session = None
    if session.get("admin_authenticated") is not True:
        return
    token = session.get("admin_session_id")
    if not token:
        _clear_admin_auth()
        return
    row = admin_services.active_session(get_db(), token)
    if not row:
        _clear_admin_auth()
        return
    g.admin_session = row
    session["admin_username"] = row["username"]


def is_admin():
    return bool(getattr(g, "admin_session", None))


def current_admin():
    return getattr(g, "admin_session", None)


def admin_has(permission):
    return admin_services.has_permission(current_admin(), permission)


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_admin():
            if wants_json():
                return jsonify({"error": "Admin authentication required."}), 401
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)

    return wrapper


def permission_required(permission):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not is_admin():
                if wants_json():
                    return jsonify({"error": "Admin authentication required."}), 401
                return redirect(url_for("admin_login", next=request.path))
            if not admin_has(permission):
                if wants_json():
                    return jsonify({"error": "Permission denied."}), 403
                abort(403)
            return view(*args, **kwargs)

        return wrapper

    return decorator


def verify_admin(username, password):
    expected_user = get_setting(get_db(), "admin_username", ADMIN_USERNAME)
    if not hmac.compare_digest((username or "").strip(), expected_user or ""):
        return False
    if ADMIN_PASSWORD_ENV:
        return hmac.compare_digest(password or "", ADMIN_PASSWORD_ENV)
    password_hash = get_setting(get_db(), "admin_password_hash")
    return bool(password_hash) and check_password_hash(password_hash, password or "")


def verify_current_password(password):
    account = current_admin()
    if not account:
        return False
    expected_user = get_setting(get_db(), "admin_username", ADMIN_USERNAME)
    if hmac.compare_digest(account["username"], expected_user or "") and ADMIN_PASSWORD_ENV:
        return hmac.compare_digest(password or "", ADMIN_PASSWORD_ENV)
    return admin_services.verify_password(
        admin_services.get_account(get_db(), account["account_id"]), password
    )


def set_admin_password(new_password):
    db = get_db()
    set_setting(db, "admin_password_hash", generate_password_hash(new_password))
    account = current_admin()
    if account:
        admin_services.update_account(
            db, account["account_id"], password=new_password
        )
    log_event(db, actor_label(), "admin_password_changed", detail="password rotated")
    db.commit()


def admin_locked(ip):
    record = _ADMIN_FAILURES.get(ip)
    if not record:
        return False
    count, first = record
    if time.time() - first > ADMIN_LOCKOUT_SECONDS:
        _ADMIN_FAILURES.pop(ip, None)
        return False
    return count >= ADMIN_MAX_FAILURES


def record_admin_failure(ip):
    now = time.time()
    count, first = _ADMIN_FAILURES.get(ip, (0, now))
    if now - first > ADMIN_LOCKOUT_SECONDS:
        count, first = 0, now
    _ADMIN_FAILURES[ip] = (count + 1, first)


# --------------------------------------------------------------------------- #
# Auth / request lifecycle
# --------------------------------------------------------------------------- #
@app.before_request
def load_user_and_csrf():
    register_csrf()
    load_admin_identity()
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        sent = hmac.compare_digest(token or "", session.get("csrf_token", ""))
        if not sent:
            if wants_json():
                return jsonify({"error": "Session expired. Refresh and try again."}), 400
            abort(400)


@app.context_processor
def inject_globals():
    return {
        "current_user": getattr(g, "user", None),
        "csrf_token": session.get("csrf_token", ""),
        "max_upload": MAX_UPLOAD_BYTES,
        "max_upload_human": human_size(MAX_UPLOAD_BYTES),
        "site_name": SITE_NAME,
        "contact_email": CONTACT_EMAIL,
        "legal_updated": LEGAL_UPDATED,
        "legal_updated_iso": "2026-10-11",
        "current_year": datetime.utcnow().year,
        "admin_authenticated": is_admin(),
        "admin_username": session.get("admin_username", ADMIN_USERNAME),
        "admin_account": current_admin(),
        "admin_role": (
            current_admin()["role"] if current_admin() else None
        ),
        "admin_role_label": (
            admin_services.ROLE_LABELS.get(current_admin()["role"], "")
            if current_admin()
            else ""
        ),
        "admin_can": admin_has,
        "db_engine": database.engine,
        "db_is_postgres": database.is_postgres,
    }


def username_taken(username):
    return (
        get_db()
        .execute("SELECT 1 FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        .fetchone()
        is not None
    )


def email_taken(email):
    return (
        get_db()
        .execute("SELECT 1 FROM users WHERE LOWER(email) = LOWER(?)", (email,))
        .fetchone()
        is not None
    )


def validate_credentials(username, password, email):
    username = (username or "").strip()
    if not (3 <= len(username) <= 32):
        return "Username must be between 3 and 32 characters."
    if not all(ch.isalnum() or ch in "_-" for ch in username):
        return USERNAME_RE_MSG
    email = (email or "").strip()
    if len(email) > 254 or not EMAIL_RE.match(email):
        return "Enter a valid email address."
    if len(password or "") < 6:
        return "Password must be at least 6 characters."
    return None


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        err = validate_credentials(username, password, email)
        if err:
            flash(err, "error")
        elif username_taken(username):
            flash("That username is already taken.", "error")
        elif email_taken(email):
            flash("That email is already registered. Try signing in instead.", "error")
        else:
            db = get_db()
            user_id = db.insert(
                "INSERT INTO users (username, email, password_hash, created_at) "
                "VALUES (?, ?, ?, ?)",
                (username, email, generate_password_hash(password), now_iso()),
            )
            log_event(db, f"user:{username}", "register", detail="account created")
            db.commit()
            session["user_id"] = user_id
            flash(f"Welcome aboard, {username}!", "success")
            return redirect(url_for("dashboard"))
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = (
            get_db()
            .execute(
                "SELECT * FROM users WHERE LOWER(username) = LOWER(?) "
                "OR LOWER(email) = LOWER(?)",
                (identifier, identifier),
            )
            .fetchone()
        )
        if row is None or not check_password_hash(row["password_hash"], password):
            flash("Invalid username/email or password.", "error")
        else:
            session["user_id"] = row["id"]
            db = get_db()
            log_event(db, f"user:{row['username']}", "login", detail="signed in")
            db.commit()
            flash(f"Signed in as {row['username']}.", "success")
            return redirect(url_for("dashboard"))
    return render_template("auth.html", mode="login")


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    session.pop("csrf_token", None)
    flash("You have been signed out.", "success")
    return redirect(url_for("index"))


# --------------------------------------------------------------------------- #
# Page routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    """Public landing page shown before entering the dashboard."""
    return render_template("landing.html")


@app.route("/dashboard")
def dashboard():
    stats = None
    recent = []
    if g.user:
        stats = dashboard_stats(g.user["id"])
        recent = list_files(g.user["id"], limit=6)
    return render_template("dashboard.html", stats=stats, recent=recent, meter=storage_meter())


@app.route("/files")
def my_files():
    if g.user is None:
        flash("Create a free account (or sign in) to see your dashboard.", "info")
        return redirect(url_for("login"))
    files = list_files(g.user["id"], limit=200)
    stats = dashboard_stats(g.user["id"])
    return render_template(
        "files.html", files=files, stats=stats, drives=list_drives()
    )


def _drive_entry(name, mount, label=""):
    try:
        usage = shutil.disk_usage(mount)
    except OSError:
        return None
    total = usage.total
    percent = round((usage.used / total) * 100, 1) if total else 0.0
    percent = min(percent, 100.0)
    return {
        "name": name,
        "label": label,
        "mount": mount,
        "total": total,
        "used": usage.used,
        "free": usage.free,
        "total_human": human_size(total),
        "used_human": human_size(usage.used),
        "free_human": human_size(usage.free),
        "percent": percent,
        "level": "high" if percent >= 90 else "warn" if percent >= 75 else "ok",
    }


def list_drives():
    """Every disk volume the host exposes, with its real free/used space.

    Tuned for a Linux (Ubuntu) server: reads /proc/mounts and reports real
    filesystems (root, data volumes, mounted disks). Pseudo-filesystems and
    container/runtime mounts are skipped.
    """
    REAL_FS = {
        "ext4", "ext3", "ext2", "xfs", "btrfs", "zfs", "vfat", "ntfs",
        "exfat", "f2fs", "reiserfs", "jfs",
    }
    SKIP_PREFIXES = (
        "/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker",
        "/var/lib/containerd", "/boot/efi",
    )
    drives = []
    seen = set()
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as fh:
            mounts = fh.readlines()
    except OSError:
        mounts = []
    for line in mounts:
        parts = line.split()
        if len(parts) < 3:
            continue
        mount = parts[1].replace("\\040", " ")
        fstype = parts[2]
        if fstype not in REAL_FS:
            continue
        if any(mount == p or mount.startswith(p + "/") for p in SKIP_PREFIXES):
            continue
        if mount in seen:
            continue
        # Skip bind mounts of the same device already reported.
        dev = parts[0]
        key = (dev, mount)
        if key in seen:
            continue
        seen.add(mount)
        label = "Linux root" if mount == "/" else mount
        entry = _drive_entry(label, mount)
        if entry:
            drives.append(entry)
    if not drives:
        # Final fallback: report the filesystem holding the app directory.
        entry = _drive_entry("root", "/")
        if entry:
            drives.append(entry)
    return sorted(drives, key=lambda d: d["name"])


# --------------------------------------------------------------------------- #
# Public informational pages (always accessible, no account required)
# --------------------------------------------------------------------------- #
@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/gdpr")
def gdpr():
    return render_template("gdpr.html")


def list_files(owner_id, limit=200, offset=0):
    db = get_db()
    now = now_iso()
    rows = db.execute(
        "SELECT *, "
        "(expires_at IS NOT NULL AND expires_at < ?) AS is_expired "
        "FROM files WHERE owner_id = ? AND deleted_at IS NULL "
        "ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (now, owner_id, limit, offset),
    ).fetchall()
    # Expired links stop working, but the record and bytes are archived — not
    # destroyed. An admin can restore or explicitly purge them later.
    expired = [row for row in rows if row["is_expired"]]
    for row in expired:
        archive_file(row, reason="expired", actor="system", commit=False)
    if expired:
        db.commit()
    return [meta(r) for r in rows if not r["is_expired"]]


def dashboard_stats(owner_id):
    db = get_db()
    now = now_iso()
    soon = (datetime.utcnow() + timedelta(hours=24)).isoformat(timespec="seconds")
    row = db.execute(
        """
        SELECT COUNT(*)                       AS active,
               COALESCE(SUM(size), 0)         AS total_bytes,
               COALESCE(SUM(downloads), 0)    AS total_downloads,
               SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END) AS expiring
        FROM files
        WHERE owner_id = ? AND deleted_at IS NULL
          AND (expires_at IS NULL OR expires_at > ?)
        """,
        (soon, owner_id, now),
    ).fetchone()
    return {
        "active": row["active"],
        "total_bytes": row["total_bytes"],
        "total_human": human_size(row["total_bytes"]),
        "total_downloads": row["total_downloads"],
        "expiring": row["expiring"] or 0,
    }


def meta(row):
    return {
        "token": row["token"],
        "owner_id": row["owner_id"],
        "name": row["original_name"],
        "size": row["size"],
        "size_human": human_size(row["size"]),
        "mimetype": row["mimetype"],
        "downloads": row["downloads"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "share_url": url_for("share", token=row["token"], _external=True),
        "download_url": url_for("download", token=row["token"], _external=True),
    }


# --------------------------------------------------------------------------- #
# Transfer routes
# --------------------------------------------------------------------------- #
@app.route("/upload", methods=["POST"])
def upload():
    upload = request.files.get("file")
    if upload is None or upload.filename == "":
        return jsonify({"error": "No file selected."}), 400

    original_name = clean_filename(upload.filename)
    token = secrets.token_urlsafe(9)
    delete_key = secrets.token_urlsafe(16)
    stored_name = f"{token}__{original_name}"

    dest = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    # Streams straight to disk, fsyncs, then atomically renames into place.
    try:
        size, sha256 = store_upload(upload, dest)
    except OSError:
        _remove_safely(dest)
        return jsonify({"error": "Could not store the file on disk."}), 500

    expiry = request.form.get("expiry", DEFAULT_EXPIRY)
    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO files
                (token, owner_id, original_name, stored_name, size, mimetype,
                 delete_key, created_at, expires_at, sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token,
                g.user["id"] if g.user else None,
                original_name,
                stored_name,
                size,
                upload.mimetype or "application/octet-stream",
                delete_key,
                now_iso(),
                expiry_for(expiry),
                sha256,
            ),
        )
        log_event(
            db,
            actor_label(),
            "upload",
            token,
            f"{original_name} ({size} bytes, sha256 {sha256[:16]}…)",
        )
        analytics_service.record_traffic(
            db,
            "upload",
            token,
            size,
            actor_label(),
            g.user["id"] if g.user else None,
        )
        db.commit()
    except Exception:
        db.rollback()
        # Never leave a file on disk without its database row.
        _remove_safely(dest)
        return jsonify({"error": "Could not record the file. Please try again."}), 500

    stored = db.execute("SELECT * FROM files WHERE token = ?", (token,)).fetchone()
    result = meta(stored)
    result["delete_key"] = delete_key
    result["delete_url"] = url_for(
        "delete_shared_file", token=token, key=delete_key, _external=True
    )
    return jsonify(result), 201


@app.route("/f/<token>")
def share(token):
    row = fetch_file(token)
    if row is None:
        return render_template("not_found.html"), 404
    return render_template("share.html", file=meta(row))


@app.route("/f/<token>/download")
def download(token):
    row = fetch_file(token)
    if row is None:
        abort(404)
    db = get_db()
    db.execute(
        "UPDATE files SET downloads = downloads + 1 WHERE token = ?", (token,)
    )
    log_event(db, actor_label(), "download", token, row["original_name"])
    analytics_service.record_traffic(
        db,
        "download",
        token,
        row["size"],
        actor_label(),
        row["owner_id"],
    )
    db.commit()
    path = file_path(row)
    if not os.path.exists(path):
        abort(404)
    return send_file(
        path,
        as_attachment=True,
        download_name=row["original_name"],
        mimetype=row["mimetype"] or "application/octet-stream",
    )


@app.route("/f/<token>/raw")
def raw(token):
    row = fetch_file(token)
    if row is None:
        abort(404)
    path = file_path(row)
    if not os.path.exists(path):
        abort(404)
    return send_file(
        path,
        as_attachment=False,
        download_name=row["original_name"],
        mimetype=row["mimetype"] or "application/octet-stream",
    )


@app.route("/f/<token>/delete", methods=["GET", "POST"])
def delete_shared_file(token):
    row = fetch_file(token)
    if row is None:
        return render_template("not_found.html"), 404

    # An anonymous uploader proves ownership with a one-time capability key;
    # a signed-in owner can also delete from the dashboard.
    key = request.values.get("key", "")
    owner = g.user is not None and row["owner_id"] == g.user["id"]
    if not (owner or (key and secrets.compare_digest(key, row["delete_key"]))):
        if wants_json():
            return jsonify({"error": "Not authorized to delete this file."}), 403
        return render_template("not_found.html"), 403

    archive_file(row, reason="user")
    if wants_json():
        return jsonify({"deleted": True, "archived": True})
    flash("File removed. Its link is dead and it is safely archived.", "success")
    if "/files" in (request.referrer or ""):
        return redirect(url_for("my_files"))
    return render_template("deleted.html"), 200


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
@app.errorhandler(413)
def too_large(_e):
    msg = f"File is too large. The limit is {human_size(MAX_UPLOAD_BYTES)}."
    if wants_json():
        return jsonify({"error": msg}), 413
    return render_template("error.html", title="Upload too large", message=msg), 413


@app.errorhandler(404)
def not_found(_e):
    if wants_json():
        return jsonify({"error": "Not found."}), 404
    return render_template("not_found.html"), 404


@app.errorhandler(400)
def bad_request(_e):
    if wants_json():
        return jsonify({"error": "Bad request."}), 400
    return render_template("error.html", title="Bad request", message="Try again."), 400


@app.errorhandler(403)
def forbidden(_e):
    if wants_json():
        return jsonify({"error": "Permission denied."}), 403
    return render_template(
        "error.html",
        title="Permission denied",
        message="Your admin role does not allow this action.",
    ), 403


@app.errorhandler(500)
def server_error(_e):
    if wants_json():
        return jsonify({"error": "Internal server error."}), 500
    return render_template("error.html", title="Something went wrong",
                           message="Please try again in a moment."), 500


@app.route("/healthz")
def healthz():
    info = database_info()
    fell_back = info["requested_engine"] == "postgres" and info["engine"] != "postgres"
    healthy = info["ok"] and not fell_back
    return jsonify(
        {
            "status": "ok" if healthy else "degraded",
            "database": info["engine"],
            "database_ok": info["ok"],
            "fallback_reason": info["fallback_reason"],
            "max_upload_human": human_size(MAX_UPLOAD_BYTES),
        }
    )


# --------------------------------------------------------------------------- #
# Storage usage & public status page
# --------------------------------------------------------------------------- #
def storage_stats():
    """How much space Makrotik files take, plus the host disk picture."""
    row = get_db().execute(
        """
        SELECT
            SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) AS count,
            SUM(CASE WHEN deleted_at IS NULL THEN size ELSE 0 END) AS bytes,
            SUM(CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END) AS archived_count,
            SUM(CASE WHEN deleted_at IS NOT NULL THEN size ELSE 0 END) AS archived_bytes,
            COUNT(*) AS total_count,
            COALESCE(SUM(size), 0) AS total_bytes
        FROM files
        """
    ).fetchone()
    files_bytes = row["bytes"] or 0
    files_count = row["count"] or 0
    archived_bytes = row["archived_bytes"] or 0
    archived_count = row["archived_count"] or 0
    try:
        usage = shutil.disk_usage(UPLOAD_FOLDER)
        disk_total, disk_used, disk_free = usage.total, usage.used, usage.free
    except OSError:
        disk_total = disk_used = disk_free = 0
    return {
        "files_bytes": files_bytes,
        "files_count": files_count,
        "files_human": human_size(files_bytes),
        "archived_bytes": archived_bytes,
        "archived_count": archived_count,
        "archived_human": human_size(archived_bytes),
        "total_records": row["total_count"] or 0,
        "total_bytes": row["total_bytes"] or 0,
        "total_human": human_size(row["total_bytes"] or 0),
        "disk_total": disk_total,
        "disk_used": disk_used,
        "disk_free": disk_free,
        "disk_total_human": human_size(disk_total),
        "disk_used_human": human_size(disk_used),
        "disk_free_human": human_size(disk_free),
    }


def storage_breakdown(info=None):
    stats = storage_stats()
    info = info or database_info()
    backup_bytes = sum(item["size"] for item in list_backups())
    database_bytes = int(info.get("size") or 0)
    segments = [
        ("Active uploads", stats["files_bytes"], "is-active"),
        ("Archived uploads", stats["archived_bytes"], "is-archived"),
        ("Database", database_bytes, "is-database"),
        ("Backups", backup_bytes, "is-backup"),
    ]
    total = sum(max(0, size) for _, size, _ in segments) or 1
    return {
        "segments": [
            {
                "label": label,
                "bytes": size,
                "human": human_size(size),
                "percent": round(max(0, size) / total * 100, 1),
                "class": css_class,
            }
            for label, size, css_class in segments
        ],
        "total_bytes": total,
        "total_human": human_size(total),
    }


def storage_meter():
    """The single meter shown on the dashboard and status page.

    Uses a soft quota when MAKROTIK_STORAGE_QUOTA_BYTES is set, otherwise the
    real disk usage of the volume that holds the uploads.
    """
    stats = storage_stats()
    if STORAGE_QUOTA_BYTES:
        used_bytes, total_bytes, mode = stats["files_bytes"], STORAGE_QUOTA_BYTES, "quota"
    else:
        used_bytes, total_bytes, mode = stats["disk_used"], stats["disk_total"], "disk"
    percent = round((used_bytes / total_bytes) * 100, 1) if total_bytes else 0.0
    percent = min(percent, 100.0)
    level = "high" if percent >= 90 else "warn" if percent >= 75 else "ok"
    return {
        **stats,
        "mode": mode,
        "used_bytes": used_bytes,
        "total_bytes": total_bytes,
        "used_human": human_size(used_bytes),
        "total_human": human_size(total_bytes),
        "percent": percent,
        "level": level,
    }


def _human_duration(delta):
    total = int(delta.total_seconds())
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def build_status():
    meter = storage_meter()

    try:
        get_db().execute("SELECT 1").fetchone()
        db_ok = True
    except Exception:
        db_ok = False

    storage_ok = os.path.isdir(UPLOAD_FOLDER) and os.access(UPLOAD_FOLDER, os.W_OK)

    components = [
        {
            "name": "Web application",
            "status": "operational",
            "detail": "Serving requests normally",
        },
        {
            "name": "Database",
            "status": "operational" if db_ok else "down",
            "detail": "Connected and responding" if db_ok else "Unavailable",
        },
        {
            "name": "File storage",
            "status": "operational" if storage_ok else "down",
            "detail": (
                f"{meter['used_human']} used of {meter['total_human']}"
                if storage_ok
                else "Upload directory is not writable"
            ),
        },
        {
            "name": "Uploads",
            "status": "operational" if storage_ok and MAX_UPLOAD_BYTES else "degraded",
            "detail": f"Accepting files up to {human_size(MAX_UPLOAD_BYTES)}",
        },
    ]

    if any(c["status"] == "down" for c in components):
        overall = "down"
    elif any(c["status"] == "degraded" for c in components):
        overall = "degraded"
    else:
        overall = "operational"

    return {
        "overall": overall,
        "components": components,
        "meter": meter,
        "metrics": {
            "uptime_human": _human_duration(datetime.utcnow() - APP_START),
            "stored_files": meter["files_count"],
            "stored_files_human": meter["files_human"],
            "disk_free_human": meter["disk_free_human"],
            "disk_total_human": meter["disk_total_human"],
            "max_upload_human": human_size(MAX_UPLOAD_BYTES),
            "python": platform.python_version(),
        },
        "generated_display": datetime.utcnow().strftime("%d %b %Y, %H:%M:%S UTC"),
    }


@app.route("/status")
def status():
    return render_template("status.html", status=build_status())


@app.route("/status.json")
def status_json():
    return jsonify(build_status())


# --------------------------------------------------------------------------- #
# Admin control room — a separate dashboard for the durable database
# --------------------------------------------------------------------------- #
def _redact_url(url):
    if not url:
        return f"SQLite: {SQLITE_PATH}"
    try:
        parts = urlsplit(url)
        if parts.password:
            netloc = parts.netloc.replace(f":{parts.password}@", ":****@")
            return urlunsplit(
                (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
            )
        return url
    except Exception:
        return url


def database_info():
    info = {
        "engine": database.engine,
        "requested_engine": database.requested_engine,
        "fallback_reason": database.fallback_reason,
        "url": _redact_url(database.url),
        "sqlite_path": SQLITE_PATH,
        "version": "",
        "size": 0,
        "size_human": "0 B",
        "connections": 0,
        "uptime_human": _human_duration(datetime.utcnow() - APP_START),
        "settings": {},
        "schema_version": None,
        "ok": False,
        "error": None,
    }
    try:
        db = get_db()
        info["ok"] = True
        row = db.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        info["schema_version"] = row["v"] if row else None
        if database.is_postgres:
            row = db.execute("SELECT version() AS v").fetchone()
            info["version"] = (row["v"] or "").split(" on ")[0]
            row = db.execute(
                "SELECT pg_database_size(current_database()) AS size"
            ).fetchone()
            info["size"] = row["size"] or 0
            row = db.execute(
                "SELECT COUNT(*) AS n FROM pg_stat_activity "
                "WHERE datname = current_database()"
            ).fetchone()
            info["connections"] = row["n"] or 0
            row = db.execute(
                "SELECT EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time())) "
                "AS uptime"
            ).fetchone()
            seconds = int(row["uptime"] or 0) if row else 0
            info["uptime_human"] = _human_duration(timedelta(seconds=seconds))
            settings = {}
            for key in (
                "fsync",
                "synchronous_commit",
                "full_page_writes",
                "wal_level",
                "archive_mode",
                "autovacuum",
                "max_wal_size",
                "checkpoint_completion_target",
            ):
                row = db.execute(
                    "SELECT setting, unit FROM pg_settings WHERE name = ?", (key,)
                ).fetchone()
                if row:
                    settings[key] = f"{row['setting']}{row['unit'] or ''}"
            info["settings"] = settings
        else:
            info["version"] = f"SQLite {sqlite3.sqlite_version}"
            info["size"] = (
                os.path.getsize(SQLITE_PATH) if os.path.exists(SQLITE_PATH) else 0
            )
            info["connections"] = 1
            try:
                mode = db.execute("PRAGMA journal_mode").fetchone()[0]
            except Exception:
                mode = "wal"
            info["settings"] = {
                "journal_mode": str(mode).upper(),
                "synchronous": "FULL",
                "foreign_keys": "ON",
                "busy_timeout": "20000ms",
            }
        info["size_human"] = human_size(info["size"])
    except Exception as exc:  # noqa: BLE001 - surface the real error to the admin
        info["error"] = str(exc)
    return info


def durability_warnings(info):
    warnings = []
    if info["requested_engine"] == "postgres" and info["engine"] != "postgres":
        warnings.append(
            "PostgreSQL was requested but is unreachable; the app is running on "
            f"the SQLite fallback. Reason: {info['fallback_reason']}"
        )
    if info["engine"] == "postgres":
        settings = info.get("settings", {})
        if settings.get("fsync") == "off":
            warnings.append("PostgreSQL fsync is OFF — committed data can be lost on crash.")
        if settings.get("synchronous_commit") == "off":
            warnings.append(
                "PostgreSQL synchronous_commit is OFF — recent commits are not durable."
            )
        if settings.get("full_page_writes") == "off":
            warnings.append(
                "PostgreSQL full_page_writes is OFF — torn pages can corrupt data."
            )
        if settings.get("archive_mode") not in ("on", "always"):
            warnings.append(
                "PostgreSQL archive_mode is OFF — point-in-time recovery is unavailable."
            )
    elif info["engine"] == "sqlite":
        warnings.append(
            "Running on SQLite fallback. Data is durable (WAL + synchronous=FULL) "
            "but PostgreSQL is recommended for a self-hosted production database."
        )
    return warnings


def list_backups():
    backups = []
    try:
        names = os.listdir(BACKUP_FOLDER)
    except OSError:
        return backups
    for name in names:
        if not (name.endswith(".dump") or name.endswith(".sqlite")):
            continue
        path = os.path.join(BACKUP_FOLDER, name)
        try:
            stat = os.stat(path)
        except OSError:
            continue
        backups.append(
            {
                "name": name,
                "size": stat.st_size,
                "size_human": human_size(stat.st_size),
                "created_at": datetime.utcfromtimestamp(stat.st_mtime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "kind": "PostgreSQL dump" if name.endswith(".dump") else "SQLite backup",
            }
        )
    return sorted(backups, key=lambda b: b["created_at"], reverse=True)


def create_backup():
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    os.makedirs(BACKUP_FOLDER, exist_ok=True)
    if database.is_postgres:
        name = f"makrotik-{stamp}.dump"
        dest = os.path.join(BACKUP_FOLDER, name)
        pg_dump = os.environ.get("MAKROTIK_PG_DUMP", "pg_dump")
        try:
            result = subprocess.run(
                [
                    pg_dump,
                    "--format=custom",
                    "--no-owner",
                    "--no-privileges",
                    "--file",
                    dest,
                    database.url,
                ],
                capture_output=True,
                text=True,
                timeout=1800,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "pg_dump was not found. Install the PostgreSQL client tools and "
                "make sure pg_dump is on PATH."
            )
        except subprocess.TimeoutExpired:
            _remove_safely(dest)
            raise RuntimeError("Backup timed out after 30 minutes.")
        if result.returncode != 0:
            _remove_safely(dest)
            raise RuntimeError(result.stderr.strip() or "pg_dump failed.")
    else:
        name = f"makrotik-{stamp}.sqlite"
        dest = os.path.join(BACKUP_FOLDER, name)
        src = sqlite3.connect(SQLITE_PATH)
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
            dst.commit()
        finally:
            dst.close()
            src.close()
        try:
            with open(dest, "rb") as fh:
                os.fsync(fh.fileno())
        except OSError:
            pass
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    db = get_db()
    log_event(db, actor_label(), "backup", detail=name)
    db.commit()
    return name


def run_scheduled_backup(schedule):
    db = get_db()
    started_at = now_iso()
    target = (
        backup_service.get_target(db, schedule["target_id"])
        if schedule.get("target_id")
        else None
    )
    try:
        name = create_backup()
        detail = backup_service.deliver_backup(
            os.path.join(BACKUP_FOLDER, name), target
        )
        backup_service.record_run(
            db, name, schedule.get("target_id"), "ok", detail, started_at
        )
        backup_service.mark_schedule_run(
            db, schedule["id"], schedule["interval_minutes"]
        )
        if schedule.get("retention_days"):
            removed = backup_service.prune_backups(
                BACKUP_FOLDER, schedule["retention_days"], keep_name=name
            )
            if target and target.get("kind") == "local":
                target_path = (target.get("config_data") or {}).get("path")
                if target_path:
                    removed += backup_service.prune_backups(
                        os.path.expanduser(target_path),
                        schedule["retention_days"],
                        keep_name=name,
                    )
            detail += f"; pruned {len(removed)} old backup(s)"
        log_event(
            db,
            "system:scheduler",
            "scheduled_backup",
            detail=f"{schedule['name']}: {name}; {detail}",
            category="backup",
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001 - keep the scheduler alive
        db.rollback()
        backup_service.record_run(
            db,
            None,
            schedule.get("target_id"),
            "failed",
            str(exc),
            started_at,
        )
        backup_service.mark_schedule_run(
            db, schedule["id"], schedule["interval_minutes"]
        )
        log_event(
            db,
            "system:scheduler",
            "scheduled_backup_failed",
            detail=f"{schedule['name']}: {exc}",
            severity="warning",
            category="backup",
        )
        db.commit()
        app.logger.exception("Scheduled backup failed: %s", schedule["name"])


def run_due_schedules():
    db = get_db()
    due = backup_service.due_schedules(db)
    for schedule in due:
        run_scheduled_backup(schedule)
    return len(due)


def run_lifecycle(actor="system:scheduler"):
    db = get_db()
    result = lifecycle_service.run_rules(db, actor=actor)
    db.commit()
    return result


def scheduler_loop():
    global _LAST_LIFECYCLE_RUN
    time.sleep(8)
    while True:
        try:
            with app.app_context():
                run_due_schedules()
                if time.time() - _LAST_LIFECYCLE_RUN >= 3600:
                    run_lifecycle()
                    _LAST_LIFECYCLE_RUN = time.time()
        except Exception:  # noqa: BLE001 - a scheduler must never die
            app.logger.exception("Background scheduler iteration failed.")
        time.sleep(60)


def start_scheduler():
    global _SCHEDULER_STARTED
    if _SCHEDULER_STARTED:
        return False
    if os.environ.get("MAKROTIK_DISABLE_SCHEDULER", "").lower() in (
        "1",
        "true",
        "yes",
    ):
        return False
    threading.Thread(
        target=scheduler_loop, name="makrotik-scheduler", daemon=True
    ).start()
    _SCHEDULER_STARTED = True
    return True


def run_maintenance():
    database.maintenance()
    db = get_db()
    log_event(db, actor_label(), "maintenance", detail="vacuum + analyze")
    db.commit()


def integrity_scan():
    db = get_db()
    rows = db.execute("SELECT * FROM files").fetchall()
    referenced = set()
    missing = []
    size_mismatch = []
    checksum_mismatch = []
    checked = 0
    for row in rows:
        referenced.add(row["stored_name"])
        path = file_path(row)
        if not os.path.exists(path):
            missing.append(
                {"token": row["token"], "name": row["original_name"], "path": path}
            )
            continue
        actual = os.path.getsize(path)
        if actual != row["size"]:
            size_mismatch.append(
                {
                    "token": row["token"],
                    "name": row["original_name"],
                    "expected": row["size"],
                    "actual": actual,
                }
            )
        if row["sha256"]:
            digest = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != row["sha256"]:
                checksum_mismatch.append(
                    {"token": row["token"], "name": row["original_name"]}
                )
        checked += 1
    orphans = []
    try:
        for name in os.listdir(UPLOAD_FOLDER):
            if name in referenced or name.endswith(".part"):
                continue
            path = os.path.join(UPLOAD_FOLDER, name)
            if os.path.isfile(path):
                orphans.append(
                    {"name": name, "size_human": human_size(os.path.getsize(path))}
                )
    except OSError:
        pass
    result = {
        "scanned_at": now_iso(),
        "records": len(rows),
        "checked": checked,
        "missing": missing,
        "size_mismatch": size_mismatch,
        "checksum_mismatch": checksum_mismatch,
        "orphans": orphans,
        "ok": not (missing or size_mismatch or checksum_mismatch),
    }
    set_setting(db, "last_integrity_scan", json.dumps(result))
    log_event(
        db,
        actor_label(),
        "integrity_scan",
        detail=(
            f"{len(rows)} records, {len(missing)} missing, "
            f"{len(orphans)} orphans, {len(checksum_mismatch)} checksum errors"
        ),
    )
    db.commit()
    return result


def last_integrity_scan():
    raw = get_setting(get_db(), "last_integrity_scan")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def purge_archived(days):
    db = get_db()
    if days > 0:
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat(
            timespec="seconds"
        )
        rows = db.execute(
            "SELECT * FROM files WHERE deleted_at IS NOT NULL AND deleted_at <= ?",
            (cutoff,),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM files WHERE deleted_at IS NOT NULL"
        ).fetchall()
    for row in rows:
        db.execute("DELETE FROM files WHERE token = ?", (row["token"],))
    if rows:
        log_event(
            db,
            actor_label(),
            "purge_archived",
            detail=f"permanently removed {len(rows)} archived record(s)",
        )
    db.commit()
    for row in rows:
        _remove_safely(file_path(row))
    return len(rows)


def admin_files(status="all", query=""):
    where = []
    params = []
    if status == "active":
        where.append("f.deleted_at IS NULL")
    elif status == "archived":
        where.append("f.deleted_at IS NOT NULL")
    if query:
        where.append(
            "(LOWER(f.original_name) LIKE LOWER(?) OR LOWER(f.token) LIKE LOWER(?))"
        )
        params.extend([f"%{query}%", f"%{query}%"])
    sql = (
        "SELECT f.*, u.username AS owner_name FROM files f "
        "LEFT JOIN users u ON u.id = f.owner_id"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY f.created_at DESC LIMIT 300"
    rows = get_db().execute(sql, params).fetchall()
    result = []
    for row in rows:
        result.append(
            {
                "token": row["token"],
                "name": row["original_name"],
                "size_human": human_size(row["size"]),
                "owner": row["owner_name"] or "anonymous",
                "downloads": row["downloads"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "deleted_at": row["deleted_at"],
                "delete_reason": row["delete_reason"],
                "sha256": row["sha256"],
                "tags": row["tags"] or "",
                "share_url": url_for("share", token=row["token"], _external=True),
            }
        )
    return result


def admin_audit(limit=400):
    rows = get_db().execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(row) for row in rows]


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if is_admin():
        return redirect(url_for("admin_dashboard"))
    next_url = request.values.get("next", "")
    needs_totp = False
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        expected_user = get_setting(db, "admin_username", ADMIN_USERNAME)
        account = admin_services.get_account_by_username(db, username)
        env_primary = bool(
            ADMIN_PASSWORD_ENV
            and hmac.compare_digest(username, expected_user or "")
        )
        if env_primary and not account:
            primary_hash = get_setting(db, "admin_password_hash") or generate_password_hash(
                ADMIN_PASSWORD_ENV
            )
            admin_services.ensure_primary_account(db, expected_user, primary_hash)
            db.commit()
            account = admin_services.get_account_by_username(db, username)
        password_ok = False
        if account and account["active"]:
            if env_primary:
                password_ok = hmac.compare_digest(password, ADMIN_PASSWORD_ENV)
            else:
                password_ok = admin_services.verify_password(account, password)
        if admin_locked(ip):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
        elif account and admin_services.account_locked(account):
            flash("This admin account is temporarily locked.", "error")
        elif not password_ok:
            record_admin_failure(ip)
            if account:
                admin_services.record_failed_login(db, account)
            log_event(
                db,
                "anonymous",
                "admin_login_failed",
                detail=f"{username or 'unknown'} from {ip}",
                severity="warning",
                category="auth",
            )
            db.commit()
            flash("Invalid admin credentials.", "error")
        else:
            totp_ok = True
            code = request.form.get("totp_code", "").strip()
            if account["totp_enabled"]:
                needs_totp = True
                if not code:
                    totp_ok = False
                    flash("Enter the code from your authenticator app.", "info")
                else:
                    totp_ok = totp.verify_code(account["totp_secret"], code)
                    if not totp_ok and account["recovery_codes"]:
                        used, remaining = totp.verify_recovery_code(
                            account["recovery_codes"], code
                        )
                        if used:
                            admin_services.set_recovery_codes(
                                db, account["id"], remaining
                            )
                            totp_ok = True
                            log_event(
                                db,
                                f"admin:{account['username']}",
                                "admin_recovery_code_used",
                                detail=f"{ip} used a recovery code",
                                severity="warning",
                                category="auth",
                            )
            if not totp_ok:
                record_admin_failure(ip)
                admin_services.record_failed_login(db, account)
                if code:
                    log_event(
                        db,
                        "anonymous",
                        "admin_2fa_failed",
                        detail=f"{username or 'unknown'} from {ip}",
                        severity="warning",
                        category="auth",
                    )
                db.commit()
            else:
                token, expires = admin_services.create_session(
                    db,
                    account["id"],
                    ip=ip,
                    user_agent=request.headers.get("User-Agent", ""),
                    hours=ADMIN_SESSION_HOURS,
                )
                admin_services.record_login(db, account["id"])
                session["admin_authenticated"] = True
                session["admin_username"] = account["username"]
                session["admin_session_id"] = token
                session["admin_account_id"] = account["id"]
                _ADMIN_FAILURES.pop(ip, None)
                log_event(
                    db,
                    f"admin:{account['username']}",
                    "admin_login",
                    detail=f"successful sign-in from {ip}; expires {expires}",
                    category="auth",
                )
                db.commit()
                if next_url.startswith("/admin"):
                    return redirect(next_url)
                return redirect(url_for("admin_dashboard"))
    return render_template(
        "admin/login.html",
        next=next_url,
        needs_totp=needs_totp,
        login_username=request.form.get("username", ""),
    )


@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    db = get_db()
    admin = current_admin()
    log_event(db, actor_label(), "admin_logout", detail="signed out", category="auth")
    if admin:
        admin_services.revoke_session(db, admin["id"])
    db.commit()
    _clear_admin_auth()
    flash("Signed out of the admin control room.", "success")
    return redirect(url_for("admin_login"))


@app.route("/admin/")
@permission_required("view_dashboard")
def admin_dashboard():
    info = database_info()
    storage = storage_stats()
    db = get_db()
    users = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    events = db.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"]
    downloads = db.execute(
        "SELECT COALESCE(SUM(downloads), 0) AS n FROM files"
    ).fetchone()["n"]
    recent = db.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 8"
    ).fetchall()
    return render_template(
        "admin/dashboard.html",
        info=info,
        storage=storage,
        breakdown=storage_breakdown(info),
        meter=storage_meter(),
        warnings=durability_warnings(info),
        users=users,
        events=events,
        downloads=downloads,
        recent=[dict(r) for r in recent],
        scan=last_integrity_scan(),
        backups=list_backups()[:3],
        drives=list_drives(),
        traffic=analytics_service.traffic_summary(db, 14),
        host=infra_service.host_info(UPLOAD_FOLDER, BACKUP_FOLDER),
        audit_verification=last_audit_verification(),
    )


@app.route("/admin/files")
@permission_required("view_files")
def admin_files_page():
    status = request.args.get("status", "all")
    query = request.args.get("q", "").strip()
    return render_template(
        "admin/files.html",
        files=admin_files(status, query),
        status=status,
        query=query,
    )


@app.route("/admin/files/<token>/restore", methods=["POST"])
@permission_required("manage_files")
def admin_restore_file(token):
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE token = ?", (token,)).fetchone()
    if row is None:
        abort(404)
    db.execute(
        "UPDATE files SET deleted_at = NULL, delete_reason = NULL, expires_at = NULL "
        "WHERE token = ?",
        (token,),
    )
    log_event(db, actor_label(), "restore", token, row["original_name"])
    db.commit()
    flash(f"Restored {row['original_name']} with no expiry.", "success")
    return redirect(url_for("admin_files_page"))


@app.route("/admin/files/<token>/purge", methods=["POST"])
@permission_required("manage_files")
def admin_purge_file(token):
    if request.form.get("confirm") != token:
        flash("Type the file token to confirm permanent deletion.", "error")
        return redirect(url_for("admin_files_page"))
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE token = ?", (token,)).fetchone()
    if row is None:
        abort(404)
    purge_file(row)
    flash(f"Permanently removed {row['original_name']}.", "success")
    return redirect(url_for("admin_files_page"))


@app.route("/admin/files/purge-archived", methods=["POST"])
@permission_required("manage_files")
def admin_purge_archived():
    if request.form.get("confirm") != "purge":
        flash("Confirm the purge before running it.", "error")
        return redirect(url_for("admin_settings"))
    try:
        days = max(0, int(request.form.get("days", "0")))
    except ValueError:
        days = 0
    count = purge_archived(days)
    flash(f"Permanently purged {count} archived record(s).", "success")
    return redirect(url_for("admin_settings"))


@app.route("/admin/files/<token>/tags", methods=["POST"])
@permission_required("manage_files")
def admin_file_tags(token):
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE token = ?", (token,)).fetchone()
    if row is None:
        abort(404)
    tags = lifecycle_service.update_tags(
        db, token, request.form.get("tags", ""), actor_label()
    )
    db.commit()
    flash(f"Tags updated for {row['original_name']}: {tags or 'none'}.", "success")
    return redirect(url_for("admin_files_page"))


def last_audit_verification():
    raw = get_setting(get_db(), "audit_verification")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


@app.route("/admin/audit")
@permission_required("view_audit")
def admin_audit_page():
    db = get_db()
    events = audit_service.query_events(db, request.args)
    return render_template(
        "admin/audit.html",
        events=events,
        filters=request.args,
        severities=audit_service.SEVERITIES,
        categories=audit_service.CATEGORIES,
        verification=last_audit_verification(),
    )


@app.route("/admin/audit/verify", methods=["POST"])
@permission_required("view_audit")
def admin_audit_verify():
    db = get_db()
    result = audit_service.verify_chain(db)
    set_setting(db, "audit_verification", json.dumps(result))
    log_event(
        db,
        actor_label(),
        "audit_verify",
        detail=(
            f"{result['checked']} hashed entries checked; "
            f"{result['legacy']} legacy rows; "
            f"{'clean' if result['ok'] else 'BROKEN CHAIN'}"
        ),
        severity="critical" if not result["ok"] else "notice",
        category="security",
    )
    db.commit()
    flash(
        "Audit chain verified clean."
        if result["ok"]
        else "Audit chain verification found a problem.",
        "success" if result["ok"] else "error",
    )
    return redirect(url_for("admin_audit_page"))


@app.route("/admin/audit/export")
@permission_required("export_audit")
def admin_audit_export():
    fmt = request.args.get("format", "json").lower()
    if fmt not in ("json", "csv"):
        fmt = "json"
    db = get_db()
    body, mimetype = audit_service.export_rows(db, request.args, fmt=fmt)
    log_event(
        db,
        actor_label(),
        "audit_export",
        detail=f"{fmt} export with filters: {dict(request.args)}",
        severity="notice",
        category="audit",
    )
    db.commit()
    filename = f"makrotik-audit-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.{fmt}"
    return Response(
        body,
        mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/admin/backups")
@permission_required("view_backups")
def admin_backups_page():
    db = get_db()
    return render_template(
        "admin/backups.html",
        backups=list_backups(),
        info=database_info(),
        targets=backup_service.list_targets(db),
        schedules=backup_service.list_schedules(db),
        runs=backup_service.list_runs(db),
        can_manage=admin_has("manage_backups"),
    )


@app.route("/admin/backups/create", methods=["POST"])
@permission_required("manage_backups")
def admin_create_backup():
    try:
        name = create_backup()
        flash(f"Backup created: {name}", "success")
    except Exception as exc:  # noqa: BLE001 - show the operator the real reason
        flash(f"Backup failed: {exc}", "error")
    return redirect(url_for("admin_backups_page"))


@app.route("/admin/backups/targets", methods=["POST"])
@permission_required("manage_backups")
def admin_create_backup_target():
    name = request.form.get("name", "").strip()
    kind = request.form.get("kind", "local").strip().lower()
    if not name or kind not in ("local", "s3", "sftp"):
        flash("Enter a target name and choose local, S3 or SFTP.", "error")
        return redirect(url_for("admin_backups_page"))
    config = {}
    if kind == "local":
        config["path"] = request.form.get("path", "").strip()
    elif kind == "s3":
        config = {
            "bucket": request.form.get("bucket", "").strip(),
            "prefix": request.form.get("prefix", "").strip(),
            "region": request.form.get("region", "").strip(),
            "endpoint_url": request.form.get("endpoint_url", "").strip(),
        }
    else:
        config = {
            "host": request.form.get("host", "").strip(),
            "port": request.form.get("port", "22").strip(),
            "username": request.form.get("username", "").strip(),
            "password": request.form.get("password", ""),
            "key_path": request.form.get("key_path", "").strip(),
            "path": request.form.get("remote_path", "/").strip() or "/",
        }
    db = get_db()
    target_id = backup_service.create_target(db, name, kind, config)
    log_event(
        db,
        actor_label(),
        "backup_target_created",
        detail=f"{name} ({kind})",
        category="backup",
    )
    db.commit()
    flash(f"Backup target #{target_id} created.", "success")
    return redirect(url_for("admin_backups_page"))


@app.route("/admin/backups/targets/<int:target_id>/delete", methods=["POST"])
@permission_required("manage_backups")
def admin_delete_backup_target(target_id):
    db = get_db()
    target = backup_service.get_target(db, target_id)
    if not target:
        abort(404)
    backup_service.delete_target(db, target_id)
    log_event(
        db,
        actor_label(),
        "backup_target_deleted",
        detail=target["name"],
        severity="critical",
        category="backup",
    )
    db.commit()
    flash(f"Backup target {target['name']} removed.", "success")
    return redirect(url_for("admin_backups_page"))


@app.route("/admin/backups/schedules", methods=["POST"])
@permission_required("manage_backups")
def admin_create_backup_schedule():
    try:
        interval = int(request.form.get("interval_minutes", "1440"))
        retention = int(request.form.get("retention_days", "30"))
    except ValueError:
        flash("Interval and retention must be numbers.", "error")
        return redirect(url_for("admin_backups_page"))
    target_id = request.form.get("target_id", "").strip()
    db = get_db()
    schedule_id = backup_service.create_schedule(
        db,
        request.form.get("name", ""),
        int(target_id) if target_id else None,
        interval,
        retention,
    )
    log_event(
        db,
        actor_label(),
        "backup_schedule_created",
        detail=f"schedule #{schedule_id} every {interval} minutes",
        category="backup",
    )
    db.commit()
    flash(f"Backup schedule #{schedule_id} created.", "success")
    return redirect(url_for("admin_backups_page"))


@app.route("/admin/backups/schedules/<int:schedule_id>/toggle", methods=["POST"])
@permission_required("manage_backups")
def admin_toggle_backup_schedule(schedule_id):
    db = get_db()
    enabled = backup_service.toggle_schedule(db, schedule_id)
    log_event(
        db,
        actor_label(),
        "backup_schedule_toggled",
        detail=f"schedule #{schedule_id} enabled={enabled}",
        category="backup",
    )
    db.commit()
    flash(f"Backup schedule {'enabled' if enabled else 'disabled'}.", "success")
    return redirect(url_for("admin_backups_page"))


@app.route("/admin/backups/schedules/<int:schedule_id>/delete", methods=["POST"])
@permission_required("manage_backups")
def admin_delete_backup_schedule(schedule_id):
    db = get_db()
    backup_service.delete_schedule(db, schedule_id)
    log_event(
        db,
        actor_label(),
        "backup_schedule_deleted",
        detail=f"schedule #{schedule_id}",
        severity="critical",
        category="backup",
    )
    db.commit()
    flash("Backup schedule removed.", "success")
    return redirect(url_for("admin_backups_page"))


@app.route("/admin/backups/run-due", methods=["POST"])
@permission_required("manage_backups")
def admin_run_due_backups():
    count = run_due_schedules()
    flash(f"Ran {count} due backup schedule(s).", "success")
    return redirect(url_for("admin_backups_page"))


@app.route("/admin/backups/<name>/test", methods=["POST"])
@permission_required("manage_backups")
def admin_test_backup(name):
    if os.path.basename(name) != name:
        abort(404)
    path = os.path.join(BACKUP_FOLDER, name)
    if not os.path.isfile(path):
        abort(404)
    started = now_iso()
    ok, detail = backup_service.test_backup(path, name)
    db = get_db()
    backup_service.record_run(
        db, name, None, "verified" if ok else "failed", detail, started
    )
    log_event(
        db,
        actor_label(),
        "backup_verified" if ok else "backup_verification_failed",
        detail=f"{name}: {detail}",
        severity="notice" if ok else "warning",
        category="backup",
    )
    db.commit()
    flash(
        f"{name}: {detail}",
        "success" if ok else "error",
    )
    return redirect(url_for("admin_backups_page"))


@app.route("/admin/backups/<name>")
@permission_required("view_backups")
def admin_download_backup(name):
    if os.path.basename(name) != name:
        abort(404)
    path = os.path.join(BACKUP_FOLDER, name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=name)


@app.route("/admin/integrity", methods=["POST"])
@permission_required("manage_settings")
def admin_integrity():
    result = integrity_scan()
    if result["ok"]:
        flash(
            f"Integrity scan clean: {result['records']} records verified, "
            f"{len(result['orphans'])} orphan file(s) found.",
            "success",
        )
    else:
        flash(
            f"Integrity scan found issues: {len(result['missing'])} missing, "
            f"{len(result['size_mismatch'])} size mismatches, "
            f"{len(result['checksum_mismatch'])} checksum mismatches.",
            "error",
        )
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/maintenance", methods=["POST"])
@permission_required("manage_settings")
def admin_maintenance():
    try:
        run_maintenance()
        flash("Maintenance complete: database vacuumed and analyzed.", "success")
    except Exception as exc:  # noqa: BLE001
        flash(f"Maintenance failed: {exc}", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/lifecycle")
@permission_required("view_lifecycle")
def admin_lifecycle_page():
    db = get_db()
    rules = lifecycle_service.list_rules(db)
    active = db.execute(
        "SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NULL"
    ).fetchone()["n"]
    tagged = db.execute(
        "SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NULL "
        "AND tags IS NOT NULL AND tags <> ''"
    ).fetchone()["n"]
    return render_template(
        "admin/lifecycle.html",
        rules=rules,
        active=active,
        tagged=tagged,
        condition_types=lifecycle_service.CONDITION_TYPES,
        can_manage=admin_has("manage_lifecycle"),
    )


@app.route("/admin/lifecycle/rules", methods=["POST"])
@permission_required("manage_lifecycle")
def admin_create_lifecycle_rule():
    db = get_db()
    try:
        rule_id = lifecycle_service.create_rule(
            db,
            request.form.get("name", ""),
            request.form.get("condition_type", ""),
            request.form.get("condition_value", ""),
            "archive",
        )
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin_lifecycle_page"))
    log_event(
        db,
        actor_label(),
        "lifecycle_rule_created",
        detail=f"rule #{rule_id}: {request.form.get('name', '')}",
        category="lifecycle",
    )
    db.commit()
    flash(f"Lifecycle rule #{rule_id} created.", "success")
    return redirect(url_for("admin_lifecycle_page"))


@app.route("/admin/lifecycle/rules/<int:rule_id>/toggle", methods=["POST"])
@permission_required("manage_lifecycle")
def admin_toggle_lifecycle_rule(rule_id):
    db = get_db()
    enabled = lifecycle_service.toggle_rule(db, rule_id)
    log_event(
        db,
        actor_label(),
        "lifecycle_rule_toggled",
        detail=f"rule #{rule_id} enabled={enabled}",
        category="lifecycle",
    )
    db.commit()
    flash(f"Lifecycle rule {'enabled' if enabled else 'disabled'}.", "success")
    return redirect(url_for("admin_lifecycle_page"))


@app.route("/admin/lifecycle/rules/<int:rule_id>/delete", methods=["POST"])
@permission_required("manage_lifecycle")
def admin_delete_lifecycle_rule(rule_id):
    db = get_db()
    lifecycle_service.delete_rule(db, rule_id)
    log_event(
        db,
        actor_label(),
        "lifecycle_rule_deleted",
        detail=f"rule #{rule_id}",
        severity="critical",
        category="lifecycle",
    )
    db.commit()
    flash("Lifecycle rule removed.", "success")
    return redirect(url_for("admin_lifecycle_page"))


@app.route("/admin/lifecycle/run", methods=["POST"])
@permission_required("manage_lifecycle")
def admin_run_lifecycle():
    result = run_lifecycle(actor_label())
    flash(
        f"Lifecycle run complete: {result['matched']} file(s) archived "
        f"by {result['rules']} active rule(s).",
        "success",
    )
    return redirect(url_for("admin_lifecycle_page"))


@app.route("/admin/analytics")
@permission_required("view_analytics")
def admin_analytics_page():
    try:
        days = int(request.args.get("days", "30"))
    except ValueError:
        days = 30
    db = get_db()
    lifetime = db.execute(
        "SELECT COALESCE(SUM(downloads), 0) AS n, COUNT(*) AS files FROM files"
    ).fetchone()
    return render_template(
        "admin/analytics.html",
        traffic=analytics_service.traffic_summary(db, days),
        days=days,
        lifetime=lifetime,
    )


@app.route("/admin/infrastructure")
@permission_required("view_infrastructure")
def admin_infrastructure_page():
    info = database_info()
    return render_template(
        "admin/infrastructure.html",
        info=info,
        host=infra_service.host_info(UPLOAD_FOLDER, BACKUP_FOLDER),
        storage=storage_stats(),
        warnings=durability_warnings(info),
        drives=list_drives(),
    )


@app.route("/admin/accounts")
@permission_required("manage_admins")
def admin_accounts_page():
    db = get_db()
    return render_template(
        "admin/accounts.html",
        accounts=admin_services.list_accounts(db),
        roles=admin_services.ROLES,
        role_labels=admin_services.ROLE_LABELS,
        role_permissions=admin_services.ROLE_PERMISSIONS,
        primary_username=get_setting(db, "admin_username", ADMIN_USERNAME),
        current_account_id=current_admin()["account_id"],
    )


@app.route("/admin/accounts", methods=["POST"])
@permission_required("manage_admins")
def admin_create_account():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "read_only")
    db = get_db()
    if not (3 <= len(username) <= 32):
        flash("Admin username must be 3–32 characters.", "error")
    elif role not in admin_services.ROLES:
        flash("Choose a valid role.", "error")
    elif len(password) < 10:
        flash("Admin password must be at least 10 characters.", "error")
    elif admin_services.username_exists(db, username):
        flash("That admin username already exists.", "error")
    else:
        account_id = admin_services.create_account(db, username, password, role)
        log_event(
            db,
            actor_label(),
            "admin_account_created",
            detail=f"{username} ({role})",
            severity="notice",
            category="security",
        )
        db.commit()
        flash(f"Admin account {username} created.", "success")
        return redirect(url_for("admin_accounts_page"))
    return redirect(url_for("admin_accounts_page"))


@app.route("/admin/accounts/<int:account_id>/update", methods=["POST"])
@permission_required("manage_admins")
def admin_update_account(account_id):
    db = get_db()
    account = admin_services.get_account(db, account_id)
    if not account:
        abort(404)
    primary_username = get_setting(db, "admin_username", ADMIN_USERNAME)
    if account["username"].lower() == (primary_username or "").lower():
        flash("The primary environment admin cannot be changed here.", "error")
        return redirect(url_for("admin_accounts_page"))
    role = request.form.get("role", account["role"])
    active = request.form.get("active") == "on"
    password = request.form.get("password", "")
    if role not in admin_services.ROLES:
        flash("Choose a valid role.", "error")
        return redirect(url_for("admin_accounts_page"))
    if password and len(password) < 10:
        flash("New password must be at least 10 characters.", "error")
        return redirect(url_for("admin_accounts_page"))
    if (
        account["role"] == "super_admin"
        and (role != "super_admin" or not active)
        and admin_services.super_admin_count(db) <= 1
    ):
        flash("At least one active super admin is required.", "error")
        return redirect(url_for("admin_accounts_page"))
    admin_services.update_account(
        db, account_id, role=role, active=active, password=password or None
    )
    if password or role != account["role"] or bool(account["active"]) != active:
        admin_services.revoke_other_sessions(db, account_id)
    log_event(
        db,
        actor_label(),
        "admin_account_updated",
        detail=f"{account['username']}: role={role}, active={active}, password_reset={bool(password)}",
        severity="critical" if password else "notice",
        category="security",
    )
    db.commit()
    flash(f"Admin account {account['username']} updated.", "success")
    return redirect(url_for("admin_accounts_page"))


@app.route("/admin/accounts/<int:account_id>/delete", methods=["POST"])
@permission_required("manage_admins")
def admin_delete_account(account_id):
    db = get_db()
    account = admin_services.get_account(db, account_id)
    if not account:
        abort(404)
    primary_username = get_setting(db, "admin_username", ADMIN_USERNAME)
    if account["username"].lower() == (primary_username or "").lower():
        flash("The primary environment admin cannot be deleted.", "error")
        return redirect(url_for("admin_accounts_page"))
    if account["id"] == current_admin()["account_id"]:
        flash("You cannot delete the account you are signed in with.", "error")
        return redirect(url_for("admin_accounts_page"))
    if (
        account["role"] == "super_admin"
        and admin_services.super_admin_count(db) <= 1
    ):
        flash("At least one active super admin is required.", "error")
        return redirect(url_for("admin_accounts_page"))
    admin_services.delete_account(db, account_id)
    log_event(
        db,
        actor_label(),
        "admin_account_deleted",
        detail=account["username"],
        severity="critical",
        category="security",
    )
    db.commit()
    flash(f"Admin account {account['username']} deleted.", "success")
    return redirect(url_for("admin_accounts_page"))


@app.route("/admin/sessions")
@permission_required("manage_sessions")
def admin_sessions_page():
    db = get_db()
    admin_services.purge_expired_sessions(db)
    db.commit()
    return render_template(
        "admin/sessions.html",
        sessions=admin_services.list_sessions(db),
        current_token=session.get("admin_session_id"),
        current_account_id=current_admin()["account_id"],
        now=now_iso(),
    )


@app.route("/admin/sessions/<session_id>/revoke", methods=["POST"])
@permission_required("manage_sessions")
def admin_revoke_session(session_id):
    db = get_db()
    admin_services.revoke_session(db, session_id)
    log_event(
        db,
        actor_label(),
        "admin_session_revoked",
        detail=session_id[:12] + "…",
        severity="critical",
        category="security",
    )
    db.commit()
    flash("Admin session revoked.", "success")
    if session_id == session.get("admin_session_id"):
        _clear_admin_auth()
        return redirect(url_for("admin_login"))
    return redirect(url_for("admin_sessions_page"))


@app.route("/admin/sessions/revoke-others", methods=["POST"])
@permission_required("manage_sessions")
def admin_revoke_other_sessions():
    db = get_db()
    admin_services.revoke_other_sessions(
        db, current_admin()["account_id"], keep_token=session.get("admin_session_id")
    )
    log_event(
        db,
        actor_label(),
        "admin_sessions_revoked",
        detail="all other sessions for this account",
        severity="critical",
        category="security",
    )
    db.commit()
    flash("All other sessions for your account were revoked.", "success")
    return redirect(url_for("admin_sessions_page"))


def _security_context(**extra):
    db = get_db()
    account = admin_services.get_account(db, current_admin()["account_id"])
    context = {
        "security_account": account,
        "pending_secret": None,
        "provisioning_uri": None,
        "new_recovery_codes": None,
        "sessions": admin_services.list_sessions(db, account["id"]),
        "current_token": session.get("admin_session_id"),
    }
    context.update(extra)
    return context


@app.route("/admin/security")
@admin_required
def admin_security_page():
    return render_template("admin/security.html", **_security_context())


@app.route("/admin/security/2fa/start", methods=["POST"])
@admin_required
def admin_start_2fa():
    db = get_db()
    account = admin_services.get_account(db, current_admin()["account_id"])
    if account["totp_enabled"]:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("admin_security_page"))
    secret = totp.generate_secret()
    admin_services.set_totp_secret(db, account["id"], secret)
    log_event(
        db,
        actor_label(),
        "admin_2fa_started",
        detail="new TOTP secret generated",
        category="security",
    )
    db.commit()
    return render_template(
        "admin/security.html",
        **_security_context(
            pending_secret=secret,
            provisioning_uri=totp.provisioning_uri(secret, account["username"]),
        ),
    )


@app.route("/admin/security/2fa/enable", methods=["POST"])
@admin_required
def admin_enable_2fa():
    db = get_db()
    account = admin_services.get_account(db, current_admin()["account_id"])
    code = request.form.get("totp_code", "")
    if not account["totp_secret"]:
        flash("Start the 2FA setup first.", "error")
        return redirect(url_for("admin_security_page"))
    if not totp.verify_code(account["totp_secret"], code):
        flash("That authenticator code is not valid. Try the current code.", "error")
        return redirect(url_for("admin_security_page"))
    codes = totp.generate_recovery_codes()
    admin_services.enable_totp(
        db, account["id"], totp.hash_recovery_codes(codes)
    )
    log_event(
        db,
        actor_label(),
        "admin_2fa_enabled",
        detail="TOTP enabled and recovery codes generated",
        severity="notice",
        category="security",
    )
    db.commit()
    return render_template(
        "admin/security.html",
        **_security_context(new_recovery_codes=codes),
    )


@app.route("/admin/security/2fa/disable", methods=["POST"])
@admin_required
def admin_disable_2fa():
    db = get_db()
    account = admin_services.get_account(db, current_admin()["account_id"])
    if not account["totp_enabled"]:
        flash("Two-factor authentication is not enabled.", "info")
        return redirect(url_for("admin_security_page"))
    if not verify_current_password(request.form.get("password", "")):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("admin_security_page"))
    code = request.form.get("totp_code", "")
    if not (
        totp.verify_code(account["totp_secret"], code)
        or totp.verify_recovery_code(account["recovery_codes"], code)[0]
    ):
        flash("Enter a valid authenticator or recovery code.", "error")
        return redirect(url_for("admin_security_page"))
    admin_services.disable_totp(db, account["id"])
    log_event(
        db,
        actor_label(),
        "admin_2fa_disabled",
        detail="TOTP disabled",
        severity="critical",
        category="security",
    )
    db.commit()
    flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("admin_security_page"))


@app.route("/admin/security/recovery-codes", methods=["POST"])
@admin_required
def admin_regenerate_recovery_codes():
    db = get_db()
    account = admin_services.get_account(db, current_admin()["account_id"])
    if not account["totp_enabled"]:
        flash("Enable two-factor authentication first.", "error")
        return redirect(url_for("admin_security_page"))
    if not verify_current_password(request.form.get("password", "")):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("admin_security_page"))
    codes = totp.generate_recovery_codes()
    admin_services.set_recovery_codes(
        db, account["id"], totp.hash_recovery_codes(codes)
    )
    log_event(
        db,
        actor_label(),
        "admin_recovery_codes_regenerated",
        detail="recovery codes replaced",
        severity="critical",
        category="security",
    )
    db.commit()
    return render_template(
        "admin/security.html",
        **_security_context(new_recovery_codes=codes),
    )


@app.route("/admin/settings")
@permission_required("view_settings")
def admin_settings():
    info = database_info()
    return render_template(
        "admin/settings.html",
        info=info,
        storage=storage_stats(),
        retention=get_setting(get_db(), "archive_retention_days", "0"),
        admin_username=current_admin()["username"],
        env_password=bool(
            ADMIN_PASSWORD_ENV
            and current_admin()["username"].lower()
            == (get_setting(get_db(), "admin_username", ADMIN_USERNAME) or "").lower()
        ),
        credentials_file=ADMIN_CREDENTIALS_FILE,
    )


@app.route("/admin/settings/password", methods=["POST"])
@permission_required("manage_settings")
def admin_change_password():
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")
    expected_user = get_setting(get_db(), "admin_username", ADMIN_USERNAME)
    env_primary = bool(
        ADMIN_PASSWORD_ENV
        and current_admin()["username"].lower() == (expected_user or "").lower()
    )
    if env_primary:
        flash(
            "The admin password is managed by MAKROTIK_ADMIN_PASSWORD in .env. "
            "Change it there and restart the app.",
            "error",
        )
    elif not verify_current_password(current):
        flash("Current admin password is incorrect.", "error")
    elif len(new) < 10:
        flash("New password must be at least 10 characters.", "error")
    elif new != confirm:
        flash("New passwords do not match.", "error")
    else:
        set_admin_password(new)
        flash("Admin password updated.", "success")
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/retention", methods=["POST"])
@permission_required("manage_settings")
def admin_set_retention():
    try:
        days = int(request.form.get("days", "0"))
    except ValueError:
        days = 0
    days = max(0, min(days, 3650))
    db = get_db()
    set_setting(db, "archive_retention_days", str(days))
    log_event(db, actor_label(), "setting_changed", detail=f"archive_retention_days={days}")
    db.commit()
    flash(f"Archive retention set to {days or 'never'} day(s).", "success")
    return redirect(url_for("admin_settings"))


# Best-effort schema setup at startup. Even if this fails (locked file, weird
# FS state), every request re-checks the schema lazily in get_db(), so the app
# recovers instead of refusing to start.
try:
    init_db()
except Exception:
    app.logger.exception("Initial database setup failed; will retry lazily.")

if __name__ == "__main__":
    start_scheduler()
    app.run(
        host=os.environ.get("MAKROTIK_HOST", "0.0.0.0"),
        port=int(os.environ.get("MAKROTIK_PORT", "5000")),
        debug=os.environ.get("MAKROTIK_DEBUG", "").lower() in ("1", "true", "yes"),
    )