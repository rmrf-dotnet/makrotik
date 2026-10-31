#!/usr/bin/env python3
"""Console setup application for Makrotik Share on Ubuntu/Debian servers.

Run as root:
    sudo python3 setup.py
"""

import getpass
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
DEFAULT_INSTALL_DIR = Path("/opt/makrotik")
SERVICE_NAME = "makrotik"
SERVICE_FILE = Path("/etc/systemd/system") / f"{SERVICE_NAME}.service"
CLI_FILE = Path("/usr/local/bin/makrotik")


def run(cmd, check=True, input_text=None, capture=False):
    return subprocess.run(
        cmd,
        check=check,
        input=input_text,
        text=True,
        capture_output=capture,
    )


def prompt(text, default=None, secret=False):
    suffix = f" [{default}]" if default not in (None, "") else ""
    if secret:
        value = getpass.getpass(f"{text}{suffix}: ")
    else:
        value = input(f"{text}{suffix}: ")
    value = value.strip()
    if not value and default is not None:
        return str(default)
    return value


def require_root():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("This setup must run as root. Re-run with: sudo python3 setup.py")
        sys.exit(1)


def ensure_packages():
    print("\n[1/8] Installing system packages (python3, venv, postgres client)...")
    run(["apt-get", "update", "-qq"])
    run(["apt-get", "install", "-y", "-qq",
         "python3", "python3-venv", "python3-pip",
         "postgresql", "postgresql-client", "git", "curl"])
    print("Packages ready.")


def install_files(install_dir):
    print(f"\n[2/8] Installing application into {install_dir} ...")
    install_dir = Path(install_dir)
    if install_dir.exists():
        answer = prompt(f"{install_dir} already exists. Overwrite? (y/N)", "N")
        if answer.lower() not in ("y", "yes"):
            print("Aborted.")
            sys.exit(1)
        shutil.rmtree(install_dir)
    shutil.copytree(REPO_DIR, install_dir, symlinks=True,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "venv",
                                                 "instance", "uploads", "backups"))
    for sub in ("instance", "uploads", "backups"):
        (install_dir / sub).mkdir(parents=True, exist_ok=True)
    print("Files installed.")


def configure_env(install_dir):
    print("\n[3/8] Configuring environment (.env) ...")
    install_dir = Path(install_dir)
    use_pg = prompt("Use PostgreSQL for durable storage? (Y/n)", "Y").lower() in ("y", "yes", "")
    if use_pg:
        pg_user = prompt("PostgreSQL user", "makrotik")
        pg_db = prompt("PostgreSQL database", "makrotik")
        pg_pass = prompt("PostgreSQL password", "change-me-now", secret=True)
        db_url = f"postgresql://{pg_user}:{pg_pass}@127.0.0.1:5432/{pg_db}"
        # create role/db
        try:
            run(["sudo", "-u", "postgres", "psql", "-c",
                 f"CREATE USER {pg_user} WITH PASSWORD '{pg_pass}';"], check=False, capture=True)
            run(["sudo", "-u", "postgres", "psql", "-c",
                 f"CREATE DATABASE {pg_db} OWNER {pg_user};"], check=False, capture=True)
            run(["sudo", "-u", "postgres", "psql", "-d", pg_db, "-c",
                 f"GRANT ALL PRIVILEGES ON DATABASE {pg_db} TO {pg_user};"], check=False, capture=True)
            print("PostgreSQL role/database ensured.")
        except Exception as exc:
            print(f"PostgreSQL setup warning: {exc}")
    else:
        db_url = ""
    admin_user = prompt("Admin username", "admin")
    admin_pass = prompt("Admin password (12+ chars)", "", secret=True)
    while len(admin_pass) < 10:
        print("Password must be at least 10 characters.")
        admin_pass = prompt("Admin password (12+ chars)", "", secret=True)
    host = prompt("Bind host", "0.0.0.0")
    port = prompt("Bind port", "5000")
    debug = prompt("Enable debug mode? (y/N)", "N")
    lines = [
        f"MAKROTIK_DATABASE_URL={db_url}",
        f"MAKROTIK_ADMIN_USER={admin_user}",
        f"MAKROTIK_ADMIN_PASSWORD={admin_pass}",
        f"MAKROTIK_HOST={host}",
        f"MAKROTIK_PORT={port}",
        f"MAKROTIK_DEBUG={'1' if debug.lower() in ('y', 'yes') else '0'}",
        "",
    ]
    (install_dir / ".env").write_text("\n".join(lines))
    os.chmod(install_dir / ".env", 0o600)
    print(".env written.")


def create_venv(install_dir):
    print("\n[4/8] Creating Python virtual environment ...")
    install_dir = Path(install_dir)
    run([sys.executable, "-m", "venv", str(install_dir / "venv")])
    pip = install_dir / "venv" / "bin" / "pip"
    run([str(pip), "install", "--upgrade", "pip", "wheel"])
    run([str(pip), "install", "-r", str(install_dir / "requirements.txt")])
    print("Virtual environment ready.")


def write_service(install_dir):
    print("\n[5/8] Creating systemd service ...")
    install_dir = Path(install_dir)
    venv_python = install_dir / "venv" / "bin" / "python"
    unit = f"""[Unit]
Description=Makrotik Share
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory={install_dir}
EnvironmentFile={install_dir}/.env
ExecStart={install_dir}/venv/bin/gunicorn -w 1 -b 0.0.0.0:${{MAKROTIK_PORT}} wsgi:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    # gunicorn binds host from env not supported in -b simply; use 0.0.0.0
    unit = unit.replace("-b 0.0.0.0:${MAKROTIK_PORT}", "-b ${MAKROTIK_HOST}:${MAKROTIK_PORT}")
    SERVICE_FILE.write_text(unit)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", SERVICE_NAME])
    print("Service created and enabled.")


def write_cli(install_dir):
    print("\n[6/8] Installing 'makrotik' console command ...")
    install_dir = Path(install_dir)
    script = f"""#!/usr/bin/env bash
set -euo pipefail
DIR="{install_dir}"
case "${{1:-status}}" in
  start) systemctl start {SERVICE_NAME} ;;
  stop) systemctl stop {SERVICE_NAME} ;;
  restart) systemctl restart {SERVICE_NAME} ;;
  status) systemctl status {SERVICE_NAME} --no-pager ;;
  logs) journalctl -u {SERVICE_NAME} -f ;;
  update)
    cd "$DIR"
    git pull || true
    "$DIR/venv/bin/pip" install -r "$DIR/requirements.txt"
    systemctl restart {SERVICE_NAME}
    ;;
  shell) cd "$DIR" && "$DIR/venv/bin/python" ;;
  *) echo "Usage: makrotik {{start|stop|restart|status|logs|update|shell}}"; exit 1 ;;
esac
"""
    CLI_FILE.write_text(script)
    os.chmod(CLI_FILE, 0o755)
    print("Console command installed.")


def start_service():
    print("\n[7/8] Starting service ...")
    try:
        run(["systemctl", "restart", SERVICE_NAME])
        print("Service started.")
    except subprocess.CalledProcessError as exc:
        print(f"Could not start service: {exc}")
        print("Check logs with: journalctl -u makrotik -e")


def finish(install_dir, host, port):
    print("\n[8/8] Done.")
    print("=" * 60)
    print(f"Install dir : {install_dir}")
    print(f"Service     : {SERVICE_NAME} (systemctl status {SERVICE_NAME})")
    print(f"URL         : http://{host if host != '0.0.0.0' else '<server-ip>'}:{port}")
    print("Console     : makrotik status | makrotik logs | makrotik restart")
    print("=" * 60)


def main():
    require_root()
    print("Makrotik Share - console setup")
    print("=" * 60)
    ensure_packages()
    install_dir = prompt("Install directory", str(DEFAULT_INSTALL_DIR))
    install_files(install_dir)
    configure_env(install_dir)
    create_venv(install_dir)
    # read host/port back for finish
    env_text = (Path(install_dir) / ".env").read_text()
    host = "0.0.0.0"
    port = "5000"
    for line in env_text.splitlines():
        if line.startswith("MAKROTIK_HOST="):
            host = line.split("=", 1)[1]
        if line.startswith("MAKROTIK_PORT="):
            port = line.split("=", 1)[1]
    write_service(install_dir)
    write_cli(install_dir)
    start_service()
    finish(install_dir, host, port)


if __name__ == "__main__":
    main()
