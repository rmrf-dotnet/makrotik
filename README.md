# Makrotik Share (CLI / Server edition)

Anonymous file sharing with optional accounts. This edition is prepared for
installation on an Ubuntu/Debian live server managed over SSH (PuTTY).

## Requirements

- Ubuntu 20.04+ / Debian 11+ (64-bit)
- Python 3.10+
- PostgreSQL 14+ (installed automatically by the setup wizard, optional)
- 2 GB RAM minimum, more for large uploads

## Quick install (recommended)

On your server (via PuTTY/SSH):

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/YOUR-USER/YOUR-REPO.git
cd YOUR-REPO
sudo bash install.sh
```

The wizard will:
1. Install system packages (Python, PostgreSQL, git).
2. Copy the app to `/opt/makrotik`.
3. Ask for database, admin and network settings and write `/opt/makrotik/.env`.
4. Create a Python virtualenv and install dependencies.
5. Create and enable a `makrotik` systemd service.
6. Install a `makrotik` console command.

When finished open `http://<server-ip>:5000` (default port 5000).

## Console management

```bash
makrotik status      # service status
makrotik start       # start
makrotik stop        # stop
makrotik restart     # restart
makrotik logs        # follow logs
makrotik update      # git pull + reinstall deps + restart
makrotik shell       # open venv python
```

## Manual install

```bash
sudo apt-get install -y python3 python3-venv python3-pip postgresql postgresql-client git
git clone https://github.com/YOUR-USER/YOUR-REPO.git /opt/makrotik
cd /opt/makrotik
cp .env.example .env
# edit .env
python3 -m venv venv
venv/bin/pip install -r requirements.txt
mkdir -p instance uploads backups
sudo venv/bin/python tools/reset_admin_password.py   # optional
# run in foreground:
./run.sh
```

## Run as a service (manual)

```bash
sudo cp /opt/makrotik/makrotik.service /etc/systemd/system/  # if you created one
sudo systemctl daemon-reload
sudo systemctl enable --now makrotik
```

The provided `setup.py` already performs this step.

## Configuration (.env)

See `.env.example`. Key variables:

- `MAKROTIK_DATABASE_URL` - PostgreSQL URL; leave empty for SQLite fallback.
- `MAKROTIK_ADMIN_USER` / `MAKROTIK_ADMIN_PASSWORD` - admin control room credentials.
- `MAKROTIK_HOST` / `MAKROTIK_PORT` - bind address (use `0.0.0.0` to expose).
- `MAKROTIK_DEBUG` - never enable on a public server.
- `MAKROTIK_DISABLE_SCHEDULER` - disable background jobs.

## Database migration (SQLite -> PostgreSQL)

```bash
cd /opt/makrotik
venv/bin/python tools/migrate_to_postgres.py postgresql://makrotik:pass@127.0.0.1:5432/makrotik
```

## Reset admin password

```bash
cd /opt/makrotik
venv/bin/python tools/reset_admin_password.py
```

## Updating

```bash
makrotik update
```

Or manually:

```bash
cd /opt/makrotik
git pull
venv/bin/pip install -r requirements.txt
sudo systemctl restart makrotik
```

## Backups

Backups are stored in `/opt/makrotik/backups`. Use the admin panel
(`/admin/backups`) or schedule `pg_dump`/file copies via cron.

## Troubleshooting

- Service logs: `journalctl -u makrotik -e`
- Check port: `ss -lntp | grep 5000`
- PostgreSQL status: `systemctl status postgresql`
- Disk/space: admin panel -> Infrastructure.

## Notes for Linux

This edition targets Linux (Ubuntu). Windows-specific code paths
(Win32 drive enumeration) were removed; disk discovery reads `/proc/mounts`.
