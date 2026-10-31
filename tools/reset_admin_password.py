"""Reset the /admin/ password without knowing the old one.

Usage:
    python reset_admin_password.py [new-password]

Set MAKROTIK_NEW_ADMIN_PASSWORD to skip the prompt (useful for automation).
The target is whichever database the app is currently using; the engine is
printed so there is no ambiguity about PostgreSQL vs the SQLite fallback.
"""

import getpass
import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

import app as makrotik


def _write_dotenv_password(path, new_password):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        lines = []
    output = []
    replaced = False
    for line in lines:
        if line.strip().startswith("MAKROTIK_ADMIN_PASSWORD="):
            output.append(f"MAKROTIK_ADMIN_PASSWORD={new_password}\n")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        if output and not output[-1].endswith("\n"):
            output[-1] += "\n"
        output.append(f"MAKROTIK_ADMIN_PASSWORD={new_password}\n")
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as fh:
        fh.writelines(output)
    try:
        os.chmod(temp, 0o600)
    except OSError:
        pass
    os.replace(temp, path)


def main():
    new = (
        (sys.argv[1] if len(sys.argv) > 1 else "")
        or os.environ.get("MAKROTIK_NEW_ADMIN_PASSWORD", "")
    )
    if not new:
        new = getpass.getpass("New admin password (10+ characters): ")
        confirm = getpass.getpass("Confirm new admin password: ")
        if new != confirm:
            raise SystemExit("Passwords do not match.")
    if len(new) < 10:
        raise SystemExit("Admin password must be at least 10 characters.")

    with makrotik.app.app_context():
        makrotik.set_admin_password(new)
        print(f"Admin password reset on {makrotik.database.engine}.")
        if makrotik.database.engine == "sqlite":
            print(f"SQLite database: {makrotik.SQLITE_PATH}")
        else:
            print(f"PostgreSQL: {makrotik._redact_url(makrotik.database.url)}")

    if makrotik.ADMIN_PASSWORD_ENV:
        env_path = os.path.join(makrotik.BASE_DIR, ".env")
        _write_dotenv_password(env_path, new)
        makrotik.ADMIN_PASSWORD_ENV = new
        print(f"Updated MAKROTIK_ADMIN_PASSWORD in {env_path}.")
        print(
            "If that variable is also exported outside .env, update that copy too "
            "or it will keep overriding the file."
        )


if __name__ == "__main__":
    main()
