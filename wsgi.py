"""WSGI entrypoint for production servers (gunicorn/uwsgi).

Starts the in-process scheduler exactly once per worker.
"""
import os

from app import app, start_scheduler

if os.environ.get("MAKROTIK_DISABLE_SCHEDULER", "").lower() not in ("1", "true", "yes"):
    start_scheduler()
