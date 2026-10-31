"""Dependency-free host, process and storage health probes."""

from __future__ import annotations

import os
import platform
import shutil
import sys
import time
from datetime import datetime

_STARTED = time.time()


def human_bytes(value):
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _linux_memory():
    values = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                if key in ("MemTotal", "MemAvailable", "MemFree"):
                    values[key] = int(rest.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    if not total:
        return None
    used = max(0, total - available)
    return {
        "total": total,
        "available": available,
        "used": used,
        "percent": round(used / total * 100, 1),
        "total_human": human_bytes(total),
        "available_human": human_bytes(available),
        "used_human": human_bytes(used),
    }


def memory_info():
    return _linux_memory()


def _linux_uptime():
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            seconds = int(float(fh.read().split()[0]))
        return seconds
    except (OSError, ValueError, IndexError):
        return None


def uptime_human(seconds):
    seconds = max(0, int(seconds or 0))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def process_info():
    result = {
        "pid": os.getpid(),
        "python": platform.python_version(),
        "executable": sys.executable,
        "started_at": datetime.utcfromtimestamp(_STARTED).isoformat(
            timespec="seconds"
        ),
        "uptime_human": uptime_human(time.time() - _STARTED),
        "threads": None,
        "rss": None,
        "rss_human": "—",
    }
    try:
        import threading

        result["threads"] = threading.active_count()
    except Exception:  # noqa: BLE001
        pass
    try:
        import resource

        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            rss = rss
        else:
            rss = rss * 1024
        result["rss"] = rss
        result["rss_human"] = human_bytes(rss)
    except Exception:  # noqa: BLE001 - resource is Unix-only
        pass
    return result


def disk_info(path):
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return {
            "path": path,
            "ok": False,
            "total": 0,
            "used": 0,
            "free": 0,
            "percent": 0,
            "total_human": "0 B",
            "used_human": "0 B",
            "free_human": "0 B",
        }
    percent = round(usage.used / usage.total * 100, 1) if usage.total else 0
    return {
        "path": path,
        "ok": True,
        "total": usage.total,
        "used": usage.used,
        "free": usage.free,
        "percent": min(percent, 100),
        "total_human": human_bytes(usage.total),
        "used_human": human_bytes(usage.used),
        "free_human": human_bytes(usage.free),
    }


def directory_info(path):
    files = 0
    size = 0
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    if entry.is_file(follow_symlinks=False):
                        files += 1
                        size += entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
    except OSError:
        pass
    return {
        "path": path,
        "writable": os.path.isdir(path) and os.access(path, os.W_OK),
        "files": files,
        "bytes": size,
        "size_human": human_bytes(size),
    }


def host_info(upload_folder, backup_folder):
    load = None
    try:
        load = os.getloadavg()
    except (AttributeError, OSError):
        pass
    host_uptime = _linux_uptime()
    return {
        "hostname": platform.node() or "unknown",
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count() or 0,
        "load": [round(value, 2) for value in load] if load else None,
        "host_uptime": uptime_human(host_uptime) if host_uptime else "—",
        "memory": memory_info(),
        "process": process_info(),
        "disks": [
            disk_info(upload_folder),
            disk_info(backup_folder),
        ],
        "uploads": directory_info(upload_folder),
        "backups": directory_info(backup_folder),
    }
