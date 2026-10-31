"""Transfer traffic recording and dashboard aggregation."""

from __future__ import annotations

from datetime import datetime, timedelta

from db import now_iso


def record_traffic(conn, direction, token, size, actor="anonymous", owner_id=None):
    if direction not in ("upload", "download"):
        return None
    return conn.insert(
        "INSERT INTO traffic_events "
        "(created_at, direction, token, bytes, actor, owner_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            now_iso(),
            direction,
            token,
            max(0, int(size or 0)),
            actor or "anonymous",
            owner_id,
        ),
    )


def _bucket_labels(days):
    today = datetime.utcnow().date()
    return [
        (today - timedelta(days=offset)).isoformat()
        for offset in range(days - 1, -1, -1)
    ]


def traffic_summary(conn, days=30):
    days = max(1, min(int(days or 30), 365))
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat(
        timespec="seconds"
    )
    rows = conn.execute(
        "SELECT created_at, direction, bytes, actor, token "
        "FROM traffic_events WHERE created_at >= ? ORDER BY created_at",
        (cutoff,),
    ).fetchall()
    labels = _bucket_labels(days)
    buckets = {
        label: {"date": label, "upload": 0, "download": 0, "events": 0}
        for label in labels
    }
    upload_bytes = download_bytes = 0
    uploads = downloads = 0
    actors = {}
    tokens = {}
    for row in rows:
        day = (row["created_at"] or "")[:10]
        bucket = buckets.get(day)
        size = int(row["bytes"] or 0)
        if bucket is not None:
            bucket[row["direction"]] += size
            bucket["events"] += 1
        if row["direction"] == "upload":
            upload_bytes += size
            uploads += 1
        else:
            download_bytes += size
            downloads += 1
        actor = row["actor"] or "anonymous"
        actors[actor] = actors.get(actor, 0) + size
        if row["token"]:
            entry = tokens.setdefault(
                row["token"], {"token": row["token"], "bytes": 0, "events": 0}
            )
            entry["bytes"] += size
            entry["events"] += 1
    peak = max(
        [bucket["upload"] + bucket["download"] for bucket in buckets.values()]
        + [1]
    )
    bucket_list = []
    for label in labels:
        bucket = buckets[label]
        total = bucket["upload"] + bucket["download"]
        bucket_list.append(
            {
                **bucket,
                "total": total,
                "upload_human": human_bytes(bucket["upload"]),
                "download_human": human_bytes(bucket["download"]),
                "total_human": human_bytes(total),
                "percent": round(total / peak * 100, 1) if peak else 0,
            }
        )
    top_tokens = sorted(
        tokens.values(), key=lambda item: item["bytes"], reverse=True
    )[:10]
    for item in top_tokens:
        item["bytes_human"] = human_bytes(item["bytes"])
        file_row = conn.execute(
            "SELECT original_name FROM files WHERE token = ?", (item["token"],)
        ).fetchone()
        item["name"] = file_row["original_name"] if file_row else item["token"]
    top_actors = [
        {"actor": actor, "bytes": size, "bytes_human": human_bytes(size)}
        for actor, size in sorted(
            actors.items(), key=lambda item: item[1], reverse=True
        )[:10]
    ]
    return {
        "days": days,
        "from": cutoff,
        "to": now_iso(),
        "upload_bytes": upload_bytes,
        "download_bytes": download_bytes,
        "total_bytes": upload_bytes + download_bytes,
        "upload_human": human_bytes(upload_bytes),
        "download_human": human_bytes(download_bytes),
        "total_human": human_bytes(upload_bytes + download_bytes),
        "uploads": uploads,
        "downloads": downloads,
        "events": len(rows),
        "buckets": bucket_list,
        "top_files": top_tokens,
        "top_actors": top_actors,
    }


def human_bytes(value):
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
