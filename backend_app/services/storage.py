import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import hashlib
import hmac
import secrets

from backend_app.config import resolve_storage_dir

LOGS_DIR = resolve_storage_dir()
DB_PATH = LOGS_DIR / "roy_shield.db"


def ensure_logs_dir() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    ensure_logs_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_storage() -> None:
    with closing(get_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id INTEGER,
                raw_url TEXT NOT NULL,
                normalized_url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                verdict TEXT NOT NULL,
                content_analyzed INTEGER NOT NULL,
                signal_count INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id INTEGER,
                url TEXT NOT NULL,
                report_type TEXT NOT NULL,
                comment TEXT NOT NULL,
                score INTEGER,
                verdict TEXT,
                level TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                moderation_note TEXT NOT NULL DEFAULT '',
                moderated_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shared_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                source_report_id INTEGER,
                url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                level TEXT NOT NULL,
                score INTEGER NOT NULL,
                snapshot TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            )
            """
        )
        _ensure_column(conn, "scan_events", "user_id", "INTEGER")
        _ensure_column(conn, "reports", "user_id", "INTEGER")
        _ensure_column(conn, "reports", "status", "TEXT NOT NULL DEFAULT 'pending'")
        _ensure_column(conn, "reports", "moderation_note", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "reports", "moderated_at", "TEXT")
        conn.commit()


def append_scan_event(event: dict) -> None:
    with closing(get_connection()) as conn:
        conn.execute(
            """
            INSERT INTO scan_events (
                timestamp, user_id, raw_url, normalized_url, hostname, score, level,
                verdict, content_analyzed, signal_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["timestamp"],
                event.get("user_id"),
                event["raw_url"],
                event["normalized_url"],
                event["hostname"],
                event["score"],
                event["level"],
                event["verdict"],
                1 if event.get("content_analyzed") else 0,
                event.get("signal_count", 0),
            ),
        )
        conn.commit()


def read_scan_events(
    limit: int | None = None,
    *,
    days: int | None = None,
    level: str | None = None,
    user_id: int | None = None,
) -> list[dict]:
    filters = []
    params: list = []
    if days is not None and days > 0:
        since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).date().isoformat()
        filters.append("timestamp >= ?")
        params.append(f"{since}T00:00:00+00:00")
    if level:
        filters.append("level = ?")
        params.append(level)
    if user_id is not None:
        filters.append("user_id = ?")
        params.append(user_id)

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    query = """
        SELECT timestamp, user_id, raw_url, normalized_url, hostname, score, level,
               verdict, content_analyzed, signal_count
        FROM scan_events
        {where_clause}
        ORDER BY id ASC
    """.format(where_clause=where_clause)
    if limit is not None:
        query = """
            SELECT * FROM (
                SELECT timestamp, user_id, raw_url, normalized_url, hostname, score, level,
                       verdict, content_analyzed, signal_count
                FROM scan_events
                {where_clause}
                ORDER BY id DESC
                LIMIT ?
            ) ORDER BY timestamp ASC
        """.format(where_clause=where_clause)
        params.append(limit)

    with closing(get_connection()) as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
    return [_row_to_scan_event(row) for row in rows]


def create_report(payload: dict) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            """
            INSERT INTO reports (
                timestamp, user_id, url, report_type, comment, score, verdict, level, status, moderation_note, moderated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                payload.get("user_id"),
                payload["url"],
                payload["report_type"],
                payload.get("comment", ""),
                payload.get("score"),
                payload.get("verdict"),
                payload.get("level"),
                payload.get("status", "pending"),
                payload.get("moderation_note", ""),
                payload.get("moderated_at"),
            ),
        )
        conn.commit()
        report_id = cursor.lastrowid
    return {
        "id": report_id,
        "timestamp": timestamp,
        "user_id": payload.get("user_id"),
        "url": payload["url"],
        "report_type": payload["report_type"],
        "comment": payload.get("comment", ""),
        "score": payload.get("score"),
        "verdict": payload.get("verdict"),
        "level": payload.get("level"),
        "status": payload.get("status", "pending"),
        "moderation_note": payload.get("moderation_note", ""),
        "moderated_at": payload.get("moderated_at"),
    }


def read_reports(
    limit: int | None = None,
    *,
    days: int | None = None,
    report_type: str | None = None,
    user_id: int | None = None,
) -> list[dict]:
    filters = []
    params: list = []
    if days is not None and days > 0:
        since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).date().isoformat()
        filters.append("timestamp >= ?")
        params.append(f"{since}T00:00:00+00:00")
    if report_type:
        filters.append("report_type = ?")
        params.append(report_type)
    if user_id is not None:
        filters.append("user_id = ?")
        params.append(user_id)

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    query = """
        SELECT id, timestamp, user_id, url, report_type, comment, score, verdict, level,
               status, moderation_note, moderated_at
        FROM reports
        {where_clause}
        ORDER BY id DESC
    """.format(where_clause=where_clause)
    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)

    with closing(get_connection()) as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
    return [_row_to_report(row) for row in rows]


def moderate_report(report_id: int, status: str, note: str = "") -> dict | None:
    moderated_at = datetime.now(timezone.utc).isoformat()
    with closing(get_connection()) as conn:
        conn.execute(
            """
            UPDATE reports
            SET status = ?, moderation_note = ?, moderated_at = ?
            WHERE id = ?
            """,
            (status, note, moderated_at, report_id),
        )
        conn.commit()
        row = conn.execute(
            """
            SELECT id, timestamp, user_id, url, report_type, comment, score, verdict, level,
                   status, moderation_note, moderated_at
            FROM reports
            WHERE id = ?
            """,
            (report_id,),
        ).fetchone()
    return _row_to_report(row) if row else None


def create_shared_report(payload: dict, source_report_id: int | None = None) -> dict:
    token = secrets.token_urlsafe(10)
    created_at = datetime.now(timezone.utc).isoformat()
    snapshot = json.dumps(payload, ensure_ascii=False)
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            """
            INSERT INTO shared_reports (
                created_at, token, source_report_id, url, verdict, level, score, snapshot
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                token,
                source_report_id,
                payload["url"],
                payload["verdict"],
                payload["level"],
                payload["score"],
                snapshot,
            ),
        )
        conn.commit()
        share_id = cursor.lastrowid
    return {
        "id": share_id,
        "token": token,
        "created_at": created_at,
        "source_report_id": source_report_id,
        **payload,
    }


def get_shared_report(token: str) -> dict | None:
    with closing(get_connection()) as conn:
        row = conn.execute(
            """
            SELECT id, created_at, token, source_report_id, url, verdict, level, score, snapshot
            FROM shared_reports
            WHERE token = ?
            """,
            (token,),
        ).fetchone()
    if not row:
        return None
    snapshot = json.loads(row["snapshot"])
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "token": row["token"],
        "source_report_id": row["source_report_id"],
        **snapshot,
    }


def create_user(name: str, email: str, password: str) -> dict | None:
    timestamp = datetime.now(timezone.utc).isoformat()
    password_hash = _hash_password(password)
    normalized_email = email.strip().lower()
    with closing(get_connection()) as conn:
        try:
            cursor = conn.execute(
                """
                INSERT INTO users (created_at, name, email, password_hash)
                VALUES (?, ?, ?, ?)
                """,
                (timestamp, name.strip(), normalized_email, password_hash),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return None
        user_id = cursor.lastrowid
    return {"id": user_id, "created_at": timestamp, "name": name.strip(), "email": normalized_email}


def authenticate_user(email: str, password: str) -> dict | None:
    normalized_email = email.strip().lower()
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT id, created_at, name, email, password_hash FROM users WHERE email = ?",
            (normalized_email,),
        ).fetchone()
    if not row or not _verify_password(password, row["password_hash"]):
        return None
    return {"id": row["id"], "created_at": row["created_at"], "name": row["name"], "email": row["email"]}


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with closing(get_connection()) as conn:
        conn.execute(
            "INSERT INTO sessions (user_id, token, created_at) VALUES (?, ?, ?)",
            (user_id, token, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    return token


def delete_session(token: str) -> None:
    with closing(get_connection()) as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def get_user_by_token(token: str) -> dict | None:
    with closing(get_connection()) as conn:
        row = conn.execute(
            """
            SELECT users.id, users.created_at, users.name, users.email
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?
            """,
            (token,),
        ).fetchone()
    if not row:
        return None
    return {"id": row["id"], "created_at": row["created_at"], "name": row["name"], "email": row["email"]}


def summarize_scan_events(events: list[dict]) -> dict:
    totals = {"safe": 0, "warn": 0, "danger": 0}
    source_totals = {"frontend_only": 0, "backend_enriched": 0}
    last_7_days = _empty_trend_window()

    for event in events:
        level = event.get("level")
        if level in totals:
            totals[level] += 1
        if event.get("content_analyzed"):
            source_totals["backend_enriched"] += 1
        else:
            source_totals["frontend_only"] += 1
        _increment_trend(last_7_days, event.get("timestamp"))

    total_scans = len(events)
    average_score = round(sum(event.get("score", 0) for event in events) / total_scans, 1) if total_scans else 0
    latest_scan_at = events[-1]["timestamp"] if events else None

    return {
        "total_scans": total_scans,
        "safe_scans": totals["safe"],
        "warn_scans": totals["warn"],
        "danger_scans": totals["danger"],
        "average_score": average_score,
        "latest_scan_at": latest_scan_at,
        "source_totals": source_totals,
        "trend_last_7_days": last_7_days,
        "highest_score": max((event.get("score", 0) for event in events), default=0),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def summarize_reports(reports: list[dict]) -> dict:
    totals: dict[str, int] = {}
    last_7_days = _empty_trend_window()

    for report in reports:
        report_type = report.get("report_type", "other")
        totals[report_type] = totals.get(report_type, 0) + 1
        _increment_trend(last_7_days, report.get("timestamp"))

    latest_report_at = reports[0]["timestamp"] if reports else None

    return {
        "total_reports": len(reports),
        "by_type": totals,
        "latest_report_at": latest_report_at,
        "trend_last_7_days": last_7_days,
        "pending_reports": sum(1 for report in reports if report.get("status") == "pending"),
    }


def _row_to_scan_event(row: sqlite3.Row) -> dict:
    return {
        "timestamp": row["timestamp"],
        "user_id": row["user_id"],
        "raw_url": row["raw_url"],
        "normalized_url": row["normalized_url"],
        "hostname": row["hostname"],
        "score": row["score"],
        "level": row["level"],
        "verdict": row["verdict"],
        "content_analyzed": bool(row["content_analyzed"]),
        "signal_count": row["signal_count"],
    }


def _row_to_report(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "user_id": row["user_id"],
        "url": row["url"],
        "report_type": row["report_type"],
        "comment": row["comment"],
        "score": row["score"],
        "verdict": row["verdict"],
        "level": row["level"],
        "status": row["status"],
        "moderation_note": row["moderation_note"],
        "moderated_at": row["moderated_at"],
    }


def _empty_trend_window() -> list[dict]:
    today = datetime.now(timezone.utc).date()
    return [
        {"day": (today - timedelta(days=offset)).isoformat(), "count": 0}
        for offset in range(6, -1, -1)
    ]


def _increment_trend(window: list[dict], timestamp: str | None) -> None:
    if not timestamp:
        return
    day = timestamp[:10]
    for item in window:
        if item["day"] == day:
            item["count"] += 1
            return


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return f"{salt}${digest}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return hmac.compare_digest(candidate, digest)
