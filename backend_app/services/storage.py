import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
LOGS_DIR = BASE_DIR / "logs"
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
                url TEXT NOT NULL,
                report_type TEXT NOT NULL,
                comment TEXT NOT NULL,
                score INTEGER,
                verdict TEXT,
                level TEXT
            )
            """
        )
        conn.commit()


def append_scan_event(event: dict) -> None:
    with closing(get_connection()) as conn:
        conn.execute(
            """
            INSERT INTO scan_events (
                timestamp, raw_url, normalized_url, hostname, score, level,
                verdict, content_analyzed, signal_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["timestamp"],
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


def read_scan_events(limit: int | None = None) -> list[dict]:
    query = """
        SELECT timestamp, raw_url, normalized_url, hostname, score, level,
               verdict, content_analyzed, signal_count
        FROM scan_events
        ORDER BY id ASC
    """
    params: tuple = ()
    if limit is not None:
        query = """
            SELECT * FROM (
                SELECT timestamp, raw_url, normalized_url, hostname, score, level,
                       verdict, content_analyzed, signal_count
                FROM scan_events
                ORDER BY id DESC
                LIMIT ?
            ) ORDER BY timestamp ASC
        """
        params = (limit,)

    with closing(get_connection()) as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_scan_event(row) for row in rows]


def create_report(payload: dict) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            """
            INSERT INTO reports (
                timestamp, url, report_type, comment, score, verdict, level
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                payload["url"],
                payload["report_type"],
                payload.get("comment", ""),
                payload.get("score"),
                payload.get("verdict"),
                payload.get("level"),
            ),
        )
        conn.commit()
        report_id = cursor.lastrowid
    return {
        "id": report_id,
        "timestamp": timestamp,
        "url": payload["url"],
        "report_type": payload["report_type"],
        "comment": payload.get("comment", ""),
        "score": payload.get("score"),
        "verdict": payload.get("verdict"),
        "level": payload.get("level"),
    }


def read_reports(limit: int | None = None) -> list[dict]:
    query = """
        SELECT id, timestamp, url, report_type, comment, score, verdict, level
        FROM reports
        ORDER BY id DESC
    """
    params: tuple = ()
    if limit is not None:
        query += " LIMIT ?"
        params = (limit,)

    with closing(get_connection()) as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_report(row) for row in rows]


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
    }


def _row_to_scan_event(row: sqlite3.Row) -> dict:
    return {
        "timestamp": row["timestamp"],
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
        "url": row["url"],
        "report_type": row["report_type"],
        "comment": row["comment"],
        "score": row["score"],
        "verdict": row["verdict"],
        "level": row["level"],
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
