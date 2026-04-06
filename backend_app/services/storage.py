import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
LOGS_DIR = BASE_DIR / "logs"
SCAN_LOG_FILE = LOGS_DIR / "scan_events.jsonl"


def ensure_logs_dir() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def append_scan_event(event: dict) -> None:
    ensure_logs_dir()
    with SCAN_LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def read_scan_events(limit: int | None = None) -> list[dict]:
    if not SCAN_LOG_FILE.exists():
        return []

    with SCAN_LOG_FILE.open("r", encoding="utf-8") as handle:
        events = [json.loads(line) for line in handle if line.strip()]

    if limit is not None:
        return events[-limit:]
    return events


def summarize_scan_events(events: list[dict]) -> dict:
    totals = {"safe": 0, "warn": 0, "danger": 0}
    source_totals = {"frontend_only": 0, "backend_enriched": 0}

    for event in events:
        level = event.get("level")
        if level in totals:
            totals[level] += 1
        if event.get("content_analyzed"):
            source_totals["backend_enriched"] += 1
        else:
            source_totals["frontend_only"] += 1

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
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
