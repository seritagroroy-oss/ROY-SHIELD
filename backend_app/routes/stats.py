from fastapi import APIRouter

from backend_app.services.analytics_service import build_security_posture
from backend_app.services.storage import read_reports, read_scan_events, summarize_reports, summarize_scan_events

router = APIRouter()


@router.get("/stats")
def stats(days: int = 30, level: str | None = None, report_type: str | None = None):
    safe_days = max(1, min(days, 365))
    events = read_scan_events(days=safe_days, level=level)
    reports = read_reports(days=safe_days, report_type=report_type)
    payload = summarize_scan_events(events)
    report_summary = summarize_reports(reports)
    payload["reports"] = report_summary
    payload["security"] = build_security_posture(payload, report_summary)
    return payload


@router.get("/recent-scans")
def recent_scans(limit: int = 5, days: int = 30, level: str | None = None):
    safe_limit = max(1, min(limit, 20))
    safe_days = max(1, min(days, 365))
    events = read_scan_events(limit=safe_limit, days=safe_days, level=level)
    events.reverse()
    return {"items": events, "count": len(events)}
