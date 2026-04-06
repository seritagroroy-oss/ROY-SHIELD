from fastapi import APIRouter

from backend_app.services.storage import read_reports, read_scan_events, summarize_reports, summarize_scan_events

router = APIRouter()


@router.get("/stats")
def stats():
    events = read_scan_events()
    reports = read_reports()
    payload = summarize_scan_events(events)
    payload["reports"] = summarize_reports(reports)
    return payload


@router.get("/recent-scans")
def recent_scans(limit: int = 5):
    safe_limit = max(1, min(limit, 20))
    events = read_scan_events(limit=safe_limit)
    events.reverse()
    return {"items": events, "count": len(events)}
