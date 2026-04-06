from fastapi import APIRouter

from backend_app.services.storage import read_scan_events, summarize_scan_events

router = APIRouter()


@router.get("/stats")
def stats():
    events = read_scan_events()
    return summarize_scan_events(events)


@router.get("/recent-scans")
def recent_scans(limit: int = 5):
    safe_limit = max(1, min(limit, 20))
    events = read_scan_events(limit=safe_limit)
    events.reverse()
    return {"items": events, "count": len(events)}
