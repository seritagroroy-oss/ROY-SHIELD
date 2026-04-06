from fastapi import APIRouter

from backend_app.models import ReportRequest
from backend_app.services.storage import create_report, read_reports, summarize_reports

router = APIRouter()


@router.post("/reports")
def submit_report(req: ReportRequest):
    report = create_report(req.model_dump())
    return {"ok": True, "report": report}


@router.get("/reports/recent")
def recent_reports(limit: int = 5):
    safe_limit = max(1, min(limit, 20))
    reports = read_reports(limit=safe_limit)
    return {"items": reports, "count": len(reports)}


@router.get("/reports/stats")
def report_stats():
    reports = read_reports()
    return summarize_reports(reports)
