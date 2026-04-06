from fastapi import APIRouter, Depends

from backend_app.models import ReportRequest
from backend_app.routes.auth import resolve_token_user
from backend_app.services.storage import create_report, read_reports, summarize_reports

router = APIRouter()


@router.post("/reports")
def submit_report(req: ReportRequest, user: dict | None = Depends(resolve_token_user)):
    payload = req.model_dump()
    payload["user_id"] = user["id"] if user else None
    report = create_report(payload)
    return {"ok": True, "report": report}


@router.get("/reports/recent")
def recent_reports(limit: int = 5, days: int = 30, report_type: str | None = None):
    safe_limit = max(1, min(limit, 20))
    safe_days = max(1, min(days, 365))
    reports = read_reports(limit=safe_limit, days=safe_days, report_type=report_type)
    return {"items": reports, "count": len(reports)}


@router.get("/reports/stats")
def report_stats(days: int = 30, report_type: str | None = None):
    safe_days = max(1, min(days, 365))
    reports = read_reports(days=safe_days, report_type=report_type)
    return summarize_reports(reports)
