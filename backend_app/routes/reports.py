from fastapi import APIRouter, Depends, HTTPException, Request

from backend_app.models import ReportModerationRequest, ReportRequest, ShareReportRequest
from backend_app.routes.auth import require_admin, resolve_token_user
from backend_app.services.notification_service import dispatch_webhook
from backend_app.services.rate_limit import enforce_rate_limit
from backend_app.services.storage import (
    create_report,
    create_shared_report,
    get_shared_report,
    moderate_report,
    read_reports,
    summarize_reports,
)

router = APIRouter()


@router.post("/reports")
def submit_report(req: ReportRequest, request: Request, user: dict | None = Depends(resolve_token_user)):
    enforce_rate_limit(request, "reports")
    payload = req.model_dump()
    payload["user_id"] = user["id"] if user else None
    report = create_report(payload)
    dispatch_webhook("report_created", report)
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


@router.post("/reports/share")
def share_report(req: ShareReportRequest):
    share = create_shared_report(req.model_dump())
    dispatch_webhook("shared_report_created", {"token": share["token"], "url": share["url"], "level": share["level"]})
    return {"ok": True, "share": share}


@router.get("/shared-reports/{token}")
def shared_report(token: str):
    payload = get_shared_report(token)
    if payload is None:
        raise HTTPException(status_code=404, detail="shared_report_not_found")
    return {"ok": True, "report": payload}


@router.get("/admin/reports")
def admin_reports(status: str = "pending", days: int = 90, is_admin: bool = Depends(require_admin)):
    safe_days = max(1, min(days, 365))
    reports = read_reports(days=safe_days)
    if status:
        reports = [report for report in reports if report.get("status") == status]
    return {"ok": True, "items": reports, "count": len(reports)}


@router.post("/admin/reports/{report_id}/moderate")
def admin_moderate_report(
    report_id: int,
    req: ReportModerationRequest,
    is_admin: bool = Depends(require_admin),
):
    report = moderate_report(report_id, req.status, req.note)
    if report is None:
        raise HTTPException(status_code=404, detail="report_not_found")
    dispatch_webhook("report_moderated", report)
    return {"ok": True, "report": report}
