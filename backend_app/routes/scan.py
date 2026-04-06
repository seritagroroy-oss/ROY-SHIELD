from fastapi import APIRouter, Depends, Request

from backend_app.models import ScanRequest
from backend_app.routes.auth import resolve_token_user
from backend_app.services.rate_limit import enforce_rate_limit
from backend_app.services.scan_service import analyze_scan

router = APIRouter()


@router.post("/scan")
async def scan(req: ScanRequest, request: Request, user: dict | None = Depends(resolve_token_user)):
    enforce_rate_limit(request, "scan")
    return await analyze_scan(req.url, user_id=user["id"] if user else None)
