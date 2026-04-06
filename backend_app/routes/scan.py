from fastapi import APIRouter

from backend_app.models import ScanRequest
from backend_app.services.scan_service import analyze_scan

router = APIRouter()


@router.post("/scan")
async def scan(req: ScanRequest):
    return await analyze_scan(req.url)
