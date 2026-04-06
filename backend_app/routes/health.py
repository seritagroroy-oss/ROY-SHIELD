from fastapi import APIRouter

from backend_app.config import ALLOWED_ORIGINS, APP_ENV, APP_VERSION

router = APIRouter()


@router.get("/health")
def health():
    return {
        "status": "ok",
        "version": APP_VERSION,
        "environment": APP_ENV,
        "allowed_origins": ALLOWED_ORIGINS or ["*"],
    }
