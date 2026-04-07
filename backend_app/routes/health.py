from fastapi import APIRouter

from backend_app.config import ALLOWED_ORIGINS, APP_ENV, APP_VERSION, IS_VERCEL, VERCEL_ENV, resolve_storage_dir

router = APIRouter()


@router.get("/health")
def health():
    return {
        "status": "ok",
        "version": APP_VERSION,
        "environment": APP_ENV,
        "allowed_origins": ALLOWED_ORIGINS or ["*"],
        "platform": "vercel" if IS_VERCEL else "standard",
        "vercel_env": VERCEL_ENV or None,
        "storage_dir": str(resolve_storage_dir()),
    }
