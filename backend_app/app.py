from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend_app.config import ALLOWED_ORIGINS, APP_VERSION
from backend_app.routes import health_router, scan_router

app = FastAPI(title="ROY SHIELD API", version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(health_router)
