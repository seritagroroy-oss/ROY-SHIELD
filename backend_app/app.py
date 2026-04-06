from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend_app.config import ALLOWED_ORIGINS, APP_VERSION
from backend_app.routes import auth_router, health_router, reports_router, scan_router, stats_router
from backend_app.services.storage import init_storage

init_storage()

app = FastAPI(title="ROY SHIELD API", version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(health_router)
app.include_router(stats_router)
app.include_router(reports_router)
app.include_router(auth_router)
