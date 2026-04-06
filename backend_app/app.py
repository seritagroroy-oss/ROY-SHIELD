from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend_app.config import ALLOWED_ORIGINS, APP_VERSION
from backend_app.middleware.security import SecurityHeadersMiddleware
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
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "ok": False,
            "error": "validation_failed",
            "details": exc.errors(),
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "ok": False,
            "error": exc.detail if isinstance(exc.detail, str) else "request_failed",
            "details": exc.detail if isinstance(exc.detail, dict) else None,
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "ok": False,
            "error": "internal_server_error",
        },
    )

app.include_router(scan_router)
app.include_router(health_router)
app.include_router(stats_router)
app.include_router(reports_router)
app.include_router(auth_router)
