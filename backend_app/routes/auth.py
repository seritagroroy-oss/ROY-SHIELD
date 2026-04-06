from fastapi import APIRouter, Depends, Header, HTTPException, Request

from backend_app.models import LoginRequest, RegisterRequest
from backend_app.services.rate_limit import enforce_rate_limit
from backend_app.services.storage import (
    authenticate_user,
    create_session,
    create_user,
    delete_session,
    get_user_by_token,
    read_scan_events,
    summarize_scan_events,
)

router = APIRouter()


def resolve_token_user(authorization: str | None = Header(default=None)) -> dict | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        return None
    return get_user_by_token(token)


@router.post("/auth/register")
def register(req: RegisterRequest, request: Request):
    enforce_rate_limit(request, "auth")
    user = create_user(req.name, req.email, req.password)
    if user is None:
        raise HTTPException(status_code=409, detail="email_already_exists")
    token = create_session(user["id"])
    return {"ok": True, "token": token, "user": user}


@router.post("/auth/login")
def login(req: LoginRequest, request: Request):
    enforce_rate_limit(request, "auth")
    user = authenticate_user(req.email, req.password)
    if user is None:
        raise HTTPException(status_code=401, detail="invalid_credentials")
    token = create_session(user["id"])
    return {"ok": True, "token": token, "user": user}


@router.post("/auth/logout")
def logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if token:
            delete_session(token)
    return {"ok": True}


@router.get("/me")
def me(user: dict | None = Depends(resolve_token_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"ok": True, "user": user}


@router.get("/me/scans")
def my_scans(limit: int = 10, days: int = 30, user: dict | None = Depends(resolve_token_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    safe_limit = max(1, min(limit, 50))
    safe_days = max(1, min(days, 365))
    events = read_scan_events(limit=safe_limit, days=safe_days, user_id=user["id"])
    return {"ok": True, "items": list(reversed(events)), "stats": summarize_scan_events(events), "count": len(events)}
