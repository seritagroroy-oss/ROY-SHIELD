from collections import defaultdict, deque
from time import time

from fastapi import HTTPException, Request

from backend_app.config import RATE_LIMIT_AUTH, RATE_LIMIT_REPORTS, RATE_LIMIT_SCAN, RATE_LIMIT_WINDOW_SECONDS


_BUCKETS: dict[str, deque[float]] = defaultdict(deque)

RATE_LIMITS = {
    "scan": RATE_LIMIT_SCAN,
    "reports": RATE_LIMIT_REPORTS,
    "auth": RATE_LIMIT_AUTH,
}


def enforce_rate_limit(request: Request, bucket: str) -> None:
    limit = RATE_LIMITS.get(bucket, RATE_LIMIT_SCAN)
    window = RATE_LIMIT_WINDOW_SECONDS
    key = _build_key(request, bucket)
    now = time()
    history = _BUCKETS[key]

    while history and now - history[0] >= window:
        history.popleft()

    if len(history) >= limit:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "rate_limit_exceeded",
                "bucket": bucket,
                "limit": limit,
                "window_seconds": window,
            },
        )

    history.append(now)


def _build_key(request: Request, bucket: str) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else None
    client_ip = client_ip or (request.client.host if request.client else "unknown")
    return f"{bucket}:{client_ip}"
