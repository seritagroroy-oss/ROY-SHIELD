import asyncio

import httpx

from backend_app.config import WEBHOOK_URL


async def notify_webhook(event_type: str, payload: dict) -> None:
    if not WEBHOOK_URL:
        return
    body = {"event": event_type, "payload": payload}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(WEBHOOK_URL, json=body)
    except Exception:
        return


def dispatch_webhook(event_type: str, payload: dict) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(notify_webhook(event_type, payload))
