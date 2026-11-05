from __future__ import annotations

import asyncio
import json
import logging

import httpx

from app.config import settings

logger = logging.getLogger("gatekeeper.alerts")

# Tests swap in httpx.MockTransport; production uses the default network transport.
_transport: httpx.AsyncBaseTransport | None = None
_pending: set[asyncio.Task] = set()


def _clip(value: str, limit: int) -> str:
    return value.encode("utf-8")[:limit].decode("utf-8", "ignore")


def security_alert_request(subject: str, lines: list[str], key: str) -> dict:
    clean_subject = _clip(" ".join(f"[GateKeeper] {subject}".split()), 255)
    return {
        "url": f"{settings.sendy_api_url.rstrip('/')}/api/v1/emails",
        "headers": {
            "Authorization": f"Bearer {settings.sendy_api_key}",
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
            "Idempotency-Key": _clip(key, 128),
        },
        "content": json.dumps(
            {
                "data": {
                    "type": "emails",
                    "attributes": {
                        "from": settings.alert_email_from,
                        "to": settings.alert_email_to,
                        "subject": clean_subject,
                        "text": _clip("\n".join(lines), 60000),
                    },
                }
            }
        ),
    }


async def _deliver(request: dict) -> None:
    try:
        async with httpx.AsyncClient(transport=_transport, timeout=5.0) as client:
            response = await client.post(**request)
        if response.status_code != 202:
            logger.warning("Security alert email was not accepted (status %s)", response.status_code)
    except Exception as exc:  # never let alert delivery break auth flows
        logger.warning("Security alert email failed: %s", type(exc).__name__)


def send_security_alert(subject: str, lines: list[str], key: str) -> None:
    """Queue a security alert email through Sendy without blocking or failing the request."""
    if not settings.sendy_api_key or not settings.alert_email_to or not key:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    task = loop.create_task(_deliver(security_alert_request(subject, lines, key)))
    _pending.add(task)
    task.add_done_callback(_pending.discard)
