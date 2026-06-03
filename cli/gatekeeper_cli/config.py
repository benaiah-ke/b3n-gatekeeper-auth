from __future__ import annotations

from pathlib import Path

APP_DIR = Path.home() / ".gatekeeper"
CREDENTIALS_FILE = APP_DIR / "credentials.json"


def normalize_url(url: str | None) -> str:
    return (url or "https://gatekeeper.b3n.in").rstrip("/")

