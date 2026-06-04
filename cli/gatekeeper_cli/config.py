from __future__ import annotations

import os
from pathlib import Path

APP_DIR = Path.home() / ".gatekeeper"
CREDENTIALS_FILE = APP_DIR / "credentials.json"
DEFAULT_URL = "http://localhost:8000"


def normalize_url(url: str | None) -> str:
    return (url or os.environ.get("GATEKEEPER_URL") or DEFAULT_URL).rstrip("/")
