from __future__ import annotations

import os
from pathlib import Path

APP_DIR = Path.home() / ".b3n-gatekeeper"
CREDENTIALS_FILE = APP_DIR / "credentials.json"
DEFAULT_URL = "http://localhost:8000"
B3N_GATEKEEPER_URL_ENV = "B3N_GATEKEEPER_URL"


def normalize_url(url: str | None) -> str:
    return (url or os.environ.get(B3N_GATEKEEPER_URL_ENV) or DEFAULT_URL).rstrip("/")
