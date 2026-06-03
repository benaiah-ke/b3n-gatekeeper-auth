from __future__ import annotations

import json
import time
import webbrowser

import httpx
import keyring
from rich.console import Console

from gatekeeper_cli.config import APP_DIR, CREDENTIALS_FILE

SERVICE = "b3n-gatekeeper"
console = Console()


def save_credentials(base_url: str, access_token: str, refresh_token: str | None) -> None:
    keyring.set_password(SERVICE, base_url, access_token)
    APP_DIR.mkdir(parents=True, exist_ok=True)
    APP_DIR.chmod(0o700)
    CREDENTIALS_FILE.write_text(
        json.dumps({"base_url": base_url, "refresh_token": refresh_token, "token_type": "gatekeeper_device"}, indent=2)
    )
    CREDENTIALS_FILE.chmod(0o600)


def load_access_token(base_url: str) -> str | None:
    try:
        return keyring.get_password(SERVICE, base_url)
    except Exception:
        return None


def clear_credentials(base_url: str) -> None:
    try:
        keyring.delete_password(SERVICE, base_url)
    except Exception:
        pass
    if CREDENTIALS_FILE.exists():
        CREDENTIALS_FILE.unlink()


def device_login(base_url: str, client_id: str, scope: str) -> None:
    with httpx.Client(base_url=base_url, timeout=20.0) as client:
        response = client.post(
            "/oauth/device_authorization",
            json={"client_id": client_id, "scope": scope, "audience": "gatekeeper-api"},
        )
        response.raise_for_status()
        grant = response.json()
        console.print(f"[bold]Code:[/bold] {grant['user_code']}")
        console.print(grant["verification_uri_complete"])
        try:
            webbrowser.open(grant["verification_uri_complete"])
        except Exception:
            pass
        deadline = time.time() + int(grant["expires_in"])
        while time.time() < deadline:
            token_response = client.post(
                "/oauth/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": grant["device_code"],
                    "client_id": client_id,
                },
            )
            if token_response.status_code == 200:
                token = token_response.json()
                save_credentials(base_url, token["access_token"], token.get("refresh_token"))
                console.print("[green]Logged in[/green]")
                return
            if token_response.status_code not in {400, 428}:
                token_response.raise_for_status()
            time.sleep(int(grant.get("interval", 5)))
    raise RuntimeError("Device login expired")

