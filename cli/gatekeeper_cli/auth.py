from __future__ import annotations

import base64
import json
import os
import time
import webbrowser
from typing import Any

import httpx
import keyring
from rich.console import Console

from gatekeeper_cli.config import APP_DIR, CREDENTIALS_FILE

SERVICE = "b3n-gatekeeper"
console = Console()


def _read_credentials() -> dict[str, Any]:
    if not CREDENTIALS_FILE.exists():
        return {}
    try:
        return json.loads(CREDENTIALS_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _write_credentials(data: dict[str, Any]) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    APP_DIR.chmod(0o700)
    CREDENTIALS_FILE.write_text(json.dumps(data, indent=2))
    CREDENTIALS_FILE.chmod(0o600)


def _jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
    except Exception:
        return {}


def _is_fresh(token: str) -> bool:
    exp = _jwt_claims(token).get("exp")
    if not exp:
        return True
    return int(exp) > int(time.time()) + 60


def _load_stored_access_token(base_url: str, data: dict[str, Any]) -> str | None:
    access_token = data.get("access_token") if data.get("base_url") == base_url else None
    try:
        return keyring.get_password(SERVICE, base_url) or access_token
    except Exception:
        return access_token


def _store_access_token(base_url: str, access_token: str, data: dict[str, Any]) -> None:
    try:
        keyring.set_password(SERVICE, base_url, access_token)
        data.pop("access_token", None)
        data["access_token_storage"] = "keyring"
    except Exception:
        data["access_token"] = access_token
        data["access_token_storage"] = "file"


def save_credentials(
    base_url: str,
    access_token: str,
    refresh_token: str | None,
    *,
    token_response: dict[str, Any] | None = None,
    current_org_id: str | None = None,
) -> None:
    data = _read_credentials()
    data.update(
        {
            "base_url": base_url,
            "refresh_token": refresh_token,
            "token_type": "gatekeeper_device",
            "scope": (token_response or {}).get("scope"),
            "user": (token_response or {}).get("user"),
            "orgs": (token_response or {}).get("orgs") or data.get("orgs") or [],
            "current_org_id": current_org_id or data.get("current_org_id"),
            "updated_at": int(time.time()),
        }
    )
    _store_access_token(base_url, access_token, data)
    _write_credentials(data)


def refresh_access_token(base_url: str) -> str | None:
    data = _read_credentials()
    refresh_token = data.get("refresh_token") if data.get("base_url") == base_url else None
    if not refresh_token:
        return None
    try:
        with httpx.Client(base_url=base_url, timeout=20.0) as client:
            response = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
            if response.status_code != 200:
                return None
            token = response.json()
    except httpx.HTTPError:
        return None
    save_credentials(
        base_url,
        token["access_token"],
        token.get("refresh_token"),
        token_response=token,
        current_org_id=data.get("current_org_id"),
    )
    return token["access_token"]


def load_access_token(base_url: str) -> str | None:
    override = os.environ.get("B3N_GATEKEEPER_TOKEN") or os.environ.get("B3N_GATEKEEPER_ACCESS_TOKEN")
    if override:
        return override
    data = _read_credentials()
    token = _load_stored_access_token(base_url, data)
    if token and _is_fresh(token):
        return token
    return refresh_access_token(base_url)


def save_token_response(base_url: str, token_response: dict[str, Any], *, current_org_id: str | None = None) -> None:
    save_credentials(
        base_url,
        token_response["access_token"],
        token_response.get("refresh_token"),
        token_response=token_response,
        current_org_id=current_org_id,
    )


def credentials_context(base_url: str) -> dict[str, Any]:
    data = _read_credentials()
    if data.get("base_url") != base_url:
        return {}
    return data


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
                current_org_id = None
                try:
                    me = client.get(
                        "/api/v1/auth/me",
                        headers={"Authorization": f"Bearer {token['access_token']}"},
                    )
                    if me.status_code == 200:
                        current_org_id = me.json().get("org_id")
                except httpx.HTTPError:
                    pass
                save_token_response(base_url, token, current_org_id=current_org_id)
                console.print("[green]Logged in[/green]")
                return
            if token_response.status_code not in {400, 428}:
                token_response.raise_for_status()
            time.sleep(int(grant.get("interval", 5)))
    raise RuntimeError("Device login expired")
