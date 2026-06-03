from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import pytest
from httpx import ASGITransport, AsyncClient

from app import security
from app.config import settings
from app.database import Base, engine
from app.main import app
from app.security import create_access_token, decode_access_token, public_jwk


@pytest.fixture(autouse=True)
def reset_jwt_key_cache():
    security._keypair_pem.cache_clear()
    yield
    security._keypair_pem.cache_clear()


@pytest.fixture(autouse=True)
async def reset_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


async def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://testserver")


@pytest.mark.asyncio
async def test_signup_login_refresh_and_replay_detection():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "admin@b3n.in", "password": "correct horse battery", "display_name": "Admin"},
        )
        assert signup.status_code == 200
        refresh = signup.json()["refresh_token"]

        login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "admin@b3n.in", "password": "correct horse battery"},
        )
        assert login.status_code == 200
        me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"})
        assert me.status_code == 200
        assert me.json()["user"]["email"] == "admin@b3n.in"

        rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert rotated.status_code == 200

        replay = await ac.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert replay.status_code == 401


@pytest.mark.asyncio
async def test_bad_redirect_is_rejected_for_oauth_client():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "admin@b3n.in", "password": "correct horse battery"},
        )
        access = signup.json()["access_token"]
        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Sentinel",
                "public": True,
                "redirect_uris": ["https://sentinel.b3n.in/callback"],
                "audiences": ["sentinel-api"],
                "scopes": ["auth:read"],
            },
        )
        assert created.status_code == 200
        client_id = created.json()["client_id"]
        authorize = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {access}"},
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://evil.example/callback",
                "code_challenge": "abc",
                "code_challenge_method": "plain",
            },
        )
        assert authorize.status_code == 400


@pytest.mark.asyncio
async def test_mcp_metadata_defaults_and_registered_resource():
    async with await client() as ac:
        root = await ac.get("/.well-known/oauth-protected-resource")
        assert root.status_code == 200
        assert root.json()["authorization_servers"] == ["http://localhost:8000"]


def test_jwt_key_dir_persists_signing_key(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "jwt_private_key_pem", "")
    monkeypatch.setattr(settings, "jwt_public_key_pem", "")
    monkeypatch.setattr(settings, "jwt_key_dir", str(tmp_path))
    security._keypair_pem.cache_clear()

    token = create_access_token(
        subject="user_123",
        audience="gatekeeper-api",
        scopes=["auth:read"],
        token_type="user",
    )
    first_jwk = public_jwk()

    security._keypair_pem.cache_clear()
    claims = decode_access_token(token, audience="gatekeeper-api")

    assert claims["sub"] == "user_123"
    assert public_jwk()["n"] == first_jwk["n"]
    assert (tmp_path / "jwt_private.pem").exists()
    assert (tmp_path / "jwt_public.pem").exists()


@pytest.mark.asyncio
async def test_client_credentials_and_bad_audience():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "admin@b3n.in", "password": "correct horse battery"},
        )
        access = signup.json()["access_token"]
        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Knowhere service",
                "public": False,
                "audiences": ["knowhere-api"],
                "scopes": ["deploy:read"],
            },
        )
        assert created.status_code == 200
        created_client = created.json()

        bad_audience = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": created_client["client_id"],
                "client_secret": created_client["client_secret"],
                "audience": "sentinel-api",
                "scope": "deploy:read",
            },
        )
        assert bad_audience.status_code == 400

        token = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": created_client["client_id"],
                "client_secret": created_client["client_secret"],
                "audience": "knowhere-api",
                "scope": "deploy:read",
            },
        )
        assert token.status_code == 200
        assert token.json()["token_type"] == "Bearer"


@pytest.mark.asyncio
async def test_device_flow_and_api_token_revocation():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "admin@b3n.in", "password": "correct horse battery"},
        )
        access = signup.json()["access_token"]

        device = await ac.post(
            "/oauth/device_authorization",
            json={"client_id": "gatekeeper-cli", "scope": "auth:read", "audience": "gatekeeper-api"},
        )
        assert device.status_code == 200
        grant = device.json()
        pending = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": grant["device_code"],
                "client_id": "gatekeeper-cli",
            },
        )
        assert pending.status_code == 428

        approve = await ac.post(
            "/api/v1/auth/device/approve",
            headers={"Authorization": f"Bearer {access}"},
            json={"user_code": grant["user_code"], "approve": True},
        )
        assert approve.status_code == 200
        token = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": grant["device_code"],
                "client_id": "gatekeeper-cli",
            },
        )
        assert token.status_code == 200

        created = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "test token",
                "token_type": "personal",
                "scopes": ["auth:read"],
                "audiences": ["gatekeeper-api"],
            },
        )
        assert created.status_code == 200
        raw_token = created.json()["token"]
        introspected = await ac.post("/oauth/introspect", data={"token": raw_token})
        assert introspected.json()["active"] is True
        revoked = await ac.delete(
            f"/api/v1/tokens/{created.json()['id']}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert revoked.status_code == 200
        introspected_again = await ac.post("/oauth/introspect", data={"token": raw_token})
        assert introspected_again.json()["active"] is False
