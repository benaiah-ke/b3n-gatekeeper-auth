from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import Base, engine
from app.main import app


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

