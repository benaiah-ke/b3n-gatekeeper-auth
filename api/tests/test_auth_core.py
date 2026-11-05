from __future__ import annotations

import asyncio
import json
import os
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import CredentialDeviceType

from app import alerts, ops, security, services
from app import main as main_module
from app.config import settings
from app.database import Base, async_session_factory, engine
from app.main import app
from app.models import (
    AuditEvent,
    Identity,
    InstallClaim,
    Membership,
    OneTimeCode,
    Organization,
    RateLimitBucket,
    Role,
    Session,
    User,
    WebAuthnChallenge,
    WebAuthnCredential,
)
from app.security import create_access_token, decode_access_token, public_jwk, totp_code


@pytest.fixture(autouse=True)
def reset_jwt_key_cache():
    security._keypair_pem.cache_clear()
    yield
    security._keypair_pem.cache_clear()


@pytest.fixture(autouse=True)
async def reset_db():
    alerts._recent.clear()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


async def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://testserver")


async def register(ac: AsyncClient, json: dict):
    """Sign up the first owner; later accounts are created directly because signup is closed."""
    async with async_session_factory() as db:
        if not (await db.execute(select(User.id).limit(1))).scalar_one_or_none():
            return await ac.post("/api/v1/auth/signup", json=json)
        user = await services.create_user(
            db, email=json["email"], password=json["password"], display_name=json.get("display_name")
        )
        if not await services.org_roles(db, user.id):
            org = await services.ensure_bootstrap(db)
            viewer = (
                await db.execute(select(Role).where(Role.org_id == org.id, Role.name == "viewer"))
            ).scalar_one()
            db.add(Membership(org_id=org.id, user_id=user.id, role_id=viewer.id, status="active"))
            await db.commit()
    return await ac.post("/api/v1/auth/login", json={"email": json["email"], "password": json["password"]})


@pytest.mark.asyncio
async def test_version_reports_release_metadata_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "gatekeeper_image_tag", "abc123")
    monkeypatch.setattr(settings, "git_sha", "abc123def456")

    async with await client() as ac:
        response = await ac.get("/version")

    assert response.status_code == 200
    assert response.json() == {
        "service": "gatekeeper-api",
        "version": settings.app_version,
        "environment": settings.app_env,
        "issuer": settings.issuer,
        "image_tag": "abc123",
        "git_sha": "abc123def456",
    }


@pytest.mark.asyncio
async def test_signup_login_refresh_and_replay_detection():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery", "display_name": "Admin"},
        )
        assert signup.status_code == 200
        refresh = signup.json()["refresh_token"]
        assert ac.cookies.get(settings.refresh_cookie_name) == refresh

        login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        assert login.status_code == 200
        assert ac.cookies.get(settings.refresh_cookie_name) == login.json()["refresh_token"]
        me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"})
        assert me.status_code == 200
        assert me.json()["user"]["email"] == "admin@example.com"

        rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert rotated.status_code == 200

        replay = await ac.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert replay.status_code == 401


@pytest.mark.asyncio
async def test_signup_is_closed_after_the_first_owner():
    async with await client() as ac:
        first = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "first@example.com", "password": "correct horse battery"},
        )
        assert first.status_code == 200
        assert first.json()["orgs"][0]["role"] == "owner"
        for email in ("outsider@example.com", str(settings.bootstrap_admin_email)):
            refused = await ac.post("/api/v1/auth/signup", json={"email": email, "password": "correct horse battery"})
            assert refused.status_code == 403

    async with async_session_factory() as db:
        assert set((await db.execute(select(User.email))).scalars()) == {"first@example.com"}
        refusals = await db.execute(select(AuditEvent).where(AuditEvent.action == "auth.signup.refused"))
        assert len(refusals.scalars().all()) == 2


@pytest.mark.asyncio
async def test_first_signup_race_is_closed_by_a_database_claim():
    async with async_session_factory() as db:
        db.add(InstallClaim(name="first-owner", user_id="concurrent-signup"))
        await db.commit()
    async with await client() as ac:
        late = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "late@example.com", "password": "correct horse battery"},
        )
        assert late.status_code == 403
    async with async_session_factory() as db:
        assert (await db.execute(select(User.id))).first() is None


@pytest.mark.asyncio
async def test_email_code_never_creates_accounts(monkeypatch):
    monkeypatch.setattr(settings, "email_code_login_enabled", True)
    async with await client() as ac:
        requested = await ac.post("/api/v1/auth/email-code/request", json={"email": "stranger@example.com"})
        assert requested.status_code == 200
        assert requested.json() == {"status": "sent"}
        async with async_session_factory() as db:
            assert (await db.execute(select(OneTimeCode.id))).first() is None
            stale_code = await services.create_one_time_code(db, email="stranger@example.com", purpose="login")
            await db.commit()

        for code in (stale_code, "WRONGCODE"):
            verified = await ac.post(
                "/api/v1/auth/email-code/verify",
                json={"email": "stranger@example.com", "code": code},
            )
            assert verified.status_code == 401
            assert verified.json()["detail"] == "Invalid or expired code"

    async with async_session_factory() as db:
        assert (await db.execute(select(User.id))).first() is None


@pytest.mark.asyncio
async def test_email_code_routes_are_off_by_default():
    async with await client() as ac:
        await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        requested = await ac.post("/api/v1/auth/email-code/request", json={"email": "owner@example.com"})
        assert requested.status_code == 403
        async with async_session_factory() as db:
            code = await services.create_one_time_code(db, email="owner@example.com", purpose="login")
            await db.commit()
        verified = await ac.post("/api/v1/auth/email-code/verify", json={"email": "owner@example.com", "code": code})
        assert verified.status_code == 403


@pytest.mark.asyncio
async def test_email_code_login_enforces_mfa_and_client_policy(monkeypatch):
    monkeypatch.setattr(settings, "email_code_login_enabled", True)
    password = "correct horse battery"

    async def email_code(email: str) -> str:
        async with async_session_factory() as db:
            code = await services.create_one_time_code(db, email=email, purpose="login")
            await db.commit()
        return code

    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        secret = (await ac.post("/api/v1/auth/mfa/totp/setup", headers=owner_headers)).json()["secret"]
        enabled = await ac.post(
            "/api/v1/auth/mfa/totp/enable", headers=owner_headers, json={"code": totp_code(secret)}
        )
        assert enabled.status_code == 200

        code = await email_code("owner@example.com")
        without_totp = await ac.post(
            "/api/v1/auth/email-code/verify", json={"email": "owner@example.com", "code": code}
        )
        assert without_totp.status_code == 401
        assert without_totp.json()["detail"] == "TOTP code required"
        with_totp = await ac.post(
            "/api/v1/auth/email-code/verify",
            json={"email": "owner@example.com", "code": code, "totp_code": totp_code(secret)},
        )
        assert with_totp.status_code == 200
        assert decode_access_token(with_totp.json()["access_token"])["amr"] == ["email", "otp"]

        strict = await ac.post(
            "/api/v1/clients",
            headers=owner_headers,
            json={"name": "Strict", "public": True, "audiences": ["strict-api"], "require_mfa": True},
        )
        member = await register(ac, json={"email": "member@example.com", "password": password})
        no_mfa = await ac.post(
            "/api/v1/auth/email-code/verify",
            json={
                "email": "member@example.com",
                "code": await email_code("member@example.com"),
                "client_id": strict.json()["client_id"],
            },
        )
        assert no_mfa.status_code == 403
        assert no_mfa.json()["detail"] == "MFA enrollment required for this client"

        async with async_session_factory() as db:
            (await db.get(User, member.json()["user"]["id"])).disabled = True
            await db.commit()
        disabled = await ac.post(
            "/api/v1/auth/email-code/verify",
            json={"email": "member@example.com", "code": await email_code("member@example.com")},
        )
        assert disabled.status_code == 401


@pytest.mark.asyncio
async def test_refresh_keeps_the_scopes_and_audience_granted_at_login():
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        product = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {owner.json()['access_token']}"},
            json={
                "name": "Product",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["product-api"],
                "scopes": ["auth:read", "mcp:tools", "mcp:resources"],
            },
        )
        login = {"email": "owner@example.com", "password": password, "client_id": product.json()["client_id"]}

        narrow = await ac.post("/api/v1/auth/login", json={**login, "scope": "mcp:tools"})
        assert narrow.json()["scope"] == "mcp:tools"
        refreshed = await ac.post("/api/v1/auth/refresh", json={"refresh_token": narrow.json()["refresh_token"]})
        assert refreshed.json()["scope"] == "mcp:tools"
        assert decode_access_token(refreshed.json()["access_token"], audience="product-api")["scope"] == "mcp:tools"
        oauth_refreshed = await ac.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": refreshed.json()["refresh_token"]},
        )
        assert oauth_refreshed.json()["scope"] == "mcp:tools"

        hosted_ui = await ac.post("/api/v1/auth/login", json={**login, "audience": settings.issuer})
        ui_refreshed = await ac.post("/api/v1/auth/refresh", json={"refresh_token": hosted_ui.json()["refresh_token"]})
        assert decode_access_token(ui_refreshed.json()["access_token"])["aud"] == settings.issuer
        me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {ui_refreshed.json()['access_token']}"})
        assert me.status_code == 200


@pytest.mark.asyncio
async def test_refresh_can_rotate_from_browser_refresh_cookie():
    async with await client() as ac:
        signup = await register(
            ac,
            json={
                "email": "admin@example.com",
                "password": "correct horse battery",
                "display_name": "Admin User",
            },
        )
        assert signup.status_code == 200
        first_refresh = signup.json()["refresh_token"]
        assert ac.cookies.get(settings.refresh_cookie_name) == first_refresh

        rotated = await ac.post("/api/v1/auth/refresh", json={})
        assert rotated.status_code == 200
        second_refresh = rotated.json()["refresh_token"]
        assert second_refresh != first_refresh
        assert ac.cookies.get(settings.refresh_cookie_name) == second_refresh

        replay = await ac.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
        assert replay.status_code == 401


@pytest.mark.asyncio
async def test_first_signup_without_bootstrap_email_becomes_owner():
    async with await client() as ac:
        signup = await register(
            ac,
            json={
                "email": "operator@example.com",
                "password": "correct horse battery",
                "display_name": "Operator",
            },
        )
        assert signup.status_code == 200
        payload = signup.json()
        assert payload["orgs"][0]["role"] == "owner"
        assert "*" in payload["orgs"][0]["permissions"]

        setup = await ac.get(
            "/api/v1/setup/status",
            headers={"Authorization": f"Bearer {payload['access_token']}"},
        )
        assert setup.status_code == 200
        assert setup.json()["owner_exists"] is True
        assert setup.json()["can_manage_clients"] is True

        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {payload['access_token']}"},
            json={
                "name": "Example Web",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "allowed_origins": ["https://app.example.com"],
                "audiences": ["example-api"],
                "scopes": ["auth:read"],
            },
        )
        assert created.status_code == 200
        created_client = created.json()
        assert created_client["client_id"].startswith("gkc_")
        assert "client_secret" not in created_client

        app_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "operator@example.com",
                "password": "correct horse battery",
                "client_id": created_client["client_id"],
                "audience": settings.issuer,
            },
        )
        assert app_login.status_code == 200
        sessions = await ac.get(
            "/api/v1/sessions",
            headers={"Authorization": f"Bearer {app_login.json()['access_token']}"},
        )
        assert sessions.status_code == 200
        current_session = next(item for item in sessions.json() if item["current"])
        assert current_session["auth_client_id"] == created_client["id"]
        assert current_session["client_id"] == created_client["client_id"]
        assert current_session["client_name"] == "Example Web"
        assert current_session["client_public"] is True


@pytest.mark.asyncio
async def test_client_create_accepts_operator_stable_client_id_and_rejects_duplicates():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]

        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Sentinel Control Plane",
                "client_id": "sentinel-control-plane",
                "public": False,
                "redirect_uris": ["https://sentinel.b3n.in/api/v1/auth/callback"],
                "allowed_origins": ["https://sentinel.b3n.in"],
                "audiences": ["sentinel-api"],
                "scopes": ["openid", "profile", "email", "auth:read"],
                "require_mfa": True,
            },
        )
        assert created.status_code == 200
        payload = created.json()
        assert payload["client_id"] == "sentinel-control-plane"
        assert payload["public"] is False
        assert payload["require_mfa"] is True
        assert payload["client_secret"].startswith("gkcs_")

        async with async_session_factory() as session:
            result = await session.execute(
                select(AuditEvent).where(
                    AuditEvent.action == "client.create",
                    AuditEvent.target_id == payload["id"],
                )
            )
            event = result.scalar_one()
            assert event.details["client_id"] == "sentinel-control-plane"
            assert event.details["operator_specified_client_id"] is True
            assert event.details["public"] is False

        duplicate = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Duplicate Sentinel",
                "client_id": "sentinel-control-plane",
                "public": True,
                "redirect_uris": ["https://sentinel.b3n.in/api/v1/auth/callback"],
                "allowed_origins": ["https://sentinel.b3n.in"],
                "audiences": ["sentinel-api"],
                "scopes": ["auth:read"],
            },
        )
        assert duplicate.status_code == 409


@pytest.mark.asyncio
async def test_client_create_rejects_reserved_or_non_normalized_stable_client_ids():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]

        for client_id in ("gkc_operator", "Sentinel-Control-Plane", "ab", "sentinel control"):
            response = await ac.post(
                "/api/v1/clients",
                headers={"Authorization": f"Bearer {access}"},
                json={
                    "name": "Invalid Client",
                    "client_id": client_id,
                    "public": True,
                    "redirect_uris": ["https://sentinel.b3n.in/api/v1/auth/callback"],
                    "allowed_origins": ["https://sentinel.b3n.in"],
                    "audiences": ["sentinel-api"],
                    "scopes": ["auth:read"],
                },
            )
            assert response.status_code == 422


@pytest.mark.asyncio
async def test_org_creation_seeds_owner_membership_and_session_switching():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]

        created_org = await ac.post(
            "/api/v1/orgs",
            headers={"Authorization": f"Bearer {access}"},
            json={"name": "Second Product", "slug": "second-product"},
        )
        assert created_org.status_code == 200
        second_org = created_org.json()
        assert second_org["role"] == "owner"
        assert second_org["permissions"] == ["*"]

        cross_org_roles = await ac.get(
            f"/api/v1/roles?org_id={second_org['id']}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert cross_org_roles.status_code == 403

        cross_org_client = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Second Product API",
                "org_id": second_org["id"],
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "allowed_origins": ["https://app.example.com"],
                "audiences": ["second-product-api"],
                "scopes": ["openid", "profile", "email", "api:read", "auth:read"],
                "require_org_membership": True,
            },
        )
        assert cross_org_client.status_code == 403

        switched = await ac.post(
            "/api/v1/auth/session/switch-org",
            headers={"Authorization": f"Bearer {access}"},
            json={"org_id": second_org["id"]},
        )
        assert switched.status_code == 200
        second_access = switched.json()["access_token"]

        roles = await ac.get(
            f"/api/v1/roles?org_id={second_org['id']}",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        assert roles.status_code == 200
        assert {role["name"] for role in roles.json()} == {"owner", "admin", "operator", "viewer"}

        created_client = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {second_access}"},
            json={
                "name": "Second Product API",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "allowed_origins": ["https://app.example.com"],
                "audiences": ["second-product-api"],
                "scopes": ["openid", "profile", "email", "api:read", "auth:read"],
                "require_org_membership": True,
            },
        )
        assert created_client.status_code == 200
        assert created_client.json()["org_id"] == second_org["id"]

        switched = await ac.post(
            "/api/v1/auth/session/switch-org",
            headers={"Authorization": f"Bearer {second_access}"},
            json={
                "org_id": second_org["id"],
                "client_id": created_client.json()["client_id"],
                "scope": "api:read",
                "audience": "second-product-api",
            },
        )
        assert switched.status_code == 400
        switched_claims = decode_access_token(second_access)
        assert switched_claims["org_id"] == second_org["id"]
        assert switched_claims["org_slug"] == "second-product"
        assert switched_claims["org_role"] == "owner"
        assert switched_claims["permissions"] == ["*"]

        setup = await ac.get(
            "/api/v1/setup/status",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        assert setup.status_code == 200
        assert setup.json()["org"]["id"] == second_org["id"]
        assert setup.json()["can_manage_clients"] is True

        other_signup = await register(
            ac,
            json={"email": "other@example.com", "password": "correct horse battery"},
        )
        assert other_signup.status_code == 200
        denied = await ac.post(
            "/api/v1/auth/session/switch-org",
            headers={"Authorization": f"Bearer {other_signup.json()['access_token']}"},
            json={"org_id": second_org["id"]},
        )
        assert denied.status_code == 403
        assert denied.json()["detail"] == "Organization membership required"


@pytest.mark.asyncio
async def test_platform_admin_gates_orgs_reserved_audience_clients_and_providers(monkeypatch):
    password = "correct horse battery"
    client_body = {"name": "Product", "public": True, "redirect_uris": ["https://app.example.com/callback"]}
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        org_id = owner.json()["orgs"][0]["id"]
        admin = await register(ac, json={"email": "admin@corp.example.com", "password": password})
        admin_id = admin.json()["user"]["id"]
        promoted = await ac.put(
            f"/api/v1/users/{admin_id}/membership",
            headers=owner_headers,
            json={"org_id": org_id, "role": "admin", "status": "active"},
        )
        assert promoted.status_code == 200
        admin_login = await ac.post(
            "/api/v1/auth/login", json={"email": "admin@corp.example.com", "password": password}
        )
        assert "admin:*" in admin_login.json()["scope"].split()
        admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}

        denied_org = await ac.post("/api/v1/orgs", headers=admin_headers, json={"name": "X", "slug": "x"})
        assert denied_org.status_code == 403
        for extra in ({"audiences": ["sentinel-api"]}, {"audiences": ["my-api"], "mcp_resource_uri": "knowhere-api"}):
            denied = await ac.post("/api/v1/clients", headers=admin_headers, json={**client_body, **extra})
            assert denied.status_code == 403
        own_client = await ac.post(
            "/api/v1/clients", headers=admin_headers, json={**client_body, "audiences": ["my-api"]}
        )
        assert own_client.status_code == 200
        retarget = await ac.patch(
            f"/api/v1/clients/{own_client.json()['id']}",
            headers=admin_headers,
            json={"audiences": ["gatekeeper-api"]},
        )
        assert retarget.status_code == 403
        first_party = await ac.post(
            "/api/v1/clients",
            headers=owner_headers,
            json={**client_body, "public": False, "audiences": ["sentinel-api"]},
        )
        assert first_party.status_code == 200
        first_party_id = first_party.json()["id"]
        rename = await ac.patch(f"/api/v1/clients/{first_party_id}", headers=admin_headers, json={"name": "Mine"})
        assert rename.status_code == 403
        rotate = await ac.post(f"/api/v1/clients/{first_party_id}/rotate-secret", headers=admin_headers)
        assert rotate.status_code == 403
        assert (await ac.get("/api/v1/auth/oauth/providers/admin", headers=admin_headers)).status_code == 403

        service = await ac.post(
            "/api/v1/tokens",
            headers=owner_headers,
            json={"name": "owner service", "token_type": "service", "org_id": org_id, "scopes": ["*"]},
        )
        service_headers = {"Authorization": f"Bearer {service.json()['token']}"}
        service_org = await ac.post("/api/v1/orgs", headers=service_headers, json={"name": "S", "slug": "s"})
        assert service_org.status_code == 403
        assert (await ac.get("/api/v1/auth/oauth/providers/admin", headers=service_headers)).status_code == 403

        owner_org = await ac.post("/api/v1/orgs", headers=owner_headers, json={"name": "O", "slug": "o"})
        assert owner_org.status_code == 200
        monkeypatch.setattr(settings, "platform_admin_user_ids", admin_id)
        allowed = await ac.post("/api/v1/orgs", headers=admin_headers, json={"name": "A", "slug": "a"})
        assert allowed.status_code == 200


@pytest.mark.asyncio
async def test_org_admin_cannot_update_another_organization(monkeypatch):
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        bootstrap_id = owner.json()["orgs"][0]["id"]
        second = await ac.post("/api/v1/orgs", headers=owner_headers, json={"name": "Second", "slug": "second"})
        switched = await ac.post(
            "/api/v1/auth/session/switch-org", headers=owner_headers, json={"org_id": second.json()["id"]}
        )
        invite = await ac.post(
            "/api/v1/invitations",
            headers={"Authorization": f"Bearer {switched.json()['access_token']}"},
            json={"email": "tenant@example.com", "org_id": second.json()["id"], "role": "owner"},
        )
        monkeypatch.setattr(settings, "signup_mode", "invite")
        tenant = await ac.post(
            "/api/v1/auth/invitations/accept",
            json={"email": "tenant@example.com", "password": password, "token": invite.json()["token"]},
        )
        tenant_headers = {"Authorization": f"Bearer {tenant.json()['access_token']}"}

        denied = await ac.patch(f"/api/v1/orgs/{bootstrap_id}", headers=tenant_headers, json={"name": "Taken"})
        assert denied.status_code == 403
        own = await ac.patch(f"/api/v1/orgs/{second.json()['id']}", headers=tenant_headers, json={"name": "Mine"})
        assert own.status_code == 200


@pytest.mark.asyncio
async def test_client_scopes_are_capped_to_the_creators_permissions(monkeypatch):
    password = "correct horse battery"
    body = {
        "name": "Product",
        "public": True,
        "redirect_uris": ["https://app.example.com/callback"],
        "audiences": ["product-api"],
    }

    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_token = owner.json()["access_token"]
        bootstrap_id = owner.json()["orgs"][0]["id"]
        admin = await register(ac, json={"email": "admin@corp.example.com", "password": password})
        await ac.put(
            f"/api/v1/users/{admin.json()['user']['id']}/membership",
            headers=bearer(owner_token),
            json={"org_id": bootstrap_id, "role": "admin", "status": "active"},
        )
        admin_token = (
            await ac.post("/api/v1/auth/login", json={"email": "admin@corp.example.com", "password": password})
        ).json()["access_token"]

        for scopes in (["admin:*"], ["*"], ["api:read"], ["token:*"]):
            denied = await ac.post("/api/v1/clients", headers=bearer(admin_token), json={**body, "scopes": scopes})
            assert denied.status_code == 403
        allowed = await ac.post(
            "/api/v1/clients",
            headers=bearer(admin_token),
            json={**body, "scopes": ["openid", "auth:read", "mcp:tools"]},
        )
        assert allowed.status_code == 200
        widened = await ac.patch(
            f"/api/v1/clients/{allowed.json()['id']}", headers=bearer(admin_token), json={"scopes": ["token:*"]}
        )
        assert widened.status_code == 403

        second = await ac.post("/api/v1/orgs", headers=bearer(owner_token), json={"name": "Second", "slug": "second"})
        switched = await ac.post(
            "/api/v1/auth/session/switch-org", headers=bearer(owner_token), json={"org_id": second.json()["id"]}
        )
        invite = await ac.post(
            "/api/v1/invitations",
            headers=bearer(switched.json()["access_token"]),
            json={"email": "tenant@example.com", "org_id": second.json()["id"], "role": "owner"},
        )
        monkeypatch.setattr(settings, "signup_mode", "invite")
        tenant_token = (
            await ac.post(
                "/api/v1/auth/invitations/accept",
                json={"email": "tenant@example.com", "password": password, "token": invite.json()["token"]},
            )
        ).json()["access_token"]
        for scopes, expected in ((["*"], 403), (["admin:*"], 403), (["api:read"], 200)):
            created = await ac.post("/api/v1/clients", headers=bearer(tenant_token), json={**body, "scopes": scopes})
            assert created.status_code == expected

        platform = await ac.post("/api/v1/clients", headers=bearer(owner_token), json={**body, "scopes": ["admin:*"]})
        assert platform.status_code == 200


@pytest.mark.asyncio
async def test_service_principals_list_only_their_own_org():
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        bootstrap_id = owner.json()["orgs"][0]["id"]
        await ac.post("/api/v1/orgs", headers=owner_headers, json={"name": "Second", "slug": "second"})
        service = await ac.post(
            "/api/v1/tokens",
            headers=owner_headers,
            json={"name": "automation", "token_type": "service", "scopes": ["auth:read"]},
        )
        listed = await ac.get("/api/v1/orgs", headers={"Authorization": f"Bearer {service.json()['token']}"})
        assert listed.status_code == 200
        assert [org["id"] for org in listed.json()] == [bootstrap_id]


@pytest.mark.asyncio
async def test_client_management_is_scoped_to_current_organization():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        first_access = signup.json()["access_token"]
        first_org_id = signup.json()["orgs"][0]["id"]

        first_client = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {first_access}"},
            json={
                "name": "First API",
                "public": False,
                "redirect_uris": ["https://first.example.com/callback"],
                "allowed_origins": ["https://first.example.com"],
                "audiences": ["first-api"],
                "scopes": ["openid", "profile", "api:read"],
            },
        )
        assert first_client.status_code == 200
        assert first_client.json()["org_id"] == first_org_id

        created_org = await ac.post(
            "/api/v1/orgs",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"name": "Second Product", "slug": "second-product"},
        )
        assert created_org.status_code == 200
        second_org_id = created_org.json()["id"]

        cross_org_create = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {first_access}"},
            json={
                "name": "Forbidden Second API",
                "org_id": second_org_id,
                "public": True,
                "redirect_uris": ["https://second.example.com/callback"],
                "allowed_origins": ["https://second.example.com"],
                "audiences": ["second-api"],
                "scopes": ["openid", "profile", "api:read"],
            },
        )
        assert cross_org_create.status_code == 403

        switched = await ac.post(
            "/api/v1/auth/session/switch-org",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"org_id": second_org_id},
        )
        assert switched.status_code == 200
        second_access = switched.json()["access_token"]

        second_client = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {second_access}"},
            json={
                "name": "Second API",
                "public": False,
                "redirect_uris": ["https://second.example.com/callback"],
                "allowed_origins": ["https://second.example.com"],
                "audiences": ["second-api"],
                "scopes": ["openid", "profile", "api:read"],
            },
        )
        assert second_client.status_code == 200
        assert second_client.json()["org_id"] == second_org_id

        first_list = await ac.get("/api/v1/clients", headers={"Authorization": f"Bearer {first_access}"})
        assert first_list.status_code == 200
        first_client_ids = {client["id"] for client in first_list.json()}
        assert first_client.json()["id"] in first_client_ids
        assert second_client.json()["id"] not in first_client_ids

        second_list = await ac.get("/api/v1/clients", headers={"Authorization": f"Bearer {second_access}"})
        assert second_list.status_code == 200
        second_client_ids = {client["id"] for client in second_list.json()}
        assert second_client.json()["id"] in second_client_ids
        assert first_client.json()["id"] not in second_client_ids

        forbidden_patch = await ac.patch(
            f"/api/v1/clients/{second_client.json()['id']}",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"enabled": False},
        )
        assert forbidden_patch.status_code == 404

        forbidden_rotate = await ac.post(
            f"/api/v1/clients/{second_client.json()['id']}/rotate-secret",
            headers={"Authorization": f"Bearer {first_access}"},
        )
        assert forbidden_rotate.status_code == 404

        forbidden_delete = await ac.delete(
            f"/api/v1/clients/{second_client.json()['id']}",
            headers={"Authorization": f"Bearer {first_access}"},
        )
        assert forbidden_delete.status_code == 404

        rotated = await ac.post(
            f"/api/v1/clients/{second_client.json()['id']}/rotate-secret",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        assert rotated.status_code == 200
        assert rotated.json()["client_secret"].startswith("gkcs_")

        deleted = await ac.delete(
            f"/api/v1/clients/{second_client.json()['id']}",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        assert deleted.status_code == 200


@pytest.mark.asyncio
async def test_setup_resources_are_scoped_to_current_organization():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        first_access = signup.json()["access_token"]
        first_org_id = signup.json()["orgs"][0]["id"]

        first_workspace = await ac.post(
            "/api/v1/workspaces",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"org_id": first_org_id, "name": "First Workspace", "slug": "first-workspace"},
        )
        assert first_workspace.status_code == 200
        first_project = await ac.post(
            "/api/v1/projects",
            headers={"Authorization": f"Bearer {first_access}"},
            json={
                "org_id": first_org_id,
                "workspace_id": first_workspace.json()["id"],
                "name": "First API",
                "slug": "first-api",
                "audience": "first-api",
            },
        )
        assert first_project.status_code == 200
        first_role = await ac.post(
            "/api/v1/roles",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"org_id": first_org_id, "name": "support-first", "permissions": ["auth:read"]},
        )
        assert first_role.status_code == 200

        created_org = await ac.post(
            "/api/v1/orgs",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"name": "Second Product", "slug": "second-product-setup"},
        )
        assert created_org.status_code == 200
        second_org_id = created_org.json()["id"]

        cross_workspace = await ac.post(
            "/api/v1/workspaces",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"org_id": second_org_id, "name": "Forbidden Workspace", "slug": "forbidden-workspace"},
        )
        assert cross_workspace.status_code == 403
        cross_project = await ac.post(
            "/api/v1/projects",
            headers={"Authorization": f"Bearer {first_access}"},
            json={
                "org_id": second_org_id,
                "name": "Forbidden API",
                "slug": "forbidden-api",
                "audience": "forbidden-api",
            },
        )
        assert cross_project.status_code == 403
        cross_role = await ac.post(
            "/api/v1/roles",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"org_id": second_org_id, "name": "support-second", "permissions": ["auth:read"]},
        )
        assert cross_role.status_code == 403

        switched = await ac.post(
            "/api/v1/auth/session/switch-org",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"org_id": second_org_id},
        )
        assert switched.status_code == 200
        second_access = switched.json()["access_token"]

        second_workspace = await ac.post(
            "/api/v1/workspaces",
            headers={"Authorization": f"Bearer {second_access}"},
            json={"org_id": second_org_id, "name": "Second Workspace", "slug": "second-workspace"},
        )
        assert second_workspace.status_code == 200
        wrong_workspace_project = await ac.post(
            "/api/v1/projects",
            headers={"Authorization": f"Bearer {second_access}"},
            json={
                "org_id": second_org_id,
                "workspace_id": first_workspace.json()["id"],
                "name": "Wrong Workspace API",
                "slug": "wrong-workspace-api",
                "audience": "wrong-workspace-api",
            },
        )
        assert wrong_workspace_project.status_code == 404

        second_project = await ac.post(
            "/api/v1/projects",
            headers={"Authorization": f"Bearer {second_access}"},
            json={
                "org_id": second_org_id,
                "workspace_id": second_workspace.json()["id"],
                "name": "Second API",
                "slug": "second-api",
                "audience": "second-api",
            },
        )
        assert second_project.status_code == 200
        second_role = await ac.post(
            "/api/v1/roles",
            headers={"Authorization": f"Bearer {second_access}"},
            json={"org_id": second_org_id, "name": "support-second", "permissions": ["auth:read"]},
        )
        assert second_role.status_code == 200

        first_workspaces = await ac.get("/api/v1/workspaces", headers={"Authorization": f"Bearer {first_access}"})
        assert first_workspaces.status_code == 200
        assert {workspace["id"] for workspace in first_workspaces.json()} == {first_workspace.json()["id"]}
        second_workspaces = await ac.get("/api/v1/workspaces", headers={"Authorization": f"Bearer {second_access}"})
        assert second_workspaces.status_code == 200
        assert {workspace["id"] for workspace in second_workspaces.json()} == {second_workspace.json()["id"]}

        first_projects = await ac.get("/api/v1/projects", headers={"Authorization": f"Bearer {first_access}"})
        assert first_projects.status_code == 200
        assert {project["id"] for project in first_projects.json()} == {first_project.json()["id"]}
        second_projects = await ac.get("/api/v1/projects", headers={"Authorization": f"Bearer {second_access}"})
        assert second_projects.status_code == 200
        assert {project["id"] for project in second_projects.json()} == {second_project.json()["id"]}

        first_roles = await ac.get("/api/v1/roles", headers={"Authorization": f"Bearer {first_access}"})
        assert first_roles.status_code == 200
        first_role_names = {role["name"] for role in first_roles.json()}
        assert "support-first" in first_role_names
        assert "support-second" not in first_role_names

        second_roles = await ac.get("/api/v1/roles", headers={"Authorization": f"Bearer {second_access}"})
        assert second_roles.status_code == 200
        second_role_names = {role["name"] for role in second_roles.json()}
        assert "support-second" in second_role_names
        assert "support-first" not in second_role_names

        cross_org_project_list = await ac.get(
            f"/api/v1/projects?org_id={second_org_id}",
            headers={"Authorization": f"Bearer {first_access}"},
        )
        assert cross_org_project_list.status_code == 403


@pytest.mark.asyncio
async def test_admin_visibility_is_scoped_to_current_organization():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert owner.status_code == 200
        first_access = owner.json()["access_token"]
        first_org_id = owner.json()["orgs"][0]["id"]

        first_only_user = await register(
            ac,
            json={"email": "first-only@example.com", "password": "correct horse battery"},
        )
        assert first_only_user.status_code == 200
        first_only_user_id = first_only_user.json()["user"]["id"]

        first_invitation = await ac.post(
            "/api/v1/invitations",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"email": "first-invite@example.com", "org_id": first_org_id, "role": "viewer"},
        )
        assert first_invitation.status_code == 200
        first_mcp_resource = await ac.post(
            "/api/v1/mcp/resources",
            headers={"Authorization": f"Bearer {first_access}"},
            json={
                "name": "First MCP",
                "org_id": first_org_id,
                "resource_uri": "https://first-mcp.example.com",
                "scopes": ["mcp:tools"],
            },
        )
        assert first_mcp_resource.status_code == 200
        assert first_mcp_resource.json()["org_id"] == first_org_id

        created_org = await ac.post(
            "/api/v1/orgs",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"name": "Second Product", "slug": "second-product-admin"},
        )
        assert created_org.status_code == 200
        second_org_id = created_org.json()["id"]
        switched = await ac.post(
            "/api/v1/auth/session/switch-org",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"org_id": second_org_id},
        )
        assert switched.status_code == 200
        second_access = switched.json()["access_token"]

        second_invitation = await ac.post(
            "/api/v1/invitations",
            headers={"Authorization": f"Bearer {second_access}"},
            json={"email": "second-invite@example.com", "org_id": second_org_id, "role": "viewer"},
        )
        assert second_invitation.status_code == 200
        second_mcp_resource = await ac.post(
            "/api/v1/mcp/resources",
            headers={"Authorization": f"Bearer {second_access}"},
            json={
                "name": "Second MCP",
                "org_id": second_org_id,
                "resource_uri": "https://second-mcp.example.com",
                "scopes": ["mcp:tools"],
            },
        )
        assert second_mcp_resource.status_code == 200
        assert second_mcp_resource.json()["org_id"] == second_org_id

        first_users = await ac.get("/api/v1/users", headers={"Authorization": f"Bearer {first_access}"})
        assert first_users.status_code == 200
        assert "first-only@example.com" in {user["email"] for user in first_users.json()}
        second_users = await ac.get("/api/v1/users", headers={"Authorization": f"Bearer {second_access}"})
        assert second_users.status_code == 200
        assert "first-only@example.com" not in {user["email"] for user in second_users.json()}

        hidden_user = await ac.get(
            f"/api/v1/users/{first_only_user_id}",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        assert hidden_user.status_code == 404
        hidden_user_update = await ac.patch(
            f"/api/v1/users/{first_only_user_id}",
            headers={"Authorization": f"Bearer {second_access}"},
            json={"display_name": "Should Not Apply"},
        )
        assert hidden_user_update.status_code == 404
        hidden_user_sessions = await ac.post(
            f"/api/v1/users/{first_only_user_id}/sessions/revoke",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        assert hidden_user_sessions.status_code == 404
        hidden_user_mfa = await ac.post(
            f"/api/v1/users/{first_only_user_id}/mfa/totp/reset",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        assert hidden_user_mfa.status_code == 404

        first_invitations = await ac.get("/api/v1/invitations", headers={"Authorization": f"Bearer {first_access}"})
        assert first_invitations.status_code == 200
        assert {item["email"] for item in first_invitations.json()} == {"first-invite@example.com"}
        second_invitations = await ac.get("/api/v1/invitations", headers={"Authorization": f"Bearer {second_access}"})
        assert second_invitations.status_code == 200
        assert {item["email"] for item in second_invitations.json()} == {"second-invite@example.com"}

        cross_org_invitation_list = await ac.get(
            f"/api/v1/invitations?org_id={second_org_id}",
            headers={"Authorization": f"Bearer {first_access}"},
        )
        assert cross_org_invitation_list.status_code == 403
        cross_org_invitation_revoke = await ac.delete(
            f"/api/v1/invitations/{second_invitation.json()['id']}",
            headers={"Authorization": f"Bearer {first_access}"},
        )
        assert cross_org_invitation_revoke.status_code == 404

        first_mcp_resources = await ac.get("/api/v1/mcp/resources", headers={"Authorization": f"Bearer {first_access}"})
        assert first_mcp_resources.status_code == 200
        assert {item["id"] for item in first_mcp_resources.json()} == {first_mcp_resource.json()["id"]}
        second_mcp_resources = await ac.get(
            "/api/v1/mcp/resources",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        assert second_mcp_resources.status_code == 200
        assert {item["id"] for item in second_mcp_resources.json()} == {second_mcp_resource.json()["id"]}
        cross_org_mcp_list = await ac.get(
            f"/api/v1/mcp/resources?org_id={second_org_id}",
            headers={"Authorization": f"Bearer {first_access}"},
        )
        assert cross_org_mcp_list.status_code == 403

        first_audit = await ac.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {first_access}"},
            params={"action": "invitation.create"},
        )
        assert first_audit.status_code == 200
        assert {event["org_id"] for event in first_audit.json()} == {first_org_id}
        second_audit = await ac.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {second_access}"},
            params={"action": "invitation.create"},
        )
        assert second_audit.status_code == 200
        assert {event["org_id"] for event in second_audit.json()} == {second_org_id}
        cross_org_audit = await ac.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {first_access}"},
            params={"org_id": second_org_id},
        )
        assert cross_org_audit.status_code == 403


@pytest.mark.asyncio
async def test_audit_retention_policy_preview_and_prune():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]
        org_id = signup.json()["orgs"][0]["id"]

        unset_prune = await ac.post(
            "/api/v1/audit/prune",
            headers={"Authorization": f"Bearer {access}"},
            json={"org_id": org_id, "dry_run": True},
        )
        assert unset_prune.status_code == 400

        retention = await ac.patch(
            f"/api/v1/orgs/{org_id}",
            headers={"Authorization": f"Bearer {access}"},
            json={"audit_retention_days": 7},
        )
        assert retention.status_code == 200
        assert retention.json()["audit_retention_days"] == 7

        setup = await ac.get("/api/v1/setup/status", headers={"Authorization": f"Bearer {access}"})
        assert setup.status_code == 200
        assert setup.json()["org"]["audit_retention_days"] == 7

        async with async_session_factory() as db:
            db.add(
                AuditEvent(
                    org_id=org_id,
                    actor_user_id=None,
                    action="audit.old",
                    target_type="test",
                    target_id="old",
                    details={},
                    created_at=security.now_utc() - timedelta(days=30),
                )
            )
            db.add(
                AuditEvent(
                    org_id=org_id,
                    actor_user_id=None,
                    action="audit.recent",
                    target_type="test",
                    target_id="recent",
                    details={},
                    created_at=security.now_utc() - timedelta(days=1),
                )
            )
            await db.commit()

        preview = await ac.post(
            "/api/v1/audit/prune",
            headers={"Authorization": f"Bearer {access}"},
            json={"org_id": org_id, "dry_run": True},
        )
        assert preview.status_code == 200
        assert preview.json()["dry_run"] is True
        assert preview.json()["retention_days"] == 7
        assert preview.json()["pruned_count"] == 1

        pruned = await ac.post(
            "/api/v1/audit/prune",
            headers={"Authorization": f"Bearer {access}"},
            json={"org_id": org_id, "dry_run": False},
        )
        assert pruned.status_code == 200
        assert pruned.json()["dry_run"] is False
        assert pruned.json()["pruned_count"] == 1

        old_events = await ac.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {access}"},
            params={"action": "audit.old"},
        )
        assert old_events.status_code == 200
        assert old_events.json() == []
        recent_events = await ac.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {access}"},
            params={"action": "audit.recent"},
        )
        assert recent_events.status_code == 200
        assert len(recent_events.json()) == 1
        prune_events = await ac.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {access}"},
            params={"action": "audit.prune"},
        )
        assert prune_events.status_code == 200
        assert prune_events.json()[0]["details"]["pruned_count"] == 1


@pytest.mark.asyncio
async def test_self_service_profile_password_and_email_change(monkeypatch):
    monkeypatch.setattr(services, "new_code", lambda length=8: "ABC12345")
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert signup.status_code == 200
        first_access = signup.json()["access_token"]
        first_refresh = signup.json()["refresh_token"]

        login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert login.status_code == 200
        second_access = login.json()["access_token"]
        second_refresh = login.json()["refresh_token"]

        updated = await ac.patch(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {second_access}"},
            json={"display_name": "Renamed Owner"},
        )
        assert updated.status_code == 200
        assert updated.json()["display_name"] == "Renamed Owner"

        bad_change = await ac.post(
            "/api/v1/auth/password/change",
            headers={"Authorization": f"Bearer {second_access}"},
            json={"current_password": "wrong horse battery", "new_password": "better horse battery"},
        )
        assert bad_change.status_code == 401

        changed = await ac.post(
            "/api/v1/auth/password/change",
            headers={"Authorization": f"Bearer {second_access}"},
            json={"current_password": "correct horse battery", "new_password": "better horse battery"},
        )
        assert changed.status_code == 200
        assert changed.json() == {
            "status": "updated",
            "revoked_count": 1,
            "current_session_kept": True,
        }

        first_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {first_access}"})
        assert first_me.status_code == 401
        first_rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
        assert first_rotated.status_code == 401

        second_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {second_access}"})
        assert second_me.status_code == 200
        assert second_me.json()["user"]["display_name"] == "Renamed Owner"
        second_rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": second_refresh})
        assert second_rotated.status_code == 200

        old_password_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert old_password_login.status_code == 401

        new_password_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "owner@example.com", "password": "better horse battery"},
        )
        assert new_password_login.status_code == 200
        other_login_access = new_password_login.json()["access_token"]
        assert new_password_login.json()["user"]["display_name"] == "Renamed Owner"

        duplicate = await register(
            ac,
            json={"email": "taken@example.com", "password": "correct horse battery"},
        )
        assert duplicate.status_code == 200
        duplicate_request = await ac.post(
            "/api/v1/auth/email/change/request",
            headers={"Authorization": f"Bearer {second_rotated.json()['access_token']}"},
            json={"new_email": "taken@example.com", "current_password": "better horse battery"},
        )
        assert duplicate_request.status_code == 409

        bad_email_request = await ac.post(
            "/api/v1/auth/email/change/request",
            headers={"Authorization": f"Bearer {second_rotated.json()['access_token']}"},
            json={"new_email": "renamed@example.com", "current_password": "wrong horse battery"},
        )
        assert bad_email_request.status_code == 401

        email_request = await ac.post(
            "/api/v1/auth/email/change/request",
            headers={"Authorization": f"Bearer {second_rotated.json()['access_token']}"},
            json={"new_email": "renamed@example.com", "current_password": "better horse battery"},
        )
        assert email_request.status_code == 200
        assert email_request.json()["status"] == "sent"

        email_confirm = await ac.post(
            "/api/v1/auth/email/change/confirm",
            headers={"Authorization": f"Bearer {second_rotated.json()['access_token']}"},
            json={"new_email": "renamed@example.com", "code": "ABC12345"},
        )
        assert email_confirm.status_code == 200
        assert email_confirm.json() == {
            "status": "updated",
            "email": "renamed@example.com",
            "revoked_count": 1,
            "current_session_kept": True,
        }

        other_login_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {other_login_access}"})
        assert other_login_me.status_code == 401
        current_me = await ac.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {second_rotated.json()['access_token']}"},
        )
        assert current_me.status_code == 200
        assert current_me.json()["user"]["email"] == "renamed@example.com"
        assert current_me.json()["user"]["email_verified"] is True

        old_email_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "owner@example.com", "password": "better horse battery"},
        )
        assert old_email_login.status_code == 401
        renamed_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "renamed@example.com", "password": "better horse battery"},
        )
        assert renamed_login.status_code == 200


@pytest.mark.asyncio
async def test_self_service_account_export_and_deactivation_policy():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        sole_owner_deactivate = await ac.post(
            "/api/v1/auth/account/deactivate",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"current_password": "correct horse battery"},
        )
        assert sole_owner_deactivate.status_code == 400

        backup_owner = await register(
            ac,
            json={"email": "backup@example.com", "password": "correct horse battery"},
        )
        assert backup_owner.status_code == 200
        backup_owner_id = backup_owner.json()["user"]["id"]

        promoted = await ac.put(
            f"/api/v1/users/{backup_owner_id}/membership",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"org_id": org_id, "role": "owner", "status": "active"},
        )
        assert promoted.status_code == 200

        owner_token = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "name": "owner personal token",
                "token_type": "personal",
                "org_id": org_id,
                "scopes": ["auth:read"],
                "audiences": ["gatekeeper-api"],
            },
        )
        assert owner_token.status_code == 200
        raw_owner_token = owner_token.json()["token"]

        owner_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert owner_login.status_code == 200
        owner_login_access = owner_login.json()["access_token"]

        export = await ac.get(
            "/api/v1/auth/account/export",
            headers={"Authorization": f"Bearer {owner_access}"},
        )
        assert export.status_code == 200
        export_payload = export.json()
        assert export_payload["user"]["email"] == "owner@example.com"
        assert export_payload["memberships"][0]["role"] == "owner"
        assert export_payload["api_tokens"][0]["id"] == owner_token.json()["id"]
        assert export_payload["api_tokens"][0]["token"] is None
        assert len(export_payload["sessions"]) >= 2

        deactivated = await ac.post(
            "/api/v1/auth/account/deactivate",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"current_password": "correct horse battery"},
        )
        assert deactivated.status_code == 200
        assert deactivated.json()["status"] == "deactivated"
        assert deactivated.json()["revoked_sessions"] >= 2
        assert deactivated.json()["revoked_tokens"] == 1

        current_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {owner_access}"})
        assert current_me.status_code == 401
        other_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {owner_login_access}"})
        assert other_me.status_code == 401
        disabled_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert disabled_login.status_code == 401
        token_introspection = await ac.post("/oauth/introspect", data={"token": raw_owner_token})
        assert token_introspection.status_code == 200
        assert token_introspection.json()["active"] is False


@pytest.mark.asyncio
async def test_admin_user_hard_delete_requires_org_policy_and_confirmation():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        target = await register(
            ac,
            json={"email": "target@example.com", "password": "correct horse battery", "display_name": "Target"},
        )
        assert target.status_code == 200
        target_access = target.json()["access_token"]
        target_id = target.json()["user"]["id"]

        denied = await ac.post(
            f"/api/v1/users/{target_id}/delete",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"dry_run": True},
        )
        assert denied.status_code == 403

        enabled = await ac.patch(
            f"/api/v1/orgs/{org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"allow_user_hard_delete": True},
        )
        assert enabled.status_code == 200
        assert enabled.json()["allow_user_hard_delete"] is True

        target_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {target_access}"})
        assert target_me.status_code == 200

        preview = await ac.post(
            f"/api/v1/users/{target_id}/delete",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"dry_run": True},
        )
        assert preview.status_code == 200
        assert preview.json()["status"] == "preview"
        assert preview.json()["dry_run"] is True
        assert preview.json()["email"] == "target@example.com"
        assert preview.json()["counts"]["memberships"] == 1
        assert preview.json()["counts"]["sessions"] >= 1

        missing_confirmation = await ac.post(
            f"/api/v1/users/{target_id}/delete",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"dry_run": False},
        )
        assert missing_confirmation.status_code == 400

        deleted = await ac.post(
            f"/api/v1/users/{target_id}/delete",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"dry_run": False, "confirm_email": "target@example.com"},
        )
        assert deleted.status_code == 200
        assert deleted.json()["status"] == "deleted"
        assert deleted.json()["dry_run"] is False

        target_after_delete = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {target_access}"})
        assert target_after_delete.status_code == 401
        deleted_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "target@example.com", "password": "correct horse battery"},
        )
        assert deleted_login.status_code == 401
        admin_read = await ac.get(f"/api/v1/users/{target_id}", headers={"Authorization": f"Bearer {owner_access}"})
        assert admin_read.status_code == 404


@pytest.mark.asyncio
async def test_platform_admin_lists_new_accounts_newest_first():
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        newcomer = await register(ac, json={"email": "newcomer@example.com", "password": password})
        async with async_session_factory() as db:
            for user_id, age in ((owner.json()["user"]["id"], 48), (newcomer.json()["user"]["id"], 1)):
                (await db.get(User, user_id)).created_at = security.now_utc() - timedelta(hours=age)
            await db.commit()

        listed = await ac.get("/api/v1/admin/accounts", headers=owner_headers)
        assert listed.status_code == 200
        assert [item["email"] for item in listed.json()] == ["newcomer@example.com", "owner@example.com"]
        newest = listed.json()[0]
        assert newest["last_session_ip"] == "127.0.0.1"
        assert newest["last_session_at"]
        assert newest["mfa_totp_enabled"] is False
        assert newest["passkey_count"] == 0
        assert newest["disabled"] is False
        memberships = [(item["org_name"], item["role"]) for item in newest["memberships"]]
        assert memberships == [(settings.bootstrap_org_name, "viewer")]
        assert not {"password_hash", "mfa_totp_secret_encrypted"}.intersection(newest)

        cutoff = (security.now_utc() - timedelta(hours=24)).isoformat()
        recent = await ac.get("/api/v1/admin/accounts", headers=owner_headers, params={"created_after": cutoff})
        assert [item["email"] for item in recent.json()] == ["newcomer@example.com"]

        denied = await ac.get(
            "/api/v1/admin/accounts", headers={"Authorization": f"Bearer {newcomer.json()['access_token']}"}
        )
        assert denied.status_code == 403


@pytest.mark.asyncio
async def test_org_admin_cannot_change_credentials_of_accounts_in_other_orgs(monkeypatch):
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_id = owner.json()["user"]["id"]
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        tenant = await ac.post("/api/v1/orgs", headers=owner_headers, json={"name": "Tenant", "slug": "tenant"})
        tenant_id = tenant.json()["id"]
        switched = await ac.post("/api/v1/auth/session/switch-org", headers=owner_headers, json={"org_id": tenant_id})
        tenant_owner_headers = {"Authorization": f"Bearer {switched.json()['access_token']}"}
        invite = await ac.post(
            "/api/v1/invitations",
            headers=tenant_owner_headers,
            json={"email": "tenant-admin@example.com", "org_id": tenant_id, "role": "admin"},
        )
        monkeypatch.setattr(settings, "signup_mode", "invite")
        tenant_admin = await ac.post(
            "/api/v1/auth/invitations/accept",
            json={"email": "tenant-admin@example.com", "password": password, "token": invite.json()["token"]},
        )
        admin_headers = {"Authorization": f"Bearer {tenant_admin.json()['access_token']}"}

        takeover = await ac.patch(
            f"/scim/v2/Users/{owner_id}",
            headers=admin_headers,
            json={"Operations": [{"op": "replace", "path": "password", "value": "attacker chosen secret"}]},
        )
        assert takeover.status_code == 403
        reset = await ac.post(f"/api/v1/users/{owner_id}/mfa/totp/reset", headers=admin_headers)
        assert reset.status_code == 403
        suspend = await ac.patch(f"/api/v1/users/{owner_id}", headers=admin_headers, json={"disabled": True})
        assert suspend.status_code == 403
        owner_login = await ac.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": password})
        assert owner_login.status_code == 200

        local = await ac.post(
            "/api/v1/users/provision",
            headers=admin_headers,
            json={"org_id": tenant_id, "email": "local@example.com", "role": "viewer"},
        )
        local_id = local.json()["user"]["id"]
        local_suspend = await ac.patch(f"/api/v1/users/{local_id}", headers=admin_headers, json={"disabled": True})
        assert local_suspend.status_code == 200


@pytest.mark.asyncio
async def test_admin_user_provisioning_creates_and_updates_org_memberships():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        provisioned = await ac.post(
            "/api/v1/users/provision",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "org_id": org_id,
                "email": "provisioned@example.com",
                "display_name": "Provisioned User",
                "email_verified": True,
                "role": "operator",
                "status": "active",
            },
        )
        assert provisioned.status_code == 200
        provisioned_body = provisioned.json()
        assert provisioned_body["status"] == "created"
        assert provisioned_body["created_user"] is True
        assert provisioned_body["created_membership"] is True
        assert provisioned_body["revoked_sessions"] == 0
        assert provisioned_body["user"]["email"] == "provisioned@example.com"
        assert provisioned_body["user"]["email_verified"] is True
        assert provisioned_body["user"]["memberships"][0]["role"] == "operator"

        password_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "provisioned@example.com", "password": "correct horse battery"},
        )
        assert password_login.status_code == 401

        target = await register(
            ac,
            json={"email": "target@example.com", "password": "correct horse battery", "display_name": "Target"},
        )
        assert target.status_code == 200
        target_access = target.json()["access_token"]

        updated = await ac.post(
            "/api/v1/users/provision",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "org_id": org_id,
                "email": "target@example.com",
                "display_name": "Provisioned Target",
                "role": "operator",
                "status": "suspended",
                "disabled": True,
            },
        )
        assert updated.status_code == 200
        updated_body = updated.json()
        assert updated_body["status"] == "updated"
        assert updated_body["created_user"] is False
        assert updated_body["created_membership"] is False
        assert updated_body["revoked_sessions"] >= 1
        assert updated_body["user"]["display_name"] == "Provisioned Target"
        assert updated_body["user"]["disabled"] is True
        assert updated_body["user"]["memberships"][0]["role"] == "operator"
        assert updated_body["user"]["memberships"][0]["status"] == "suspended"

        target_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {target_access}"})
        assert target_me.status_code == 401


@pytest.mark.asyncio
async def test_scim_v2_user_compatibility_crud_and_deprovisioning():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        service_config = await ac.get("/scim/v2/ServiceProviderConfig")
        assert service_config.status_code == 200
        assert service_config.json()["patch"]["supported"] is True

        created = await ac.post(
            f"/scim/v2/Users?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "scim@example.com",
                "displayName": "SCIM User",
                "active": True,
                "roles": [{"value": "viewer"}],
            },
        )
        assert created.status_code == 201
        created_payload = created.json()
        scim_user_id = created_payload["id"]
        assert created_payload["userName"] == "scim@example.com"
        assert created_payload["displayName"] == "SCIM User"
        assert created_payload["active"] is True
        assert created_payload["roles"][0]["value"] == "viewer"

        filtered = await ac.get(
            "/scim/v2/Users",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={"org_id": org_id, "filter": 'userName eq "scim@example.com"'},
        )
        assert filtered.status_code == 200
        assert filtered.json()["totalResults"] == 1
        assert filtered.json()["Resources"][0]["id"] == scim_user_id

        patched = await ac.patch(
            f"/scim/v2/Users/{scim_user_id}?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "replace", "path": "displayName", "value": "SCIM Operator"},
                    {"op": "replace", "path": "roles", "value": [{"value": "operator"}]},
                ],
            },
        )
        assert patched.status_code == 200
        assert patched.json()["displayName"] == "SCIM Operator"
        assert patched.json()["roles"][0]["value"] == "operator"

        target = await register(
            ac,
            json={"email": "target@example.com", "password": "correct horse battery", "display_name": "Target"},
        )
        assert target.status_code == 200
        target_access = target.json()["access_token"]
        target_id = target.json()["user"]["id"]

        deprovisioned = await ac.patch(
            f"/scim/v2/Users/{target_id}?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "active", "value": False}],
            },
        )
        assert deprovisioned.status_code == 200
        assert deprovisioned.json()["active"] is False

        target_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {target_access}"})
        assert target_me.status_code == 401


@pytest.mark.asyncio
async def test_scim_v2_user_password_operations_rotate_password_and_revoke_sessions():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        service_config = await ac.get("/scim/v2/ServiceProviderConfig")
        assert service_config.status_code == 200
        assert service_config.json()["changePassword"]["supported"] is True

        created = await ac.post(
            f"/scim/v2/Users?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "password-scim@example.com",
                "displayName": "Password SCIM",
                "active": True,
                "password": "initial horse battery",
                "roles": [{"value": "viewer"}],
            },
        )
        assert created.status_code == 201
        scim_user_id = created.json()["id"]
        assert "password" not in created.json()

        initial_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "password-scim@example.com", "password": "initial horse battery"},
        )
        assert initial_login.status_code == 200
        initial_access = initial_login.json()["access_token"]

        patched = await ac.patch(
            f"/scim/v2/Users/{scim_user_id}?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "password", "value": "rotated horse battery"}],
            },
        )
        assert patched.status_code == 200
        assert "password" not in patched.json()

        revoked_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {initial_access}"})
        assert revoked_me.status_code == 401

        old_password_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "password-scim@example.com", "password": "initial horse battery"},
        )
        assert old_password_login.status_code == 401

        rotated_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "password-scim@example.com", "password": "rotated horse battery"},
        )
        assert rotated_login.status_code == 200
        rotated_access = rotated_login.json()["access_token"]

        replaced = await ac.put(
            f"/scim/v2/Users/{scim_user_id}?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "password-scim@example.com",
                "displayName": "Password SCIM",
                "active": True,
                "password": "second rotated horse battery",
                "roles": [{"value": "viewer"}],
            },
        )
        assert replaced.status_code == 200

        revoked_after_put = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {rotated_access}"})
        assert revoked_after_put.status_code == 401

        final_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "password-scim@example.com", "password": "second rotated horse battery"},
        )
        assert final_login.status_code == 200


@pytest.mark.asyncio
async def test_scim_v2_bulk_supports_common_user_group_provisioning_operations():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        service_config = await ac.get("/scim/v2/ServiceProviderConfig")
        assert service_config.status_code == 200
        assert service_config.json()["bulk"]["supported"] is True

        bulk = await ac.post(
            f"/scim/v2/Bulk?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations": [
                    {
                        "method": "POST",
                        "path": "/Users",
                        "bulkId": "user1",
                        "data": {
                            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                            "userName": "bulk-scim@example.com",
                            "displayName": "Bulk SCIM",
                            "active": True,
                            "password": "initial horse battery",
                            "roles": [{"value": "viewer"}],
                        },
                    },
                    {
                        "method": "POST",
                        "path": "/Groups",
                        "bulkId": "group1",
                        "data": {
                            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                            "displayName": "bulk-support",
                            "members": [{"value": "bulkId:user1"}],
                        },
                    },
                    {
                        "method": "PATCH",
                        "path": "/Users/bulkId:user1",
                        "data": {
                            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                            "Operations": [
                                {"op": "replace", "path": "password", "value": "rotated horse battery"},
                            ],
                        },
                    },
                    {"method": "GET", "path": "/Groups/bulkId:group1"},
                ],
            },
        )
        assert bulk.status_code == 200
        payload = bulk.json()
        assert payload["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"]
        assert [operation["status"] for operation in payload["Operations"]] == ["201", "201", "200", "200"]
        created_user = payload["Operations"][0]["response"]
        created_group = payload["Operations"][1]["response"]
        assert "password" not in created_user
        assert created_group["members"][0]["value"] == created_user["id"]
        assert payload["Operations"][3]["response"]["members"][0]["value"] == created_user["id"]

        old_password_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "bulk-scim@example.com", "password": "initial horse battery"},
        )
        assert old_password_login.status_code == 401

        rotated_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "bulk-scim@example.com", "password": "rotated horse battery"},
        )
        assert rotated_login.status_code == 200
        assert rotated_login.json()["user"]["id"] == created_user["id"]

        failed = await ac.post(
            f"/scim/v2/Bulk?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "failOnErrors": 1,
                "Operations": [
                    {"method": "POST", "path": "/Unsupported", "bulkId": "bad", "data": {}},
                    {"method": "GET", "path": f"/Users/{created_user['id']}"},
                ],
            },
        )
        assert failed.status_code == 200
        failed_payload = failed.json()
        assert len(failed_payload["Operations"]) == 1
        assert failed_payload["Operations"][0]["status"] == "400"
        assert failed_payload["Operations"][0]["response"]["schemas"] == [
            "urn:ietf:params:scim:api:messages:2.0:Error"
        ]


@pytest.mark.asyncio
async def test_scim_v2_enterprise_user_mapping_round_trips_membership_scoped_attributes():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        owner_id = owner.json()["user"]["id"]
        org_id = owner.json()["orgs"][0]["id"]

        schemas = await ac.get("/scim/v2/Schemas")
        assert schemas.status_code == 200
        schema_ids = {resource["id"] for resource in schemas.json()["Resources"]}
        assert "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User" in schema_ids

        enterprise_schema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        created = await ac.post(
            f"/scim/v2/Users?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User",
                    enterprise_schema,
                ],
                "externalId": "idp-user-123",
                "userName": "enterprise-scim@example.com",
                "displayName": "Enterprise SCIM",
                "active": True,
                "roles": [{"value": "viewer"}],
                enterprise_schema: {
                    "employeeNumber": "E-123",
                    "costCenter": "CC-42",
                    "organization": "Example Co",
                    "division": "Platform",
                    "department": "Engineering",
                    "manager": {"value": owner_id, "display": "Owner"},
                },
            },
        )
        assert created.status_code == 201
        created_payload = created.json()
        scim_user_id = created_payload["id"]
        assert created_payload["externalId"] == "idp-user-123"
        assert created_payload[enterprise_schema]["employeeNumber"] == "E-123"
        assert created_payload[enterprise_schema]["costCenter"] == "CC-42"
        assert created_payload[enterprise_schema]["organization"] == "Example Co"
        assert created_payload[enterprise_schema]["division"] == "Platform"
        assert created_payload[enterprise_schema]["department"] == "Engineering"
        assert created_payload[enterprise_schema]["manager"] == {
            "value": owner_id,
            "display": "Owner",
            "$ref": f"http://localhost:8000/scim/v2/Users/{owner_id}",
        }

        patched = await ac.patch(
            f"/scim/v2/Users/{scim_user_id}?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "replace", "path": "externalId", "value": "idp-user-456"},
                    {"op": "replace", "path": f"{enterprise_schema}:department", "value": "Security"},
                    {"op": "remove", "path": f"{enterprise_schema}:costCenter"},
                ],
            },
        )
        assert patched.status_code == 200
        patched_payload = patched.json()
        assert patched_payload["externalId"] == "idp-user-456"
        assert patched_payload[enterprise_schema]["department"] == "Security"
        assert "costCenter" not in patched_payload[enterprise_schema]
        assert patched_payload[enterprise_schema]["employeeNumber"] == "E-123"

        fetched = await ac.get(
            f"/scim/v2/Users/{scim_user_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={"org_id": org_id},
        )
        assert fetched.status_code == 200
        assert fetched.json()["externalId"] == "idp-user-456"
        assert fetched.json()[enterprise_schema]["department"] == "Security"


@pytest.mark.asyncio
async def test_scim_v2_group_compatibility_assigns_and_removes_role_members():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        target = await register(
            ac,
            json={"email": "target@example.com", "password": "correct horse battery", "display_name": "Target"},
        )
        assert target.status_code == 200
        target_access = target.json()["access_token"]
        target_id = target.json()["user"]["id"]

        resource_types = await ac.get("/scim/v2/ResourceTypes")
        assert resource_types.status_code == 200
        assert {resource["id"] for resource in resource_types.json()["Resources"]} == {"User", "Group"}

        created_group = await ac.post(
            f"/scim/v2/Groups?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "support",
            },
        )
        assert created_group.status_code == 201
        group_id = created_group.json()["id"]
        assert created_group.json()["displayName"] == "support"

        listed = await ac.get(
            "/scim/v2/Groups",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={"org_id": org_id, "filter": 'displayName eq "support"'},
        )
        assert listed.status_code == 200
        assert listed.json()["totalResults"] == 1
        assert listed.json()["Resources"][0]["id"] == group_id

        added = await ac.patch(
            f"/scim/v2/Groups/{group_id}?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "add", "path": "members", "value": [{"value": target_id}]},
                ],
            },
        )
        assert added.status_code == 200
        assert added.json()["members"] == [
            {
                "value": target_id,
                "display": "target@example.com",
                "$ref": f"http://localhost:8000/scim/v2/Users/{target_id}",
            }
        ]

        target_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {target_access}"})
        assert target_me.status_code == 401

        scim_user = await ac.get(
            f"/scim/v2/Users/{target_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={"org_id": org_id},
        )
        assert scim_user.status_code == 200
        assert scim_user.json()["roles"][0]["value"] == "support"

        removed = await ac.patch(
            f"/scim/v2/Groups/{group_id}?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "remove", "path": f'members[value eq "{target_id}"]'},
                ],
            },
        )
        assert removed.status_code == 200
        assert removed.json()["members"] == []

        scim_user_after_remove = await ac.get(
            f"/scim/v2/Users/{target_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={"org_id": org_id},
        )
        assert scim_user_after_remove.status_code == 200
        assert scim_user_after_remove.json()["active"] is False


@pytest.mark.asyncio
async def test_scim_v2_lists_support_sorting_and_pagination():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "zz-owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        service_config = await ac.get("/scim/v2/ServiceProviderConfig")
        assert service_config.status_code == 200
        assert service_config.json()["sort"]["supported"] is True

        for email, display_name in [
            ("charlie@example.com", "Charlie"),
            ("alpha@example.com", "Alpha"),
            ("bravo@example.com", "Bravo"),
        ]:
            created_user = await ac.post(
                f"/scim/v2/Users?org_id={org_id}",
                headers={"Authorization": f"Bearer {owner_access}"},
                json={
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": email,
                    "displayName": display_name,
                    "roles": [{"value": "viewer"}],
                },
            )
            assert created_user.status_code == 201

        ascending_users = await ac.get(
            "/scim/v2/Users",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={"org_id": org_id, "sortBy": "userName", "sortOrder": "ascending", "count": 3},
        )
        assert ascending_users.status_code == 200
        ascending_payload = ascending_users.json()
        assert ascending_payload["totalResults"] == 4
        assert ascending_payload["itemsPerPage"] == 3
        assert [resource["userName"] for resource in ascending_payload["Resources"]] == [
            "alpha@example.com",
            "bravo@example.com",
            "charlie@example.com",
        ]

        descending_users_page = await ac.get(
            "/scim/v2/Users",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={
                "org_id": org_id,
                "sortBy": "userName",
                "sortOrder": "descending",
                "startIndex": 2,
                "count": 2,
            },
        )
        assert descending_users_page.status_code == 200
        descending_payload = descending_users_page.json()
        assert descending_payload["startIndex"] == 2
        assert [resource["userName"] for resource in descending_payload["Resources"]] == [
            "charlie@example.com",
            "bravo@example.com",
        ]

        for group_name in ["aaaa-analytics", "zzzz-support"]:
            created_group = await ac.post(
                f"/scim/v2/Groups?org_id={org_id}",
                headers={"Authorization": f"Bearer {owner_access}"},
                json={
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                    "displayName": group_name,
                },
            )
            assert created_group.status_code == 201

        groups = await ac.get(
            "/scim/v2/Groups",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={"org_id": org_id, "sortBy": "displayName", "sortOrder": "ascending", "count": 1},
        )
        assert groups.status_code == 200
        groups_payload = groups.json()
        assert groups_payload["totalResults"] >= 5
        assert groups_payload["itemsPerPage"] == 1
        assert groups_payload["Resources"][0]["displayName"] == "aaaa-analytics"

        descending_groups = await ac.get(
            "/scim/v2/Groups",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={"org_id": org_id, "sortBy": "displayName", "sortOrder": "descending", "count": 1},
        )
        assert descending_groups.status_code == 200
        assert descending_groups.json()["Resources"][0]["displayName"] == "zzzz-support"

        unsupported = await ac.get(
            "/scim/v2/Users",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={"org_id": org_id, "sortBy": "emails.value"},
        )
        assert unsupported.status_code == 400


@pytest.mark.asyncio
async def test_linked_identities_can_be_listed_and_safely_unlinked():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]
        user_id = signup.json()["user"]["id"]

        async with engine.begin() as conn:
            await conn.execute(
                Identity.__table__.insert().values(
                    user_id=user_id,
                    provider="google",
                    provider_subject="google-owner",
                    email="owner@example.com",
                )
            )

        linked = await ac.get("/api/v1/auth/identities", headers={"Authorization": f"Bearer {access}"})
        assert linked.status_code == 200
        assert linked.json()[0]["provider"] == "google"
        assert linked.json()[0]["email"] == "owner@example.com"

        unlinked = await ac.delete(
            f"/api/v1/auth/identities/{linked.json()[0]['id']}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert unlinked.status_code == 200
        assert unlinked.json()["status"] == "unlinked"
        assert (await ac.get("/api/v1/auth/identities", headers={"Authorization": f"Bearer {access}"})).json() == []


@pytest.mark.asyncio
async def test_cannot_unlink_only_federated_sign_in_method():
    async with await client() as ac:
        async with async_session_factory() as db:
            user = User(
                email="federated@example.com",
                display_name="Federated User",
                password_hash=None,
                email_verified=True,
            )
            db.add(user)
            await db.flush()
            identity = Identity(
                user_id=user.id,
                provider="google",
                provider_subject="google-federated",
                email="federated@example.com",
            )
            db.add(identity)
            await db.flush()
            access, _refresh, _session, _refresh_model, _scopes = await services.create_session_tokens(
                db,
                user,
                bind_default_org=False,
                amr=["federated"],
            )
            identity_id = identity.id
            await db.commit()
        denied = await ac.delete(
            f"/api/v1/auth/identities/{identity_id}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert denied.status_code == 400


@pytest.mark.asyncio
async def test_configured_oauth_provider_metadata_and_start_url(monkeypatch):
    monkeypatch.setattr(settings, "google_client_id", "")
    monkeypatch.setattr(settings, "google_client_secret", "")
    monkeypatch.setattr(
        settings,
        "oauth_providers_json",
        """
        [{
          "id":"example",
          "name":"Example Login",
          "client_id":"example-client",
          "client_secret":"example-secret",
          "authorization_url":"https://login.example.com/oauth/authorize",
          "token_url":"https://login.example.com/oauth/token",
          "userinfo_url":"https://login.example.com/userinfo",
          "redirect_uri":"https://auth.example.com/api/v1/auth/oauth/example/callback",
          "scopes":["openid","email"]
        }]
        """,
    )
    async with await client() as ac:
        providers = await ac.get("/api/v1/auth/oauth/providers")
        assert providers.status_code == 200
        assert providers.json() == [
            {
                "id": "example",
                "name": "Example Login",
                "configured": True,
                "scopes": ["openid", "email"],
                "start_url": f"{settings.issuer}/api/v1/auth/oauth/example/start",
                "authorization_url": "https://login.example.com/oauth/authorize",
                "require_verified_email": True,
                "allow_email_linking": False,
            }
        ]

        started = await ac.get("/api/v1/auth/oauth/example/start")
        assert started.status_code == 200
        started_payload = started.json()
        assert started_payload["provider"] == "example"
        parsed = urlparse(started_payload["authorization_url"])
        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "https://login.example.com/oauth/authorize"
        query = parse_qs(parsed.query)
        assert query["client_id"] == ["example-client"]
        assert query["redirect_uri"] == ["https://auth.example.com/api/v1/auth/oauth/example/callback"]
        assert query["response_type"] == ["code"]
        assert query["scope"] == ["openid email"]
        assert query["state"] == [started_payload["state"]]
        assert len(query["state"][0].split(".")) == 3


@pytest.mark.asyncio
async def test_install_owner_can_manage_database_oauth_providers(monkeypatch):
    monkeypatch.setattr(settings, "google_client_id", "")
    monkeypatch.setattr(settings, "google_client_secret", "")
    monkeypatch.setattr(settings, "oauth_providers_json", "")

    async def fake_profile(provider, code):
        assert provider.id == "db-login"
        assert provider.client_secret == "db-secret"
        assert code == "provider-code"
        return {
            "sub": "db-user-1",
            "email": "db-social@example.com",
            "name": "Database Social User",
            "email_verified": True,
        }

    monkeypatch.setattr(main_module, "fetch_oauth_provider_profile", fake_profile)

    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]

        provider_body = {
            "provider_id": "db-login",
            "name": "Database Login",
            "client_id": "db-client",
            "client_secret": "db-secret",
            "authorization_url": "https://login.example.com/oauth/authorize",
            "token_url": "https://login.example.com/oauth/token",
            "userinfo_url": "https://login.example.com/userinfo",
            "scopes": ["openid", "email"],
        }
        created = await ac.post(
            "/api/v1/auth/oauth/providers/admin",
            headers={"Authorization": f"Bearer {owner_access}"},
            json=provider_body,
        )
        assert created.status_code == 201
        created_payload = created.json()
        assert created_payload["provider_id"] == "db-login"
        assert created_payload["source"] == "database"
        assert created_payload["read_only"] is False
        assert created_payload["configured"] is True
        assert created_payload["client_secret_configured"] is True
        assert "client_secret" not in created_payload

        admin_list = await ac.get(
            "/api/v1/auth/oauth/providers/admin",
            headers={"Authorization": f"Bearer {owner_access}"},
        )
        assert admin_list.status_code == 200
        assert [provider["provider_id"] for provider in admin_list.json()] == ["db-login"]

        public_list = await ac.get("/api/v1/auth/oauth/providers")
        assert public_list.status_code == 200
        assert public_list.json()[0]["id"] == "db-login"

        started = await ac.get("/api/v1/auth/oauth/db-login/start", params={"redirect": "/sessions"})
        assert started.status_code == 200
        started_payload = started.json()
        parsed = urlparse(started_payload["authorization_url"])
        query = parse_qs(parsed.query)
        assert query["client_id"] == ["db-client"]
        assert query["redirect_uri"] == [f"{settings.issuer}/api/v1/auth/oauth/db-login/callback"]
        assert query["scope"] == ["openid email"]

        invite = await ac.post(
            "/api/v1/invitations",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"email": "db-social@example.com", "org_id": owner.json()["orgs"][0]["id"], "role": "viewer"},
        )
        assert invite.status_code == 200
        monkeypatch.setattr(settings, "signup_mode", "invite")
        callback = await ac.get(
            "/api/v1/auth/oauth/db-login/callback",
            params={"code": "provider-code", "state": started_payload["state"]},
        )
        assert callback.status_code == 302
        assert callback.headers["location"] == f"{settings.ui_url.rstrip('/')}/sessions"
        me = await ac.get("/api/v1/auth/me")
        assert me.status_code == 200
        assert me.json()["user"]["email"] == "db-social@example.com"

        updated = await ac.patch(
            "/api/v1/auth/oauth/providers/admin/db-login",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"enabled": False, "client_secret": None},
        )
        assert updated.status_code == 200
        assert updated.json()["enabled"] is False
        assert updated.json()["configured"] is False

        disabled_public = await ac.get("/api/v1/auth/oauth/providers")
        assert disabled_public.status_code == 200
        assert disabled_public.json() == []
        disabled_start = await ac.get("/api/v1/auth/oauth/db-login/start")
        assert disabled_start.status_code == 404

        second_org = await ac.post(
            "/api/v1/orgs",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"name": "Second Product", "slug": "second-product-provider"},
        )
        assert second_org.status_code == 200
        switched = await ac.post(
            "/api/v1/auth/session/switch-org",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"org_id": second_org.json()["id"]},
        )
        assert switched.status_code == 200
        scoped_create = await ac.post(
            "/api/v1/auth/oauth/providers/admin",
            headers={"Authorization": f"Bearer {switched.json()['access_token']}"},
            json={**provider_body, "provider_id": "second-org-login"},
        )
        assert scoped_create.status_code == 403

        deleted = await ac.delete(
            "/api/v1/auth/oauth/providers/admin/db-login",
            headers={"Authorization": f"Bearer {owner_access}"},
        )
        assert deleted.status_code == 200


@pytest.mark.asyncio
async def test_env_managed_oauth_providers_are_admin_visible_read_only(monkeypatch):
    monkeypatch.setattr(settings, "google_client_id", "")
    monkeypatch.setattr(settings, "google_client_secret", "")
    monkeypatch.setattr(
        settings,
        "oauth_providers_json",
        """
        [{
          "id":"env-login",
          "name":"Env Login",
          "client_id":"env-client",
          "client_secret":"env-secret",
          "authorization_url":"https://env.example.com/oauth/authorize",
          "token_url":"https://env.example.com/oauth/token",
          "userinfo_url":"https://env.example.com/userinfo"
        }]
        """,
    )

    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert owner.status_code == 200
        headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}

        admin_list = await ac.get("/api/v1/auth/oauth/providers/admin", headers=headers)
        assert admin_list.status_code == 200
        assert admin_list.json()[0]["provider_id"] == "env-login"
        assert admin_list.json()[0]["source"] == "env"
        assert admin_list.json()[0]["read_only"] is True
        assert admin_list.json()[0]["client_secret_configured"] is True
        assert "client_secret" not in admin_list.json()[0]

        duplicate = await ac.post(
            "/api/v1/auth/oauth/providers/admin",
            headers=headers,
            json={
                "provider_id": "env-login",
                "name": "Duplicate",
                "authorization_url": "https://login.example.com/oauth/authorize",
                "token_url": "https://login.example.com/oauth/token",
                "userinfo_url": "https://login.example.com/userinfo",
            },
        )
        assert duplicate.status_code == 409

        patched = await ac.patch(
            "/api/v1/auth/oauth/providers/admin/env-login",
            headers=headers,
            json={"enabled": False},
        )
        assert patched.status_code == 400
        deleted = await ac.delete("/api/v1/auth/oauth/providers/admin/env-login", headers=headers)
        assert deleted.status_code == 400


@pytest.mark.asyncio
async def test_generic_oauth_callback_creates_federated_session(monkeypatch):
    monkeypatch.setattr(settings, "google_client_id", "")
    monkeypatch.setattr(settings, "google_client_secret", "")
    monkeypatch.setattr(
        settings,
        "oauth_providers_json",
        """
        [{
          "id":"example",
          "name":"Example Login",
          "client_id":"example-client",
          "client_secret":"example-secret",
          "authorization_url":"https://login.example.com/oauth/authorize",
          "token_url":"https://login.example.com/oauth/token",
          "userinfo_url":"https://login.example.com/userinfo",
          "redirect_uri":"https://auth.example.com/api/v1/auth/oauth/example/callback"
        }]
        """,
    )

    async def fake_profile(provider, code):
        assert provider.id == "example"
        assert code == "provider-code"
        return {
            "sub": "external-user-1",
            "email": "social@example.com",
            "name": "Social User",
            "email_verified": True,
        }

    monkeypatch.setattr(main_module, "fetch_oauth_provider_profile", fake_profile)

    async with await client() as ac:
        started = await ac.get("/api/v1/auth/oauth/example/start", params={"redirect": "/sessions"})
        assert started.status_code == 200
        refused = await ac.get(
            "/api/v1/auth/oauth/example/callback",
            params={"code": "provider-code", "state": started.json()["state"]},
        )
        assert refused.status_code == 403
        async with async_session_factory() as db:
            assert (await db.execute(select(User.id))).first() is None

        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        invite = await ac.post(
            "/api/v1/invitations",
            headers={"Authorization": f"Bearer {owner.json()['access_token']}"},
            json={"email": "social@example.com", "org_id": owner.json()["orgs"][0]["id"], "role": "viewer"},
        )
        assert invite.status_code == 200
        monkeypatch.setattr(settings, "signup_mode", "invite")
        ac.cookies.clear()

        started = await ac.get("/api/v1/auth/oauth/example/start", params={"redirect": "/sessions"})
        callback = await ac.get(
            "/api/v1/auth/oauth/example/callback",
            params={"code": "provider-code", "state": started.json()["state"]},
        )
        assert callback.status_code == 302
        assert callback.headers["location"] == f"{settings.ui_url.rstrip('/')}/sessions"

        me = await ac.get("/api/v1/auth/me")
        assert me.status_code == 200
        assert me.json()["user"]["email"] == "social@example.com"
        assert me.json()["user"]["email_verified"] is True

        identities = await ac.get("/api/v1/auth/identities")
        assert identities.status_code == 200
        assert identities.json()[0]["provider"] == "example"
        assert identities.json()[0]["email"] == "social@example.com"


@pytest.mark.asyncio
async def test_logged_in_user_can_link_oauth_identity_with_session_bound_state(monkeypatch):
    monkeypatch.setattr(settings, "google_client_id", "")
    monkeypatch.setattr(settings, "google_client_secret", "")
    monkeypatch.setattr(
        settings,
        "oauth_providers_json",
        """
        [{
          "id":"example",
          "name":"Example Login",
          "client_id":"example-client",
          "client_secret":"example-secret",
          "authorization_url":"https://login.example.com/oauth/authorize",
          "token_url":"https://login.example.com/oauth/token",
          "userinfo_url":"https://login.example.com/userinfo",
          "redirect_uri":"https://auth.example.com/api/v1/auth/oauth/example/callback"
        }]
        """,
    )

    async def fake_profile(provider, code):
        assert provider.id == "example"
        assert code == "link-code"
        return {
            "sub": "external-user-1",
            "email": "linked-social@example.com",
            "name": "Linked Social User",
            "email_verified": True,
        }

    monkeypatch.setattr(main_module, "fetch_oauth_provider_profile", fake_profile)

    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        owner_access = signup.json()["access_token"]
        owner_id = signup.json()["user"]["id"]

        started = await ac.get(
            "/api/v1/auth/identities/example/link/start",
            headers={"Authorization": f"Bearer {owner_access}"},
            params={"redirect": "/account"},
        )
        assert started.status_code == 200
        parsed = urlparse(started.json()["authorization_url"])
        state = parse_qs(parsed.query)["state"][0]

        async with await client() as unauthenticated:
            rejected = await unauthenticated.get(
                "/api/v1/auth/oauth/example/callback",
                params={"code": "link-code", "state": state},
            )
            assert rejected.status_code == 403

        linked = await ac.get(
            "/api/v1/auth/oauth/example/callback",
            params={"code": "link-code", "state": state},
        )
        assert linked.status_code == 302
        assert linked.headers["location"] == f"{settings.ui_url.rstrip('/')}/account"

        identities = await ac.get("/api/v1/auth/identities", headers={"Authorization": f"Bearer {owner_access}"})
        assert identities.status_code == 200
        assert identities.json()[0]["provider"] == "example"
        assert identities.json()[0]["email"] == "linked-social@example.com"

        me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {owner_access}"})
        assert me.status_code == 200
        assert me.json()["user"]["id"] == owner_id
        assert me.json()["user"]["email"] == "owner@example.com"

    async with await client() as second_client:
        second = await register(
            second_client,
            json={"email": "second@example.com", "password": "correct horse battery"},
        )
        assert second.status_code == 200
        second_started = await second_client.get(
            "/api/v1/auth/identities/example/link/start",
            headers={"Authorization": f"Bearer {second.json()['access_token']}"},
        )
        assert second_started.status_code == 200
        second_state = parse_qs(urlparse(second_started.json()["authorization_url"]).query)["state"][0]
        conflict = await second_client.get(
            "/api/v1/auth/oauth/example/callback",
            params={"code": "link-code", "state": second_state},
        )
        assert conflict.status_code == 409


@pytest.mark.asyncio
async def test_oauth_callback_requires_verified_email_for_new_links(monkeypatch):
    monkeypatch.setattr(settings, "google_client_id", "")
    monkeypatch.setattr(settings, "google_client_secret", "")
    monkeypatch.setattr(
        settings,
        "oauth_providers_json",
        """
        [{
          "id":"example",
          "name":"Example Login",
          "client_id":"example-client",
          "client_secret":"example-secret",
          "authorization_url":"https://login.example.com/oauth/authorize",
          "token_url":"https://login.example.com/oauth/token",
          "userinfo_url":"https://login.example.com/userinfo"
        }]
        """,
    )

    async def fake_profile(provider, code):
        return {
            "sub": "external-user-2",
            "email": "unverified@example.com",
            "name": "Unverified User",
            "email_verified": False,
        }

    monkeypatch.setattr(main_module, "fetch_oauth_provider_profile", fake_profile)

    async with await client() as ac:
        callback = await ac.get("/api/v1/auth/oauth/example/callback", params={"code": "provider-code"})
        assert callback.status_code == 403
        assert callback.json()["detail"] == "OAuth provider email must be verified before signup"


@pytest.mark.asyncio
async def test_totp_mfa_setup_login_enforcement_and_disable():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]

        status = await ac.get("/api/v1/auth/mfa/status", headers={"Authorization": f"Bearer {access}"})
        assert status.status_code == 200
        assert status.json() == {
            "totp_enabled": False,
            "totp_enabled_at": None,
            "totp_pending": False,
            "passkey_count": 0,
            "recovery_codes_remaining": 0,
        }

        setup = await ac.post("/api/v1/auth/mfa/totp/setup", headers={"Authorization": f"Bearer {access}"})
        assert setup.status_code == 200
        secret = setup.json()["secret"]
        assert setup.json()["otpauth_uri"].startswith("otpauth://totp/")

        bad_enable = await ac.post(
            "/api/v1/auth/mfa/totp/enable",
            headers={"Authorization": f"Bearer {access}"},
            json={"code": "000000"},
        )
        assert bad_enable.status_code == 401

        enable = await ac.post(
            "/api/v1/auth/mfa/totp/enable",
            headers={"Authorization": f"Bearer {access}"},
            json={"code": totp_code(secret)},
        )
        assert enable.status_code == 200
        assert enable.json()["totp_enabled"] is True
        recovery_codes = enable.json()["recovery_codes"]
        assert len(recovery_codes) == 10
        assert enable.json()["recovery_codes_remaining"] == 10

        no_code_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        assert no_code_login.status_code == 401
        assert no_code_login.json()["detail"] == "TOTP code required"

        bad_code_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "correct horse battery", "totp_code": "000000"},
        )
        assert bad_code_login.status_code == 401

        recovery_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@example.com",
                "password": "correct horse battery",
                "recovery_code": recovery_codes[0],
            },
        )
        assert recovery_login.status_code == 200
        recovery_claims = decode_access_token(recovery_login.json()["access_token"])
        assert recovery_claims["amr"] == ["pwd", "recovery"]

        reused_recovery_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@example.com",
                "password": "correct horse battery",
                "recovery_code": recovery_codes[0],
            },
        )
        assert reused_recovery_login.status_code == 401

        status_after_recovery = await ac.get(
            "/api/v1/auth/mfa/status",
            headers={"Authorization": f"Bearer {recovery_login.json()['access_token']}"},
        )
        assert status_after_recovery.status_code == 200
        assert status_after_recovery.json()["recovery_codes_remaining"] == 9

        good_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "correct horse battery", "totp_code": totp_code(secret)},
        )
        assert good_login.status_code == 200
        claims = decode_access_token(good_login.json()["access_token"])
        assert claims["mfa_totp_enabled"] is True
        assert claims["amr"] == ["pwd", "otp"]
        assert good_login.json()["user"]["mfa_totp_enabled"] is True

        regenerated = await ac.post(
            "/api/v1/auth/mfa/recovery-codes/regenerate",
            headers={"Authorization": f"Bearer {good_login.json()['access_token']}"},
            json={"code": totp_code(secret)},
        )
        assert regenerated.status_code == 200
        regenerated_codes = regenerated.json()["recovery_codes"]
        assert len(regenerated_codes) == 10
        assert regenerated.json()["recovery_codes_remaining"] == 10

        old_unused_recovery_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@example.com",
                "password": "correct horse battery",
                "recovery_code": recovery_codes[1],
            },
        )
        assert old_unused_recovery_login.status_code == 401

        new_recovery_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@example.com",
                "password": "correct horse battery",
                "recovery_code": regenerated_codes[0],
            },
        )
        assert new_recovery_login.status_code == 200

        disable_bad = await ac.post(
            "/api/v1/auth/mfa/totp/disable",
            headers={"Authorization": f"Bearer {good_login.json()['access_token']}"},
            json={"code": "000000"},
        )
        assert disable_bad.status_code == 401

        disable = await ac.post(
            "/api/v1/auth/mfa/totp/disable",
            headers={"Authorization": f"Bearer {good_login.json()['access_token']}"},
            json={"code": totp_code(secret)},
        )
        assert disable.status_code == 200
        assert disable.json()["totp_enabled"] is False
        assert disable.json()["recovery_codes_remaining"] == 0

        password_only_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        assert password_only_login.status_code == 200


@pytest.mark.asyncio
async def test_passkey_registration_login_management_and_replay_protection(monkeypatch):
    credential_id_bytes = b"gatekeeper-passkey-credential"
    credential_id = bytes_to_base64url(credential_id_bytes)
    registration_verification: dict[str, object] = {}
    authentication_verification: dict[str, object] = {}

    def fake_verify_registration_response(**kwargs):
        registration_verification.update(kwargs)
        return SimpleNamespace(
            credential_id=credential_id_bytes,
            credential_public_key=b"credential-public-key",
            sign_count=3,
            aaguid="00000000-0000-0000-0000-000000000000",
            credential_device_type=CredentialDeviceType.MULTI_DEVICE,
            credential_backed_up=True,
        )

    def fake_verify_authentication_response(**kwargs):
        authentication_verification.update(kwargs)
        return SimpleNamespace(
            credential_id=credential_id_bytes,
            new_sign_count=4,
            credential_device_type=CredentialDeviceType.MULTI_DEVICE,
            credential_backed_up=True,
        )

    monkeypatch.setattr(main_module, "verify_registration_response", fake_verify_registration_response)
    monkeypatch.setattr(main_module, "verify_authentication_response", fake_verify_authentication_response)

    async with await client() as ac:
        inviter = await register(
            ac,
            json={"email": "inviter@example.com", "password": "correct horse battery"},
        )
        assert inviter.status_code == 200
        inviter_access = inviter.json()["access_token"]
        inviter_org_id = inviter.json()["orgs"][0]["id"]
        invitation = await ac.post(
            "/api/v1/invitations",
            headers={"Authorization": f"Bearer {inviter_access}"},
            json={"email": "passkey@example.com", "org_id": inviter_org_id, "role": "operator"},
        )
        assert invitation.status_code == 200

        signup = await register(
            ac,
            json={"email": "passkey@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]
        headers = {"Authorization": f"Bearer {access}"}

        options = await ac.post(
            "/api/v1/auth/passkeys/registration/options",
            headers=headers,
        )
        assert options.status_code == 200
        assert options.json()["public_key"]["rp"]["id"] == "localhost"
        assert options.json()["public_key"]["authenticatorSelection"] == {
            "requireResidentKey": True,
            "residentKey": "required",
            "userVerification": "required",
        }
        registration_challenge_id = options.json()["challenge_id"]
        async with async_session_factory() as db:
            challenge = await db.get(WebAuthnChallenge, registration_challenge_id)
            assert challenge is not None
            assert challenge.challenge_encrypted != options.json()["public_key"]["challenge"]

        registration_payload = {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": "client-data",
                "attestationObject": "attestation",
                "transports": ["internal", "not-a-real-transport"],
            },
        }
        registered = await ac.post(
            "/api/v1/auth/passkeys/registration/verify",
            headers=headers,
            json={
                "challenge_id": registration_challenge_id,
                "credential": registration_payload,
                "name": "Work passkey",
            },
        )
        assert registered.status_code == 200
        assert registered.json()["name"] == "Work passkey"
        assert registered.json()["transports"] == ["internal"]
        assert registered.json()["credential_device_type"] == "multi_device"
        assert registered.json()["backed_up"] is True
        passkey_id = registered.json()["id"]
        assert registration_verification["expected_rp_id"] == "localhost"
        assert registration_verification["expected_origin"] == ["http://localhost:5173"]
        assert registration_verification["require_user_verification"] is True

        replay = await ac.post(
            "/api/v1/auth/passkeys/registration/verify",
            headers=headers,
            json={
                "challenge_id": registration_challenge_id,
                "credential": registration_payload,
            },
        )
        assert replay.status_code == 400
        assert replay.json()["detail"] == "Passkey ceremony expired or already used"

        status = await ac.get("/api/v1/auth/mfa/status", headers=headers)
        assert status.status_code == 200
        assert status.json()["passkey_count"] == 1

        renamed = await ac.patch(
            f"/api/v1/auth/passkeys/{passkey_id}",
            headers=headers,
            json={"name": "Laptop passkey"},
        )
        assert renamed.status_code == 200
        assert renamed.json()["name"] == "Laptop passkey"

        password_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "passkey@example.com", "password": "correct horse battery"},
        )
        assert password_login.status_code == 401
        assert password_login.json()["detail"] == "Passkey verification required"

        auth_options = await ac.post("/api/v1/auth/passkeys/authentication/options", json={})
        assert auth_options.status_code == 200
        assert auth_options.json()["public_key"]["rpId"] == "localhost"
        assert auth_options.json()["public_key"]["userVerification"] == "required"
        authentication_challenge_id = auth_options.json()["challenge_id"]

        authenticated = await ac.post(
            "/api/v1/auth/passkeys/authentication/verify",
            json={
                "challenge_id": authentication_challenge_id,
                "credential": {
                    "id": credential_id,
                    "rawId": credential_id,
                    "type": "public-key",
                    "response": {
                        "authenticatorData": "authenticator-data",
                        "clientDataJSON": "client-data",
                        "signature": "signature",
                        "userHandle": None,
                    },
                },
            },
        )
        assert authenticated.status_code == 200
        claims = decode_access_token(authenticated.json()["access_token"])
        assert claims["amr"] == ["webauthn"]
        assert claims["mfa_passkey_enabled"] is True
        assert authentication_verification["expected_rp_id"] == "localhost"
        assert authentication_verification["expected_origin"] == ["http://localhost:5173"]
        assert authentication_verification["require_user_verification"] is True

        accepted_invitation = await ac.post(
            "/api/v1/auth/invitations/accept",
            headers={"Authorization": f"Bearer {authenticated.json()['access_token']}"},
            json={
                "email": "passkey@example.com",
                "token": invitation.json()["token"],
            },
        )
        assert accepted_invitation.status_code == 200
        assert decode_access_token(accepted_invitation.json()["access_token"])["amr"] == ["webauthn"]
        password_fallback_invitation = await ac.post(
            "/api/v1/invitations",
            headers={"Authorization": f"Bearer {inviter_access}"},
            json={"email": "passkey@example.com", "org_id": inviter_org_id, "role": "viewer"},
        )
        assert password_fallback_invitation.status_code == 200
        ac.cookies.clear()
        password_fallback = await ac.post(
            "/api/v1/auth/invitations/accept",
            json={
                "email": "passkey@example.com",
                "password": "correct horse battery",
                "token": password_fallback_invitation.json()["token"],
            },
        )
        assert password_fallback.status_code == 401
        assert password_fallback.json()["detail"] == "Passkey sign-in required"

        async with async_session_factory() as db:
            credential = await db.get(WebAuthnCredential, passkey_id)
            assert credential is not None
            assert credential.sign_count == 4
            assert credential.last_used_at is not None

        device = await ac.post(
            "/oauth/device_authorization",
            json={"client_id": "gatekeeper-cli", "scope": "auth:read", "audience": "gatekeeper-api"},
        )
        assert device.status_code == 200
        ac.cookies.clear()
        unauthenticated_options = await ac.post(
            "/api/v1/auth/device/passkey/options",
            json={"user_code": device.json()["user_code"]},
        )
        assert unauthenticated_options.status_code == 401
        passkey_device_options = await ac.post(
            "/api/v1/auth/device/passkey/options",
            headers={"Authorization": f"Bearer {authenticated.json()['access_token']}"},
            json={"user_code": device.json()["user_code"]},
        )
        assert passkey_device_options.status_code == 200
        assert passkey_device_options.json()["public_key"]["allowCredentials"][0]["id"] == credential_id
        device_challenge_id = passkey_device_options.json()["challenge_id"]
        device_approved = await ac.post(
            "/api/v1/auth/device/passkey/verify",
            headers={"Authorization": f"Bearer {authenticated.json()['access_token']}"},
            json={
                "challenge_id": device_challenge_id,
                "credential": {
                    "id": credential_id,
                    "rawId": credential_id,
                    "type": "public-key",
                    "response": {
                        "authenticatorData": "authenticator-data",
                        "clientDataJSON": "client-data",
                        "signature": "signature",
                        "userHandle": None,
                    },
                },
            },
        )
        assert device_approved.status_code == 200
        assert device_approved.json()["status"] == "approved"
        device_replay = await ac.post(
            "/api/v1/auth/device/passkey/verify",
            headers={"Authorization": f"Bearer {authenticated.json()['access_token']}"},
            json={"challenge_id": device_challenge_id, "credential": {"id": credential_id}},
        )
        assert device_replay.status_code == 400
        device_token = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device.json()["device_code"],
                "client_id": "gatekeeper-cli",
            },
        )
        assert device_token.status_code == 200
        assert "webauthn" in decode_access_token(
            device_token.json()["access_token"],
            audience="gatekeeper-api",
        )["amr"]

        revoked = await ac.delete(
            f"/api/v1/auth/passkeys/{passkey_id}",
            headers={"Authorization": f"Bearer {authenticated.json()['access_token']}"},
        )
        assert revoked.status_code == 200

        revoked_login_options = await ac.post("/api/v1/auth/passkeys/authentication/options", json={})
        revoked_login = await ac.post(
            "/api/v1/auth/passkeys/authentication/verify",
            json={
                "challenge_id": revoked_login_options.json()["challenge_id"],
                "credential": {"id": credential_id},
            },
        )
        assert revoked_login.status_code == 401
        assert revoked_login.json()["detail"] == "Passkey authentication failed"
        revoked_login_replay = await ac.post(
            "/api/v1/auth/passkeys/authentication/verify",
            json={
                "challenge_id": revoked_login_options.json()["challenge_id"],
                "credential": {"id": credential_id},
            },
        )
        assert revoked_login_replay.status_code == 400
        assert revoked_login_replay.json()["detail"] == "Passkey ceremony expired or already used"


def test_client_ip_uses_the_rightmost_untrusted_forwarded_address(monkeypatch):
    def client_ip(peer: str, forwarded: str | None = None, **headers: str) -> str | None:
        if forwarded is not None:
            headers["x-forwarded-for"] = forwarded
        return services.client_ip(SimpleNamespace(client=SimpleNamespace(host=peer), headers=headers))

    assert client_ip("172.18.0.6", "203.0.113.9") == "172.18.0.6"
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "172.18.0.0/16, 10.0.0.0/8")
    assert client_ip("198.51.100.20", "203.0.113.9") == "198.51.100.20"
    assert client_ip("172.18.0.6", "203.0.113.9") == "203.0.113.9"
    assert client_ip("172.18.0.6", "1.2.3.4, 203.0.113.9") == "203.0.113.9"
    assert client_ip("172.18.0.6", "203.0.113.9, 10.0.0.1") == "203.0.113.9"
    assert client_ip("172.18.0.6", "203.0.113.9", **{"cf-connecting-ip": "2001:db8::7"}) == "203.0.113.9"
    assert client_ip("172.18.0.6", **{"cf-connecting-ip": "2001:db8::7"}) == "172.18.0.6"
    assert client_ip("172.18.0.6", "203.0.113.9, not-an-ip") == "172.18.0.6"
    assert client_ip("172.18.0.6", "10.0.0.5, 10.0.0.1") == "10.0.0.5"
    assert services.client_ip(None) is None


@pytest.mark.asyncio
async def test_audit_session_and_rate_limit_record_the_real_client_ip(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "127.0.0.0/8")
    async with await client() as ac:
        await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        login = await ac.post(
            "/api/v1/auth/login",
            headers={"X-Forwarded-For": "203.0.113.9"},
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert login.status_code == 200
        session_id = decode_access_token(login.json()["access_token"])["session_id"]

    async with async_session_factory() as db:
        assert (await db.get(Session, session_id)).ip_address == "203.0.113.9"
        login_event = (await db.execute(select(AuditEvent).where(AuditEvent.action == "auth.login"))).scalar_one()
        assert login_event.ip_address == "203.0.113.9"
        bucket_keys = set((await db.execute(select(RateLimitBucket.key))).scalars())
        assert "login:owner@example.com:203.0.113.9" in bucket_keys


@pytest.mark.asyncio
async def test_failed_login_attempts_persist_rate_limit_counters():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "limited@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200

        for _attempt in range(10):
            failed = await ac.post(
                "/api/v1/auth/login",
                json={"email": "limited@example.com", "password": "wrong password value"},
            )
            assert failed.status_code == 401

        limited = await ac.post(
            "/api/v1/auth/login",
            json={"email": "limited@example.com", "password": "correct horse battery"},
        )
        assert limited.status_code == 429
        assert limited.json()["detail"] == "Rate limit exceeded"


@pytest.mark.asyncio
async def test_passkey_management_requires_a_recent_session():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "reauth@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        stale_access = signup.json()["access_token"]
        session_id = decode_access_token(stale_access)["session_id"]
        async with async_session_factory() as db:
            session = await db.get(Session, session_id)
            assert session is not None
            session.created_at = security.now_utc() - timedelta(minutes=16)
            await db.commit()

        stale_options = await ac.post(
            "/api/v1/auth/passkeys/registration/options",
            headers={"Authorization": f"Bearer {stale_access}"},
        )
        assert stale_options.status_code == 401
        assert stale_options.json()["detail"] == "Sign in again before changing passkeys"

        login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "reauth@example.com", "password": "correct horse battery"},
        )
        assert login.status_code == 200
        fresh_options = await ac.post(
            "/api/v1/auth/passkeys/registration/options",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )
        assert fresh_options.status_code == 200


@pytest.mark.asyncio
async def test_passkey_options_reject_invalid_origin_configuration(monkeypatch):
    monkeypatch.setattr(settings, "webauthn_rp_id", "unrelated.example.com")
    monkeypatch.setattr(settings, "webauthn_origins", "http://auth.example.com/path")

    async with await client() as ac:
        options = await ac.post("/api/v1/auth/passkeys/authentication/options", json={})
        assert options.status_code == 503
        assert options.json()["detail"] == "Passkey origin configuration is invalid"


@pytest.mark.asyncio
async def test_client_mfa_policy_enforces_login_oauth_refresh_and_device_flows():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        setup_access = signup.json()["access_token"]

        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={
                "name": "MFA Web App",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["mfa-api"],
                "scopes": ["openid", "profile", "email", "api:read", "auth:read"],
                "require_mfa": True,
            },
        )
        assert created.status_code == 200
        assert created.json()["require_mfa"] is True

        no_mfa_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@example.com",
                "password": "correct horse battery",
                "client_id": created.json()["client_id"],
            },
        )
        assert no_mfa_login.status_code == 403
        assert no_mfa_login.json()["detail"] == "MFA enrollment required for this client"

        setup = await ac.post(
            "/api/v1/auth/mfa/totp/setup",
            headers={"Authorization": f"Bearer {setup_access}"},
        )
        assert setup.status_code == 200
        secret = setup.json()["secret"]
        enabled = await ac.post(
            "/api/v1/auth/mfa/totp/enable",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={"code": totp_code(secret)},
        )
        assert enabled.status_code == 200

        stale_session_authorize = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {setup_access}"},
            params={
                "response_type": "code",
                "client_id": created.json()["client_id"],
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": "abc",
                "code_challenge_method": "plain",
                "scope": "openid profile email api:read",
                "audience": "mfa-api",
            },
        )
        assert stale_session_authorize.status_code == 302
        step_up_location = urlparse(stale_session_authorize.headers["location"])
        assert f"{step_up_location.scheme}://{step_up_location.netloc}" == settings.ui_url
        assert step_up_location.path == "/login"
        step_up_query = parse_qs(step_up_location.query)
        assert step_up_query["step_up"] == ["mfa"]
        assert step_up_query["redirect"][0].startswith("/oauth/authorize?")

        mfa_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@example.com",
                "password": "correct horse battery",
                "client_id": created.json()["client_id"],
                "scope": "openid profile email api:read",
                "audience": "mfa-api",
                "totp_code": totp_code(secret),
            },
        )
        assert mfa_login.status_code == 200
        mfa_payload = mfa_login.json()
        assert mfa_payload["scope"] == "openid profile email api:read"
        mfa_claims = decode_access_token(mfa_payload["access_token"], audience="mfa-api")
        assert mfa_claims["amr"] == ["pwd", "otp"]
        assert set(mfa_claims["scope"].split()) == {"openid", "profile", "email", "api:read"}

        ui_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@example.com",
                "password": "correct horse battery",
                "client_id": created.json()["client_id"],
                "audience": settings.issuer,
                "totp_code": totp_code(secret),
            },
        )
        assert ui_login.status_code == 200
        ui_access = ui_login.json()["access_token"]
        product_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {mfa_payload['access_token']}"})
        assert product_me.status_code == 401

        refreshed = await ac.post("/api/v1/auth/refresh", json={"refresh_token": mfa_payload["refresh_token"]})
        assert refreshed.status_code == 200
        refreshed_claims = decode_access_token(refreshed.json()["access_token"], audience="mfa-api")
        assert refreshed_claims["amr"] == ["pwd", "otp"]

        approved = await approve_consent(
            ac,
            {"Authorization": f"Bearer {ui_access}"},
            {
                "response_type": "code",
                "client_id": created.json()["client_id"],
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": "abc",
                "code_challenge_method": "plain",
                "scope": "openid profile email api:read",
                "audience": "mfa-api",
            },
        )
        code = parse_qs(urlparse(approved).query)["code"][0]
        token = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": created.json()["client_id"],
                "redirect_uri": "https://app.example.com/callback",
                "code": code,
                "code_verifier": "abc",
            },
        )
        assert token.status_code == 200
        oauth_claims = decode_access_token(token.json()["access_token"], audience="mfa-api")
        assert oauth_claims["amr"] == ["pwd", "otp"]

        device = await ac.post(
            "/oauth/device_authorization",
            json={"client_id": created.json()["client_id"], "scope": "api:read", "audience": "mfa-api"},
        )
        assert device.status_code == 200
        stale_approve = await ac.post(
            "/api/v1/auth/device/approve",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={"user_code": device.json()["user_code"], "approve": True},
        )
        assert stale_approve.status_code == 403

        mfa_approve = await ac.post(
            "/api/v1/auth/device/approve",
            headers={"Authorization": f"Bearer {ui_access}"},
            json={"user_code": device.json()["user_code"], "approve": True},
        )
        assert mfa_approve.status_code == 200
        device_token = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device.json()["device_code"],
                "client_id": created.json()["client_id"],
            },
        )
        assert device_token.status_code == 200
        device_claims = decode_access_token(device_token.json()["access_token"], audience="mfa-api")
        assert device_claims["amr"] == ["pwd", "otp"]

        inline_mfa_device = await ac.post(
            "/oauth/device_authorization",
            json={"client_id": created.json()["client_id"], "scope": "api:read", "audience": "mfa-api"},
        )
        assert inline_mfa_device.status_code == 200
        inline_mfa_approve = await ac.post(
            "/api/v1/auth/device/approve",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={
                "user_code": inline_mfa_device.json()["user_code"],
                "approve": True,
                "totp_code": totp_code(secret),
            },
        )
        assert inline_mfa_approve.status_code == 200
        inline_device_token = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": inline_mfa_device.json()["device_code"],
                "client_id": created.json()["client_id"],
            },
        )
        assert inline_device_token.status_code == 200
        inline_device_claims = decode_access_token(inline_device_token.json()["access_token"], audience="mfa-api")
        assert inline_device_claims["amr"] == ["pwd", "otp"]


@pytest.mark.asyncio
async def test_trusted_device_mfa_bypass_requires_policy_and_active_trust():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        setup_access = signup.json()["access_token"]

        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={
                "name": "Trusted Device App",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["trusted-api"],
                "scopes": ["openid", "profile", "email", "api:read", "auth:read"],
                "require_mfa": True,
                "trusted_device_mfa_bypass": False,
            },
        )
        assert created.status_code == 200
        assert created.json()["trusted_device_mfa_bypass"] is False

        setup = await ac.post("/api/v1/auth/mfa/totp/setup", headers={"Authorization": f"Bearer {setup_access}"})
        assert setup.status_code == 200
        secret = setup.json()["secret"]
        enabled = await ac.post(
            "/api/v1/auth/mfa/totp/enable",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={"code": totp_code(secret)},
        )
        assert enabled.status_code == 200

        password_only = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "client_id": created.json()["client_id"],
            },
        )
        assert password_only.status_code == 401
        assert password_only.json()["detail"] == "TOTP code required"

        mfa_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "client_id": created.json()["client_id"],
                "audience": settings.issuer,
                "totp_code": totp_code(secret),
            },
        )
        assert mfa_login.status_code == 200
        mfa_claims = decode_access_token(mfa_login.json()["access_token"])
        trusted = await ac.patch(
            f"/api/v1/sessions/{mfa_claims['session_id']}/device",
            headers={"Authorization": f"Bearer {mfa_login.json()['access_token']}"},
            json={"device_label": "Trusted laptop", "trusted": True},
        )
        assert trusted.status_code == 200
        assert trusted.json()["trusted"] is True

        still_without_policy = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "client_id": created.json()["client_id"],
            },
        )
        assert still_without_policy.status_code == 401
        assert still_without_policy.json()["detail"] == "TOTP code required"

        enabled_policy = await ac.patch(
            f"/api/v1/clients/{created.json()['id']}",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={"trusted_device_mfa_bypass": True},
        )
        assert enabled_policy.status_code == 200
        assert enabled_policy.json()["trusted_device_mfa_bypass"] is True

        trusted_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "client_id": created.json()["client_id"],
                "audience": settings.issuer,
            },
        )
        assert trusted_login.status_code == 200
        trusted_claims = decode_access_token(trusted_login.json()["access_token"])
        assert trusted_claims["amr"] == ["pwd", "trusted_device"]
        current_session = await ac.get(
            "/api/v1/sessions",
            headers={"Authorization": f"Bearer {trusted_login.json()['access_token']}"},
        )
        assert current_session.status_code == 200
        assert next(item for item in current_session.json() if item["current"])["trusted"] is True

        refreshed = await ac.post("/api/v1/auth/refresh", json={"refresh_token": trusted_login.json()["refresh_token"]})
        assert refreshed.status_code == 200
        refreshed_claims = decode_access_token(refreshed.json()["access_token"])
        assert refreshed_claims["aud"] == settings.issuer
        assert refreshed_claims["amr"] == ["pwd", "trusted_device"]

        disabled_policy = await ac.patch(
            f"/api/v1/clients/{created.json()['id']}",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={"trusted_device_mfa_bypass": False},
        )
        assert disabled_policy.status_code == 200

        stale_refresh = await ac.post("/api/v1/auth/refresh", json={"refresh_token": refreshed.json()["refresh_token"]})
        assert stale_refresh.status_code == 401
        assert stale_refresh.json()["detail"] == "MFA required for this session"


@pytest.mark.asyncio
async def test_admin_step_up_policy_requires_mfa_for_sensitive_org_mutations():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        setup_access = signup.json()["access_token"]
        org_id = signup.json()["orgs"][0]["id"]

        before_policy = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={
                "name": "Before Policy App",
                "public": True,
                "redirect_uris": ["https://before.example.com/callback"],
                "audiences": ["before-api"],
                "scopes": ["openid", "profile", "email"],
            },
        )
        assert before_policy.status_code == 200

        enabled_policy = await ac.patch(
            f"/api/v1/orgs/{org_id}",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={"admin_step_up_mfa_required": True},
        )
        assert enabled_policy.status_code == 200
        assert enabled_policy.json()["admin_step_up_mfa_required"] is True

        without_enrollment = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={
                "name": "Blocked App",
                "public": True,
                "redirect_uris": ["https://blocked.example.com/callback"],
                "audiences": ["blocked-api"],
                "scopes": ["openid", "profile", "email"],
            },
        )
        assert without_enrollment.status_code == 403
        assert without_enrollment.json()["detail"] == "MFA enrollment required for sensitive organization actions"

        setup = await ac.post("/api/v1/auth/mfa/totp/setup", headers={"Authorization": f"Bearer {setup_access}"})
        assert setup.status_code == 200
        secret = setup.json()["secret"]
        enabled = await ac.post(
            "/api/v1/auth/mfa/totp/enable",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={"code": totp_code(secret)},
        )
        assert enabled.status_code == 200

        without_step_up = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={
                "name": "Still Blocked App",
                "public": True,
                "redirect_uris": ["https://still-blocked.example.com/callback"],
                "audiences": ["still-blocked-api"],
                "scopes": ["openid", "profile", "email"],
            },
        )
        assert without_step_up.status_code == 403
        assert without_step_up.json()["detail"] == "MFA required for sensitive organization actions"

        mfa_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "totp_code": totp_code(secret),
            },
        )
        assert mfa_login.status_code == 200
        mfa_access = mfa_login.json()["access_token"]
        mfa_claims = decode_access_token(mfa_access)
        assert mfa_claims["amr"] == ["pwd", "otp"]

        allowed_client = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {mfa_access}"},
            json={
                "name": "Allowed Step-Up App",
                "public": True,
                "redirect_uris": ["https://allowed.example.com/callback"],
                "audiences": ["allowed-api"],
                "scopes": ["openid", "profile", "email"],
            },
        )
        assert allowed_client.status_code == 200

        disabled_policy = await ac.patch(
            f"/api/v1/orgs/{org_id}",
            headers={"Authorization": f"Bearer {mfa_access}"},
            json={"admin_step_up_mfa_required": False},
        )
        assert disabled_policy.status_code == 200
        assert disabled_policy.json()["admin_step_up_mfa_required"] is False


@pytest.mark.asyncio
async def test_org_mfa_policy_enforces_org_clients_and_revokes_stale_sessions():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        setup_access = signup.json()["access_token"]
        org_id = signup.json()["orgs"][0]["id"]

        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={
                "name": "Org App",
                "org_id": org_id,
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["org-api"],
                "scopes": ["openid", "profile", "email", "api:read"],
                "require_org_membership": True,
            },
        )
        assert created.status_code == 200

        pre_policy_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "client_id": created.json()["client_id"],
            },
        )
        assert pre_policy_login.status_code == 200
        stale_access = pre_policy_login.json()["access_token"]
        stale_refresh = pre_policy_login.json()["refresh_token"]

        policy = await ac.patch(
            f"/api/v1/orgs/{org_id}",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={"require_mfa": True},
        )
        assert policy.status_code == 200
        assert policy.json()["require_mfa"] is True

        stale_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {stale_access}"})
        assert stale_me.status_code == 401
        stale_rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": stale_refresh})
        assert stale_rotated.status_code == 401

        no_mfa_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "client_id": created.json()["client_id"],
            },
        )
        assert no_mfa_login.status_code == 403
        assert no_mfa_login.json()["detail"] == "MFA enrollment required for this organization"

        setup = await ac.post(
            "/api/v1/auth/mfa/totp/setup",
            headers={"Authorization": f"Bearer {setup_access}"},
        )
        assert setup.status_code == 200
        secret = setup.json()["secret"]
        enabled = await ac.post(
            "/api/v1/auth/mfa/totp/enable",
            headers={"Authorization": f"Bearer {setup_access}"},
            json={"code": totp_code(secret)},
        )
        assert enabled.status_code == 200

        stale_authorize = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {setup_access}"},
            params={
                "response_type": "code",
                "client_id": created.json()["client_id"],
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": "abc",
                "code_challenge_method": "plain",
                "scope": "openid profile email api:read",
                "audience": "org-api",
            },
        )
        assert stale_authorize.status_code == 302
        step_up_location = urlparse(stale_authorize.headers["location"])
        assert f"{step_up_location.scheme}://{step_up_location.netloc}" == settings.ui_url
        assert step_up_location.path == "/login"
        step_up_query = parse_qs(step_up_location.query)
        assert step_up_query["step_up"] == ["mfa"]
        assert step_up_query["redirect"][0].startswith("/oauth/authorize?")

        mfa_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "client_id": created.json()["client_id"],
                "totp_code": totp_code(secret),
            },
        )
        assert mfa_login.status_code == 200
        claims = decode_access_token(mfa_login.json()["access_token"], audience="org-api")
        assert claims["org_id"] == org_id
        assert claims["amr"] == ["pwd", "otp"]

        orgs = await ac.get("/api/v1/orgs", headers={"Authorization": f"Bearer {setup_access}"})
        assert orgs.status_code == 200
        assert orgs.json()[0]["require_mfa"] is True


@pytest.mark.asyncio
async def test_admin_totp_reset_clears_mfa_and_revokes_sessions():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        user_id = signup.json()["user"]["id"]
        first_access = signup.json()["access_token"]

        setup = await ac.post("/api/v1/auth/mfa/totp/setup", headers={"Authorization": f"Bearer {first_access}"})
        assert setup.status_code == 200
        secret = setup.json()["secret"]
        enable = await ac.post(
            "/api/v1/auth/mfa/totp/enable",
            headers={"Authorization": f"Bearer {first_access}"},
            json={"code": totp_code(secret)},
        )
        assert enable.status_code == 200

        mfa_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "correct horse battery", "totp_code": totp_code(secret)},
        )
        assert mfa_login.status_code == 200
        mfa_access = mfa_login.json()["access_token"]
        mfa_refresh = mfa_login.json()["refresh_token"]

        admin_read = await ac.get(f"/api/v1/users/{user_id}", headers={"Authorization": f"Bearer {first_access}"})
        assert admin_read.status_code == 200
        assert admin_read.json()["mfa_totp_enabled"] is True
        assert admin_read.json()["mfa_totp_enabled_at"] is not None

        reset = await ac.post(
            f"/api/v1/users/{user_id}/mfa/totp/reset",
            headers={"Authorization": f"Bearer {first_access}"},
        )
        assert reset.status_code == 200
        assert reset.json()["status"] == "reset"
        assert reset.json()["revoked_count"] >= 2
        assert reset.json()["user"]["mfa_totp_enabled"] is False
        assert reset.json()["user"]["mfa_totp_enabled_at"] is None

        old_session = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {mfa_access}"})
        assert old_session.status_code == 401
        first_session = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {first_access}"})
        assert first_session.status_code == 401
        rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": mfa_refresh})
        assert rotated.status_code == 401

        password_only_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        assert password_only_login.status_code == 200
        assert password_only_login.json()["user"]["mfa_totp_enabled"] is False


@pytest.mark.asyncio
async def test_invitation_create_accept_reuse_and_revoke(monkeypatch):
    async with await client() as ac:
        owner = await register(
            ac,
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "display_name": "Owner User",
            },
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        invite = await ac.post(
            "/api/v1/invitations",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"email": "invited@example.com", "org_id": org_id, "role": "operator"},
        )
        assert invite.status_code == 200
        invite_payload = invite.json()
        invite_token = invite_payload["token"]
        assert invite_token.startswith("gki_")
        assert invite_payload["token_hint"] == invite_token[-8:]
        assert invite_payload["role"] == "operator"
        assert invite_payload["accepted_at"] is None

        listed = await ac.get(
            f"/api/v1/invitations?org_id={org_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
        )
        assert listed.status_code == 200
        assert [item["id"] for item in listed.json()] == [invite_payload["id"]]

        mismatch = await ac.post(
            "/api/v1/auth/invitations/accept",
            json={
                "email": "other@example.com",
                "password": "correct horse battery",
                "token": invite_token,
            },
        )
        assert mismatch.status_code == 403

        closed_mode = await ac.post(
            "/api/v1/auth/invitations/accept",
            json={"email": "invited@example.com", "password": "correct horse battery", "token": invite_token},
        )
        assert closed_mode.status_code == 403
        async with async_session_factory() as db:
            assert (await db.execute(select(User).where(User.email == "invited@example.com"))).first() is None

        monkeypatch.setattr(settings, "signup_mode", "invite")
        accepted = await ac.post(
            "/api/v1/auth/invitations/accept",
            json={
                "email": "invited@example.com",
                "password": "correct horse battery",
                "display_name": "Invited User",
                "token": invite_token,
            },
        )
        assert accepted.status_code == 200
        accepted_payload = accepted.json()
        assert accepted_payload["user"]["email"] == "invited@example.com"
        assert accepted_payload["user"]["email_verified"] is True
        invited_org = next(item for item in accepted_payload["orgs"] if item["id"] == org_id)
        assert invited_org["role"] == "operator"
        invited_claims = decode_access_token(accepted_payload["access_token"])
        assert invited_claims["org_id"] == org_id
        assert invited_claims["org_role"] == "operator"
        assert "token:*" in invited_claims["permissions"]

        reused = await ac.post(
            "/api/v1/auth/invitations/accept",
            json={
                "email": "invited@example.com",
                "password": "correct horse battery",
                "token": invite_token,
            },
        )
        assert reused.status_code == 401

        inactive = await ac.get(
            f"/api/v1/invitations?org_id={org_id}&include_inactive=true",
            headers={"Authorization": f"Bearer {owner_access}"},
        )
        assert inactive.status_code == 200
        accepted_invite = next(item for item in inactive.json() if item["id"] == invite_payload["id"])
        assert accepted_invite["accepted_at"] is not None
        assert accepted_invite["accepted_user_id"] == accepted_payload["user"]["id"]

        revoke_invite = await ac.post(
            "/api/v1/invitations",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"email": "revoked@example.com", "org_id": org_id, "role": "viewer"},
        )
        assert revoke_invite.status_code == 200
        revoke_token = revoke_invite.json()["token"]
        revoked = await ac.delete(
            f"/api/v1/invitations/{revoke_invite.json()['id']}",
            headers={"Authorization": f"Bearer {owner_access}"},
        )
        assert revoked.status_code == 200
        revoked_accept = await ac.post(
            "/api/v1/auth/invitations/accept",
            json={
                "email": "revoked@example.com",
                "password": "correct horse battery",
                "token": revoke_token,
            },
        )
        assert revoked_accept.status_code == 401


@pytest.mark.asyncio
async def test_bootstrap_admin_subsequent_user_and_duplicate_roles():
    async with await client() as ac:
        first = await register(
            ac,
            json={"email": "first@example.com", "password": "correct horse battery"},
        )
        assert first.status_code == 200
        assert first.json()["orgs"][0]["role"] == "owner"

        bootstrap_admin = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        assert bootstrap_admin.status_code == 200
        assert bootstrap_admin.json()["orgs"][0]["role"] == "viewer"

        viewer = await register(
            ac,
            json={"email": "viewer@example.com", "password": "correct horse battery"},
        )
        assert viewer.status_code == 200
        assert viewer.json()["orgs"][0]["role"] == "viewer"

        duplicate = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "viewer@example.com", "password": "correct horse battery"},
        )
        assert duplicate.status_code == 403


@pytest.mark.asyncio
async def test_new_accounts_get_no_default_bootstrap_membership(monkeypatch):
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        assert [org["role"] for org in owner.json()["orgs"]] == ["owner"]
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        second_org = await ac.post("/api/v1/orgs", headers=owner_headers, json={"name": "Second", "slug": "second"})
        assert second_org.status_code == 200
        switched = await ac.post(
            "/api/v1/auth/session/switch-org", headers=owner_headers, json={"org_id": second_org.json()["id"]}
        )
        invite = await ac.post(
            "/api/v1/invitations",
            headers={"Authorization": f"Bearer {switched.json()['access_token']}"},
            json={"email": "invited@example.com", "org_id": second_org.json()["id"], "role": "operator"},
        )
        assert invite.status_code == 200

        monkeypatch.setattr(settings, "signup_mode", "invite")
        accepted = await ac.post(
            "/api/v1/auth/invitations/accept",
            json={"email": "invited@example.com", "password": password, "token": invite.json()["token"]},
        )
        assert accepted.status_code == 200
        assert [(org["id"], org["role"]) for org in accepted.json()["orgs"]] == [(second_org.json()["id"], "operator")]

    async with async_session_factory() as db:
        for email in ("plain@example.com", str(settings.bootstrap_admin_email)):
            user = await services.create_user(db, email=email, password=password)
            assert await services.org_roles(db, user.id) == []


@pytest.mark.asyncio
async def test_bootstrap_org_without_owner_is_never_auto_promoted(monkeypatch):
    sent: list[str] = []

    def accept(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content)["data"]["attributes"]["subject"])
        return httpx.Response(202)

    monkeypatch.setattr(alerts, "_transport", httpx.MockTransport(accept))
    monkeypatch.setattr(settings, "sendy_api_key", "test-sendy-key")
    monkeypatch.setattr(settings, "alert_email_to", "ops@example.com")
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        member = await register(ac, json={"email": "member@example.com", "password": password})

    async with async_session_factory() as db:
        owner_membership = (
            await db.execute(select(Membership).where(Membership.user_id == owner.json()["user"]["id"]))
        ).scalar_one()
        owner_membership.status = "revoked"
        await db.commit()
        org = await services.ensure_bootstrap(db)
        assert not await services.org_has_owner(db, org.id)
        assert [item.role for item in await services.org_roles(db, member.json()["user"]["id"])] == ["viewer"]
        missing = await db.execute(select(AuditEvent).where(AuditEvent.action == "org.owner.missing"))
        assert missing.scalars().first() is not None
    await asyncio.gather(*alerts._pending)
    assert "[GateKeeper] Bootstrap organization has no owner" in sent

    await ops.set_bootstrap_owner("member@example.com")
    async with async_session_factory() as db:
        assert [item.role for item in await services.org_roles(db, member.json()["user"]["id"])] == ["owner"]
        promoted = await db.execute(select(AuditEvent).where(AuditEvent.action == "org.owner.bootstrap"))
        assert promoted.scalar_one().details["via"] == "operator"


@pytest.mark.asyncio
async def test_cookie_auth_and_refresh_preserve_owner_scope(monkeypatch):
    monkeypatch.setattr(settings, "cookie_name", "gk_custom_session")
    async with await client() as ac:
        signup = await register(
            ac,
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "display_name": "Owner User",
            },
        )
        assert signup.status_code == 200
        assert settings.cookie_name in ac.cookies
        signup_claims = decode_access_token(signup.json()["access_token"])
        assert signup_claims["email"] == "owner@example.com"
        assert signup_claims["display_name"] == "Owner User"
        assert signup_claims["email_verified"] is False
        assert "*" in signup.json()["scope"].split()
        assert signup_claims["org_id"] == signup.json()["orgs"][0]["id"]
        assert signup_claims["org_slug"] == signup.json()["orgs"][0]["slug"]
        assert signup_claims["org_role"] == "owner"
        assert "*" in signup_claims["permissions"]
        refresh = signup.json()["refresh_token"]

        cookie_me = await ac.get("/api/v1/auth/me")
        assert cookie_me.status_code == 200
        assert cookie_me.json()["user"]["email"] == "owner@example.com"

        rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert rotated.status_code == 200
        assert "*" in rotated.json()["scope"].split()
        rotated_claims = decode_access_token(rotated.json()["access_token"])
        assert rotated_claims["email"] == "owner@example.com"
        assert rotated_claims["display_name"] == "Owner User"
        assert rotated_claims["email_verified"] is False
        assert rotated_claims["org_role"] == "owner"
        assert "*" in rotated_claims["permissions"]

        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {rotated.json()['access_token']}"},
            json={
                "name": "Example Dashboard",
                "public": True,
                "redirect_uris": ["https://dashboard.example.com/auth/callback"],
                "allowed_origins": ["https://dashboard.example.com"],
                "audiences": ["dashboard-api"],
                "scopes": ["auth:read"],
            },
        )
        assert created.status_code == 200

        login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert login.status_code == 200
        assert "*" in login.json()["scope"].split()

        created_with_login = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
            json={
                "name": "Direct Login Dashboard",
                "public": True,
                "redirect_uris": ["https://direct.example.com/auth/callback"],
                "allowed_origins": ["https://direct.example.com"],
                "audiences": ["direct-api"],
                "scopes": ["auth:read"],
            },
        )
        assert created_with_login.status_code == 200


@pytest.mark.asyncio
async def test_session_revocation_invalidates_access_and_refresh_tokens():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        payload = signup.json()
        access = payload["access_token"]
        refresh = payload["refresh_token"]

        sessions = await ac.get("/api/v1/sessions", headers={"Authorization": f"Bearer {access}"})
        assert sessions.status_code == 200
        session_id = sessions.json()[0]["id"]

        revoked = await ac.delete(f"/api/v1/sessions/{session_id}", headers={"Authorization": f"Bearer {access}"})
        assert revoked.status_code == 200

        me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"})
        assert me.status_code == 401

        rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert rotated.status_code == 401

        introspected = await ac.post("/oauth/introspect", data={"token": access})
        assert introspected.status_code == 200
        assert introspected.json()["active"] is False


@pytest.mark.asyncio
async def test_org_idle_timeout_revokes_idle_session_and_refresh_token():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        payload = signup.json()
        access = payload["access_token"]
        refresh = payload["refresh_token"]
        org_id = payload["orgs"][0]["id"]
        session_id = decode_access_token(access)["session_id"]

        policy = await ac.patch(
            f"/api/v1/orgs/{org_id}",
            headers={"Authorization": f"Bearer {access}"},
            json={"session_idle_timeout_minutes": 5},
        )
        assert policy.status_code == 200
        assert policy.json()["session_idle_timeout_minutes"] == 5

        async with async_session_factory() as db:
            session = await db.get(Session, session_id)
            assert session is not None
            session.last_seen_at = security.now_utc() - timedelta(minutes=6)
            await db.commit()

        me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"})
        assert me.status_code == 401
        assert me.json()["detail"] == "Session idle timeout expired"

        rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert rotated.status_code == 401

        async with async_session_factory() as db:
            session = await db.get(Session, session_id)
            assert session is not None
            assert session.revoked_at is not None


@pytest.mark.asyncio
async def test_session_device_label_and_trust_are_self_service():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]

        sessions = await ac.get("/api/v1/sessions", headers={"Authorization": f"Bearer {access}"})
        assert sessions.status_code == 200
        session_id = sessions.json()[0]["id"]

        expired_trust = await ac.patch(
            f"/api/v1/sessions/{session_id}/device",
            headers={"Authorization": f"Bearer {access}"},
            json={"trusted": True, "trusted_until": "2000-01-01T00:00:00Z"},
        )
        assert expired_trust.status_code == 400

        updated = await ac.patch(
            f"/api/v1/sessions/{session_id}/device",
            headers={"Authorization": f"Bearer {access}"},
            json={"device_label": "Work laptop", "trusted": True},
        )
        assert updated.status_code == 200
        updated_payload = updated.json()
        assert updated_payload["device_label"] == "Work laptop"
        assert updated_payload["trusted"] is True
        assert updated_payload["trusted_at"]
        assert updated_payload["trusted_until"]
        assert updated_payload["amr"] == ["pwd"]

        listed = await ac.get("/api/v1/sessions", headers={"Authorization": f"Bearer {access}"})
        assert listed.status_code == 200
        listed_session = next(session for session in listed.json() if session["id"] == session_id)
        assert listed_session["device_label"] == "Work laptop"
        assert listed_session["trusted"] is True

        other = await register(
            ac,
            json={"email": "other@example.com", "password": "correct horse battery"},
        )
        assert other.status_code == 200
        forbidden = await ac.patch(
            f"/api/v1/sessions/{session_id}/device",
            headers={"Authorization": f"Bearer {other.json()['access_token']}"},
            json={"device_label": "Other user's label"},
        )
        assert forbidden.status_code == 403

        cleared = await ac.patch(
            f"/api/v1/sessions/{session_id}/device",
            headers={"Authorization": f"Bearer {access}"},
            json={"device_label": "", "trusted": False},
        )
        assert cleared.status_code == 200
        assert cleared.json()["device_label"] is None
        assert cleared.json()["trusted"] is False
        assert cleared.json()["trusted_at"] is None
        assert cleared.json()["trusted_until"] is None


@pytest.mark.asyncio
async def test_logout_revokes_current_session_and_refresh_token():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]
        refresh = signup.json()["refresh_token"]

        logout = await ac.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {access}"})
        assert logout.status_code == 200
        assert logout.json()["session_revoked"] is True
        assert ac.cookies.get(settings.refresh_cookie_name) is None

        me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"})
        assert me.status_code == 401
        rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert rotated.status_code == 401


@pytest.mark.asyncio
async def test_bulk_session_revocation_supports_other_devices_and_global_signout():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        first_access = signup.json()["access_token"]
        first_refresh = signup.json()["refresh_token"]

        login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert login.status_code == 200
        second_access = login.json()["access_token"]
        second_refresh = login.json()["refresh_token"]

        revoke_others = await ac.post(
            "/api/v1/sessions/revoke-all",
            headers={"Authorization": f"Bearer {second_access}"},
            json={"include_current": False},
        )
        assert revoke_others.status_code == 200
        assert revoke_others.json()["revoked_count"] == 1

        first_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {first_access}"})
        assert first_me.status_code == 401
        first_rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
        assert first_rotated.status_code == 401

        second_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {second_access}"})
        assert second_me.status_code == 200
        second_rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": second_refresh})
        assert second_rotated.status_code == 200
        current_access = second_rotated.json()["access_token"]
        current_refresh = second_rotated.json()["refresh_token"]

        revoke_all = await ac.post(
            "/api/v1/sessions/revoke-all",
            headers={"Authorization": f"Bearer {current_access}"},
            json={"include_current": True},
        )
        assert revoke_all.status_code == 200
        assert revoke_all.json()["revoked_count"] == 1

        current_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {current_access}"})
        assert current_me.status_code == 401
        current_rotated = await ac.post("/api/v1/auth/refresh", json={"refresh_token": current_refresh})
        assert current_rotated.status_code == 401


@pytest.mark.asyncio
async def test_bad_redirect_is_rejected_for_oauth_client():
    async with await client() as ac:
        signup = await register(
            ac,
            json={
                "email": "admin@example.com",
                "password": "correct horse battery",
                "display_name": "Admin User",
            },
        )
        access = signup.json()["access_token"]
        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Example Web",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["example-api"],
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
async def test_client_metadata_urls_must_be_absolute_http_urls():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        access = signup.json()["access_token"]
        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Example Web",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["example-api"],
                "scopes": ["openid", "profile"],
                "logo_url": "javascript:alert(1)",
            },
        )
        assert created.status_code == 422
        assert "logo_url" in created.json()["detail"]


@pytest.mark.asyncio
async def test_authorize_redirects_unauthenticated_user_to_hosted_login():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        access = signup.json()["access_token"]
        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Example Web",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["example-api"],
                "scopes": ["openid", "profile", "email", "api:read"],
            },
        )
        assert created.status_code == 200
        ac.cookies.clear()

        authorize = await ac.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": created.json()["client_id"],
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": "abc",
                "code_challenge_method": "plain",
                "scope": "openid profile email api:read",
                "audience": "example-api",
                "state": "resume-state",
            },
        )

        assert authorize.status_code == 302
        location = authorize.headers["location"]
        parsed = urlparse(location)
        assert f"{parsed.scheme}://{parsed.netloc}" == settings.ui_url
        assert parsed.path == "/login"
        redirect = parse_qs(parsed.query)["redirect"][0]
        assert redirect.startswith("/oauth/authorize?")
        assert "client_id=" in redirect
        assert "state=resume-state" in redirect


@pytest.mark.asyncio
async def test_authorize_requires_consent_before_issuing_code():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        access = signup.json()["access_token"]
        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Example Web",
                "description": "Example Web handles workspace dashboards and API access.",
                "logo_url": "https://app.example.com/logo.png",
                "homepage_url": "https://app.example.com",
                "privacy_policy_url": "https://app.example.com/privacy",
                "terms_url": "https://app.example.com/terms",
                "publisher_name": "Example Inc",
                "verified": True,
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "allowed_origins": ["https://app.example.com"],
                "audiences": ["example-api"],
                "scopes": ["openid", "profile", "email", "api:read"],
            },
        )
        assert created.status_code == 200
        assert created.json()["publisher_name"] == "Example Inc"
        assert created.json()["verified"] is True
        assert created.json()["verified_at"]
        params = {
            "response_type": "code",
            "client_id": created.json()["client_id"],
            "redirect_uri": "https://app.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
            "scope": "openid profile email api:read",
            "audience": "example-api",
            "state": "consent-state",
        }

        authorize = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {access}"},
            params=params,
        )
        assert authorize.status_code == 302
        consent_location = authorize.headers["location"]
        consent_parsed = urlparse(consent_location)
        assert f"{consent_parsed.scheme}://{consent_parsed.netloc}" == settings.ui_url
        assert consent_parsed.path == "/authorize"
        assert "approve=" not in consent_parsed.query

        context = await ac.get(
            f"/api/v1/oauth/authorize/context?{consent_parsed.query}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert context.status_code == 200
        context_payload = context.json()
        assert context_payload["client"]["name"] == "Example Web"
        assert context_payload["client"]["description"] == "Example Web handles workspace dashboards and API access."
        assert context_payload["client"]["logo_url"] == "https://app.example.com/logo.png"
        assert context_payload["client"]["homepage_url"] == "https://app.example.com"
        assert context_payload["client"]["privacy_policy_url"] == "https://app.example.com/privacy"
        assert context_payload["client"]["terms_url"] == "https://app.example.com/terms"
        assert context_payload["client"]["publisher_name"] == "Example Inc"
        assert context_payload["client"]["verified"] is True
        assert context_payload["client"]["verified_at"]
        assert context_payload["redirect_uri"] == "https://app.example.com/callback"
        assert context_payload["scopes"] == ["openid", "profile", "email", "api:read"]
        assert context_payload["audience"] == "example-api"
        selected_org_id = context_payload["selected_org_id"]
        assert selected_org_id == signup.json()["orgs"][0]["id"]

        invalid_context = await ac.get(
            f"/api/v1/oauth/authorize/context?{consent_parsed.query}&org_id=not-an-org",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert invalid_context.status_code == 403

        invalid_approve = await ac.post(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {access}"},
            json={
                **params,
                "approve": True,
                "org_id": "not-an-org",
                "consent_nonce": context_payload["consent_nonce"],
            },
        )
        assert invalid_approve.status_code == 403

        approved = await approve_consent(
            ac, {"Authorization": f"Bearer {access}"}, {**params, "org_id": selected_org_id}
        )
        callback = urlparse(approved)
        assert f"{callback.scheme}://{callback.netloc}{callback.path}" == "https://app.example.com/callback"
        callback_query = parse_qs(callback.query)
        assert callback_query["state"] == ["consent-state"]
        code = callback_query["code"][0]
        assert code.startswith("gkc_")

        token = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": created.json()["client_id"],
                "redirect_uri": "https://app.example.com/callback",
                "code": code,
                "code_verifier": "abc",
            },
        )
        assert token.status_code == 200
        claims = decode_access_token(token.json()["access_token"], audience="example-api")
        assert claims["org_id"] == selected_org_id
        assert claims["org_role"] == "owner"
        assert "*" in claims["permissions"]

        grants = await ac.get("/api/v1/oauth/grants", headers={"Authorization": f"Bearer {access}"})
        assert grants.status_code == 200
        grant_payload = grants.json()
        assert len(grant_payload) == 1
        assert grant_payload[0]["client_id"] == created.json()["client_id"]
        assert grant_payload[0]["org_id"] == selected_org_id
        assert set(grant_payload[0]["scopes"]) == {"openid", "profile", "email", "api:read"}

        remembered = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {access}"},
            params={**params, "state": "remembered-state"},
        )
        assert remembered.status_code == 302
        remembered_callback = urlparse(remembered.headers["location"])
        assert f"{remembered_callback.scheme}://{remembered_callback.netloc}{remembered_callback.path}" == (
            "https://app.example.com/callback"
        )
        remembered_query = parse_qs(remembered_callback.query)
        assert remembered_query["state"] == ["remembered-state"]
        assert remembered_query["code"][0].startswith("gkc_")

        revoked_grant = await ac.delete(
            f"/api/v1/oauth/grants/{grant_payload[0]['id']}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert revoked_grant.status_code == 200

        after_revoke = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {access}"},
            params={**params, "state": "after-revoke-state"},
        )
        assert after_revoke.status_code == 302
        after_revoke_location = urlparse(after_revoke.headers["location"])
        assert f"{after_revoke_location.scheme}://{after_revoke_location.netloc}" == settings.ui_url
        assert after_revoke_location.path == "/authorize"


@pytest.mark.asyncio
async def test_admin_can_review_and_revoke_oauth_grants_within_current_org():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        signup_payload = signup.json()
        access = signup_payload["access_token"]
        org_id = signup_payload["orgs"][0]["id"]
        user_id = signup_payload["user"]["id"]

        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Example Web",
                "org_id": org_id,
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "allowed_origins": ["https://app.example.com"],
                "audiences": ["example-api"],
                "scopes": ["openid", "profile", "email", "api:read"],
            },
        )
        assert created.status_code == 200
        params = {
            "response_type": "code",
            "client_id": created.json()["client_id"],
            "redirect_uri": "https://app.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
            "scope": "openid profile email api:read",
            "audience": "example-api",
        }

        approved = await approve_consent(
            ac, {"Authorization": f"Bearer {access}"}, {**params, "org_id": org_id, "state": "admin-review"}
        )
        assert parse_qs(urlparse(approved).query)["code"][0].startswith("gkc_")

        admin_grants = await ac.get(
            f"/api/v1/oauth/grants/admin?org_id={org_id}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert admin_grants.status_code == 200
        grant_payload = admin_grants.json()
        assert len(grant_payload) == 1
        assert grant_payload[0]["client_id"] == created.json()["client_id"]
        assert grant_payload[0]["user_id"] == user_id
        assert grant_payload[0]["user_email"] == "admin@example.com"
        assert grant_payload[0]["org_id"] == org_id

        revoked = await ac.delete(
            f"/api/v1/oauth/grants/admin/{grant_payload[0]['id']}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert revoked.status_code == 200

        self_grants = await ac.get("/api/v1/oauth/grants", headers={"Authorization": f"Bearer {access}"})
        assert self_grants.status_code == 200
        assert self_grants.json() == []

        revoked_grants = await ac.get(
            f"/api/v1/oauth/grants/admin?org_id={org_id}&include_revoked=true",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert revoked_grants.status_code == 200
        assert len(revoked_grants.json()) == 1
        assert revoked_grants.json()[0]["revoked_at"] is not None

        after_revoke = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {access}"},
            params={**params, "state": "after-admin-revoke"},
        )
        assert after_revoke.status_code == 302
        after_revoke_location = urlparse(after_revoke.headers["location"])
        assert f"{after_revoke_location.scheme}://{after_revoke_location.netloc}" == settings.ui_url
        assert after_revoke_location.path == "/authorize"

        created_org = await ac.post(
            "/api/v1/orgs",
            headers={"Authorization": f"Bearer {access}"},
            json={"name": "Second Product", "slug": "second-product"},
        )
        assert created_org.status_code == 200
        second_org_id = created_org.json()["id"]
        switched = await ac.post(
            "/api/v1/auth/session/switch-org",
            headers={"Authorization": f"Bearer {access}"},
            json={"org_id": second_org_id},
        )
        assert switched.status_code == 200
        second_access = switched.json()["access_token"]

        second_client = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {second_access}"},
            json={
                "name": "Second Web",
                "org_id": second_org_id,
                "public": True,
                "redirect_uris": ["https://second.example.com/callback"],
                "allowed_origins": ["https://second.example.com"],
                "audiences": ["second-api"],
                "scopes": ["openid", "profile", "api:read"],
            },
        )
        assert second_client.status_code == 200
        second_params = {
            "response_type": "code",
            "client_id": second_client.json()["client_id"],
            "redirect_uri": "https://second.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
            "scope": "openid profile api:read",
            "audience": "second-api",
        }
        await approve_consent(
            ac,
            {"Authorization": f"Bearer {second_access}"},
            {**second_params, "org_id": second_org_id, "state": "second-admin-review"},
        )

        cross_org_list = await ac.get(
            f"/api/v1/oauth/grants/admin?org_id={second_org_id}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert cross_org_list.status_code == 403

        second_admin_grants = await ac.get(
            f"/api/v1/oauth/grants/admin?org_id={second_org_id}",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        assert second_admin_grants.status_code == 200
        foreign_revoke = await ac.delete(
            f"/api/v1/oauth/grants/admin/{second_admin_grants.json()[0]['id']}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert foreign_revoke.status_code == 404


@pytest.mark.asyncio
async def test_authorize_can_issue_personal_tokens_for_clients_without_required_org_membership():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        access = signup.json()["access_token"]
        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Personal Web",
                "public": True,
                "redirect_uris": ["https://personal.example.com/callback"],
                "audiences": ["personal-api"],
                "scopes": ["openid", "profile"],
                "require_org_membership": False,
            },
        )
        assert created.status_code == 200
        params = {
            "response_type": "code",
            "client_id": created.json()["client_id"],
            "redirect_uri": "https://personal.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
            "scope": "openid profile",
            "audience": "personal-api",
        }

        context = await ac.get(
            "/api/v1/oauth/authorize/context",
            headers={"Authorization": f"Bearer {access}"},
            params=params,
        )
        assert context.status_code == 200
        assert context.json()["selected_org_id"] is None

        approved = await approve_consent(ac, {"Authorization": f"Bearer {access}"}, params)
        code = parse_qs(urlparse(approved).query)["code"][0]

        token = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": created.json()["client_id"],
                "redirect_uri": "https://personal.example.com/callback",
                "code": code,
                "code_verifier": "abc",
            },
        )
        assert token.status_code == 200
        claims = decode_access_token(token.json()["access_token"], audience="personal-api")
        assert claims["org_id"] is None
        assert "org_role" not in claims
        assert claims["roles"] == []
        assert "permissions" not in claims


@pytest.mark.asyncio
async def test_user_access_tokens_carry_role_claims_and_service_tokens_do_not():
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_claims = decode_access_token(owner.json()["access_token"])
        assert owner_claims["roles"] == ["owner"]
        assert owner_claims["org_role"] == "owner"

        await register(ac, json={"email": "viewer@example.com", "password": password})
        viewer = await ac.post(
            "/api/v1/auth/login",
            json={"email": "viewer@example.com", "password": password, "client_id": "gatekeeper-cli"},
        )
        viewer_claims = decode_access_token(viewer.json()["access_token"], audience="gatekeeper-api")
        assert viewer_claims["roles"] == ["viewer"]
        assert viewer_claims["org_role"] == "viewer"
        refreshed = await ac.post("/api/v1/auth/refresh", json={"refresh_token": viewer.json()["refresh_token"]})
        assert decode_access_token(refreshed.json()["access_token"])["roles"] == ["viewer"]
        introspected = await ac.post("/oauth/introspect", data={"token": refreshed.json()["access_token"]})
        assert introspected.json()["roles"] == ["viewer"]

        service_client = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {owner.json()['access_token']}"},
            json={"name": "Worker", "public": False, "audiences": ["worker-api"], "scopes": ["auth:read"]},
        )
        service = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": service_client.json()["client_id"],
                "client_secret": service_client.json()["client_secret"],
            },
        )
        assert service.status_code == 200
        service_claims = decode_access_token(service.json()["access_token"], audience="worker-api")
        assert service_claims["token_type"] == "service"
        assert "roles" not in service_claims
        assert "org_role" not in service_claims


@pytest.mark.asyncio
async def test_gatekeeper_api_accepts_only_its_own_token_audiences():
    password = "correct horse battery"

    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_token = owner.json()["access_token"]
        assert decode_access_token(owner_token)["aud"] == settings.issuer
        assert (await ac.get("/api/v1/auth/me", headers=bearer(owner_token))).status_code == 200

        sentinel = await ac.post(
            "/api/v1/clients",
            headers=bearer(owner_token),
            json={
                "name": "Sentinel",
                "public": False,
                "redirect_uris": ["https://sentinel.example.com/callback"],
                "audiences": ["sentinel-api"],
                "scopes": ["auth:read"],
            },
        )
        assert sentinel.status_code == 200
        sentinel_client_id = sentinel.json()["client_id"]
        login = {"email": "owner@example.com", "password": password, "client_id": sentinel_client_id}
        product = await ac.post("/api/v1/auth/login", json=login)
        assert decode_access_token(product.json()["access_token"], audience="sentinel-api")
        assert (await ac.get("/api/v1/auth/me", headers=bearer(product.json()["access_token"]))).status_code == 401

        hosted_ui = await ac.post("/api/v1/auth/login", json={**login, "audience": settings.issuer})
        assert hosted_ui.status_code == 200
        assert decode_access_token(hosted_ui.json()["access_token"])["aud"] == settings.issuer
        assert (await ac.get("/api/v1/auth/me", headers=bearer(hosted_ui.json()["access_token"]))).status_code == 200

        service = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": sentinel_client_id,
                "client_secret": sentinel.json()["client_secret"],
            },
        )
        assert (await ac.get("/api/v1/orgs", headers=bearer(service.json()["access_token"]))).status_code == 401

        device = await ac.post("/oauth/device_authorization", json={"client_id": "gatekeeper-cli"})
        approved = await ac.post(
            "/api/v1/auth/device/approve",
            headers=bearer(owner_token),
            json={"user_code": device.json()["user_code"], "approve": True},
        )
        assert approved.status_code == 200
        cli = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device.json()["device_code"],
                "client_id": "gatekeeper-cli",
            },
        )
        assert decode_access_token(cli.json()["access_token"])["aud"] == ["gatekeeper-api"]
        assert (await ac.get("/api/v1/auth/me", headers=bearer(cli.json()["access_token"]))).status_code == 200

        for audiences, expected in (([], 200), (["gatekeeper-api"], 200), (["sentinel-api"], 401)):
            api_token = await ac.post(
                "/api/v1/tokens",
                headers=bearer(owner_token),
                json={"name": "bound token", "token_type": "personal", "audiences": audiences},
            )
            assert (await ac.get("/api/v1/auth/me", headers=bearer(api_token.json()["token"]))).status_code == expected


@pytest.mark.asyncio
async def test_introspection_validates_jwts_and_rejects_invalid_tokens():
    async with await client() as ac:
        signup = await register(
            ac,
            json={
                "email": "admin@example.com",
                "password": "correct horse battery",
                "display_name": "Admin User",
            },
        )
        access = signup.json()["access_token"]

        jwt_introspection = await ac.post("/oauth/introspect", data={"token": access})
        assert jwt_introspection.status_code == 200
        jwt_payload = jwt_introspection.json()
        assert jwt_payload["active"] is True
        assert jwt_payload["token_type"] == "user"
        assert jwt_payload["sub"] == signup.json()["user"]["id"]
        assert jwt_payload["email"] == "admin@example.com"
        assert jwt_payload["display_name"] == "Admin User"
        assert jwt_payload["email_verified"] is False
        assert jwt_payload["org_role"] == "owner"
        assert "*" in jwt_payload["permissions"]

        invalid = await ac.post("/oauth/introspect", data={"token": "not-a-token"})
        assert invalid.status_code == 200
        assert invalid.json()["active"] is False


@pytest.mark.asyncio
async def test_introspection_honors_disabled_clients_for_opaque_and_service_jwts():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        owner_access = signup.json()["access_token"]
        org_id = signup.json()["orgs"][0]["id"]

        created_client = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "name": "Revocable service",
                "public": False,
                "audiences": ["revocable-api"],
                "scopes": ["auth:read"],
            },
        )
        assert created_client.status_code == 200
        client_payload = created_client.json()

        service_jwt = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_payload["client_id"],
                "client_secret": client_payload["client_secret"],
                "audience": "revocable-api",
                "scope": "auth:read",
            },
        )
        assert service_jwt.status_code == 200

        opaque_token = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "name": "Revocable service token",
                "token_type": "service",
                "org_id": org_id,
                "client_id": client_payload["id"],
                "scopes": ["auth:read"],
                "audiences": ["revocable-api"],
            },
        )
        assert opaque_token.status_code == 200

        active_opaque = await ac.post("/oauth/introspect", data={"token": opaque_token.json()["token"]})
        assert active_opaque.status_code == 200
        assert active_opaque.json()["active"] is True
        assert active_opaque.json()["reason"] is None
        assert active_opaque.json()["client_id"] == client_payload["id"]

        active_jwt = await ac.post("/oauth/introspect", data={"token": service_jwt.json()["access_token"]})
        assert active_jwt.status_code == 200
        assert active_jwt.json()["active"] is True
        assert active_jwt.json()["reason"] is None
        assert active_jwt.json()["client_id"] == client_payload["client_id"]

        disabled_client = await ac.patch(
            f"/api/v1/clients/{client_payload['id']}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"enabled": False},
        )
        assert disabled_client.status_code == 200
        assert disabled_client.json()["enabled"] is False

        inactive_opaque = await ac.post("/oauth/introspect", data={"token": opaque_token.json()["token"]})
        assert inactive_opaque.status_code == 200
        assert inactive_opaque.json()["active"] is False
        assert inactive_opaque.json()["reason"] == "client_disabled"

        inactive_jwt = await ac.post("/oauth/introspect", data={"token": service_jwt.json()["access_token"]})
        assert inactive_jwt.status_code == 200
        assert inactive_jwt.json()["active"] is False
        assert inactive_jwt.json()["reason"] == "client_disabled"


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
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        access = signup.json()["access_token"]
        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Example service",
                "public": False,
                "audiences": ["example-service-api"],
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
                "audience": "other-api",
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
                "audience": "example-service-api",
                "scope": "deploy:read",
            },
        )
        assert token.status_code == 200
        assert token.json()["token_type"] == "Bearer"


@pytest.mark.asyncio
async def test_device_flow_and_api_token_revocation():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "admin@example.com", "password": "correct horse battery"},
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


@pytest.mark.asyncio
async def test_device_grant_accepts_only_one_concurrent_decision():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "device-race@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        headers = {"Authorization": f"Bearer {signup.json()['access_token']}"}
        device = await ac.post(
            "/oauth/device_authorization",
            json={"client_id": "gatekeeper-cli", "scope": "auth:read", "audience": "gatekeeper-api"},
        )
        assert device.status_code == 200
        user_code = device.json()["user_code"]

        approved, denied = await asyncio.gather(
            ac.post(
                "/api/v1/auth/device/approve",
                headers=headers,
                json={"user_code": user_code, "approve": True},
            ),
            ac.post(
                "/api/v1/auth/device/approve",
                headers=headers,
                json={"user_code": user_code, "approve": False},
            ),
        )
        assert sorted([approved.status_code, denied.status_code]) == [200, 404]


@pytest.mark.asyncio
async def test_device_approval_rate_limit_counts_invalid_user_codes():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "device-limited@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        headers = {"Authorization": f"Bearer {signup.json()['access_token']}"}

        for _attempt in range(20):
            missing = await ac.post(
                "/api/v1/auth/device/approve",
                headers=headers,
                json={"user_code": "INVALID1", "approve": True},
            )
            assert missing.status_code == 404

        limited = await ac.post(
            "/api/v1/auth/device/approve",
            headers=headers,
            json={"user_code": "INVALID1", "approve": True},
        )
        assert limited.status_code == 429
        assert limited.json()["detail"] == "Rate limit exceeded"


@pytest.mark.asyncio
async def test_user_jwt_is_session_bound_and_revocation_updates_introspection():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]
        claims = decode_access_token(access)
        assert claims["session_id"]
        assert claims["org_role"] == "owner"
        assert "*" in claims["permissions"]

        introspected = await ac.post("/oauth/introspect", data={"token": access})
        assert introspected.status_code == 200
        assert introspected.json()["active"] is True
        assert introspected.json()["session_id"] == claims["session_id"]

        revoked = await ac.delete(
            f"/api/v1/sessions/{claims['session_id']}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert revoked.status_code == 200

        introspected_again = await ac.post("/oauth/introspect", data={"token": access})
        assert introspected_again.status_code == 200
        assert introspected_again.json()["active"] is False
        assert introspected_again.json()["reason"] == "session_revoked"

        me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"})
        assert me.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_current_session_token():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert signup.status_code == 200
        access = signup.json()["access_token"]

        logout = await ac.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {access}"})
        assert logout.status_code == 200
        assert logout.json()["session_revoked"] is True

        introspected = await ac.post("/oauth/introspect", data={"token": access})
        assert introspected.status_code == 200
        assert introspected.json()["active"] is False
        assert introspected.json()["reason"] == "session_revoked"


@pytest.mark.asyncio
async def test_personal_api_tokens_are_self_service_and_scoped_to_account():
    async with await client() as ac:
        owner = await register(
            ac,
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "display_name": "Owner User",
            },
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        viewer = await register(
            ac,
            json={"email": "viewer@example.com", "password": "correct horse battery"},
        )
        assert viewer.status_code == 200
        viewer_payload = viewer.json()
        viewer_access = viewer_payload["access_token"]
        viewer_id = viewer_payload["user"]["id"]

        owner_service = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "name": "owner service token",
                "token_type": "service",
                "org_id": org_id,
                "scopes": ["auth:read"],
                "audiences": ["service-api"],
            },
        )
        assert owner_service.status_code == 200

        viewer_cannot_create_service = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {viewer_access}"},
            json={
                "name": "viewer service token",
                "token_type": "service",
                "org_id": org_id,
                "scopes": ["auth:read"],
                "audiences": ["service-api"],
            },
        )
        assert viewer_cannot_create_service.status_code == 403

        viewer_cannot_escalate_scope = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {viewer_access}"},
            json={
                "name": "viewer admin-ish token",
                "token_type": "personal",
                "org_id": org_id,
                "scopes": ["admin:*"],
                "audiences": ["gatekeeper-api"],
            },
        )
        assert viewer_cannot_escalate_scope.status_code == 403

        viewer_personal = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {viewer_access}"},
            json={
                "name": "viewer personal token",
                "token_type": "personal",
                "org_id": org_id,
                "scopes": ["auth:read"],
                "audiences": ["gatekeeper-api"],
            },
        )
        assert viewer_personal.status_code == 200
        viewer_token = viewer_personal.json()
        assert viewer_token["user_id"] == viewer_id
        assert viewer_token["org_id"] == org_id
        assert viewer_token["token_type"] == "personal"

        viewer_tokens = await ac.get("/api/v1/tokens", headers={"Authorization": f"Bearer {viewer_access}"})
        assert viewer_tokens.status_code == 200
        assert [token["id"] for token in viewer_tokens.json()] == [viewer_token["id"]]

        viewer_cannot_revoke_owner_service = await ac.delete(
            f"/api/v1/tokens/{owner_service.json()['id']}",
            headers={"Authorization": f"Bearer {viewer_access}"},
        )
        assert viewer_cannot_revoke_owner_service.status_code == 403

        raw_viewer_token = viewer_token["token"]
        active_viewer_token = await ac.post("/oauth/introspect", data={"token": raw_viewer_token})
        assert active_viewer_token.json()["active"] is True
        assert active_viewer_token.json()["sub"] == viewer_id

        rotated = await ac.post(
            f"/api/v1/tokens/{viewer_token['id']}/rotate",
            headers={"Authorization": f"Bearer {viewer_access}"},
        )
        assert rotated.status_code == 200
        assert rotated.json()["user_id"] == viewer_id
        assert (await ac.post("/oauth/introspect", data={"token": raw_viewer_token})).json()["active"] is False
        assert (await ac.post("/oauth/introspect", data={"token": rotated.json()["token"]})).json()["active"] is True

        owner_tokens = await ac.get("/api/v1/tokens", headers={"Authorization": f"Bearer {owner_access}"})
        assert owner_tokens.status_code == 200
        owner_token_ids = {token["id"] for token in owner_tokens.json()}
        assert {owner_service.json()["id"], viewer_token["id"], rotated.json()["id"]}.issubset(owner_token_ids)


@pytest.mark.asyncio
async def test_token_scopes_are_capped_to_role_permissions_on_every_issuance_path():
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        assert owner.status_code == 200
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        org_id = owner.json()["orgs"][0]["id"]
        viewer = await register(ac, json={"email": "viewer@example.com", "password": password})
        assert viewer.status_code == 200
        viewer_id = viewer.json()["user"]["id"]

        for scope in (None, "auth:read token:* mcp:*", "token:*"):
            payload = {"email": "viewer@example.com", "password": password, "client_id": "gatekeeper-cli"}
            if scope:
                payload["scope"] = scope
            login = await ac.post("/api/v1/auth/login", json=payload)
            assert login.status_code == 200
            assert login.json()["scope"] == "auth:read"
            claims = decode_access_token(login.json()["access_token"], audience="gatekeeper-api")
            assert claims["scope"] == "auth:read"
        viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        refreshed = await ac.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": login.json()["refresh_token"]},
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["scope"] == "auth:read"
        assert decode_access_token(refreshed.json()["access_token"])["scope"] == "auth:read"

        for token_type in ("personal", "service", "admin"):
            for scopes in (["admin:*"], ["token:*"], ["*"], ["admin:*", "auth:read", "token:*", "mcp:*"]):
                denied = await ac.post(
                    "/api/v1/tokens",
                    headers=viewer_headers,
                    json={"name": "escalation", "token_type": token_type, "org_id": org_id, "scopes": scopes},
                )
                assert denied.status_code == 403

        roles = await ac.get(f"/api/v1/roles?org_id={org_id}", headers=owner_headers)
        operator_role = next(role for role in roles.json() if role["name"] == "operator")
        promoted = await ac.put(
            f"/api/v1/users/{viewer_id}/membership",
            headers=owner_headers,
            json={"org_id": org_id, "role_id": operator_role["id"], "status": "active"},
        )
        assert promoted.status_code == 200
        operator_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "viewer@example.com", "password": password, "client_id": "gatekeeper-cli"},
        )
        assert operator_login.status_code == 200
        assert set(operator_login.json()["scope"].split()) == {"auth:read", "token:*", "mcp:*"}
        operator_headers = {"Authorization": f"Bearer {operator_login.json()['access_token']}"}

        for scopes in (["admin:*"], ["*"]):
            denied = await ac.post(
                "/api/v1/tokens",
                headers=operator_headers,
                json={"name": "operator escalation", "token_type": "service", "org_id": org_id, "scopes": scopes},
            )
            assert denied.status_code == 403
        allowed = await ac.post(
            "/api/v1/tokens",
            headers=operator_headers,
            json={"name": "operator mcp", "token_type": "service", "org_id": org_id, "scopes": ["mcp:tools"]},
        )
        assert allowed.status_code == 200

        owner_admin_token = await ac.post(
            "/api/v1/tokens",
            headers=owner_headers,
            json={"name": "owner admin", "token_type": "admin", "org_id": org_id, "scopes": ["*"]},
        )
        assert owner_admin_token.status_code == 200
        operator_rotate = await ac.post(
            f"/api/v1/tokens/{owner_admin_token.json()['id']}/rotate",
            headers=operator_headers,
        )
        assert operator_rotate.status_code == 403


@pytest.mark.asyncio
async def test_token_administration_stays_in_the_callers_org(monkeypatch):
    password = "correct horse battery"

    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_token = owner.json()["access_token"]
        bootstrap_id = owner.json()["orgs"][0]["id"]
        target = await ac.post(
            "/api/v1/tokens",
            headers=bearer(owner_token),
            json={"name": "bootstrap service", "token_type": "service", "scopes": ["auth:read"]},
        )
        second = await ac.post("/api/v1/orgs", headers=bearer(owner_token), json={"name": "Second", "slug": "second"})
        switched = await ac.post(
            "/api/v1/auth/session/switch-org", headers=bearer(owner_token), json={"org_id": second.json()["id"]}
        )
        tenant_service = await ac.post(
            "/api/v1/tokens",
            headers=bearer(switched.json()["access_token"]),
            json={"name": "second automation", "token_type": "service", "scopes": ["token:*", "auth:read"]},
        )
        async with async_session_factory() as db:
            _orgless, orgless_raw = await services.create_api_token(
                db,
                name="legacy automation",
                token_type_value="service",
                org_id=None,
                user_id=None,
                project_id=None,
                client_id=None,
                scopes=["token:*", "auth:read"],
                audiences=[],
                expires_at=None,
            )
            await db.commit()

        for raw in (orgless_raw, tenant_service.json()["token"]):
            headers = bearer(raw)
            assert (await ac.get("/api/v1/tokens", headers=headers, params={"org_id": bootstrap_id})).status_code == 403
            created = await ac.post(
                "/api/v1/tokens",
                headers=headers,
                json={"name": "cross org", "token_type": "service", "org_id": bootstrap_id, "scopes": ["auth:read"]},
            )
            assert created.status_code == 403
            assert (await ac.post(f"/api/v1/tokens/{target.json()['id']}/rotate", headers=headers)).status_code == 403
            assert (await ac.delete(f"/api/v1/tokens/{target.json()['id']}", headers=headers)).status_code == 403
        assert (await ac.get("/api/v1/tokens", headers=bearer(orgless_raw))).status_code == 403

        own_org = await ac.get("/api/v1/tokens", headers=bearer(tenant_service.json()["token"]))
        assert own_org.status_code == 200
        platform_revoke = await ac.delete(f"/api/v1/tokens/{tenant_service.json()['id']}", headers=bearer(owner_token))
        assert platform_revoke.status_code == 200


@pytest.mark.asyncio
async def test_operator_command_revokes_tokens_that_exceed_the_owners_role():
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        viewer = await register(ac, json={"email": "viewer@example.com", "password": password})
        org_id = owner.json()["orgs"][0]["id"]

        async def mint(user_id: str | None, token_type: str, scopes: list[str]):
            async with async_session_factory() as db:
                token, raw = await services.create_api_token(
                    db,
                    name=f"{token_type} token",
                    token_type_value=token_type,
                    org_id=org_id,
                    user_id=user_id,
                    project_id=None,
                    client_id=None,
                    scopes=scopes,
                    audiences=[],
                    expires_at=None,
                )
                await db.commit()
                return token.id, raw

        escalated_id, escalated_raw = await mint(viewer.json()["user"]["id"], "personal", ["admin:*", "auth:read"])
        await mint(viewer.json()["user"]["id"], "personal", ["auth:read"])
        await mint(owner.json()["user"]["id"], "admin", ["*"])
        unowned_id, _unowned_raw = await mint(None, "service", ["*"])

        listed = await ops.overscoped_tokens()
        assert {(item["id"], item["action"]) for item in listed} == {(escalated_id, "revoke"), (unowned_id, "review")}
        assert next(item for item in listed if item["id"] == escalated_id)["excess"] == ["admin:*"]
        me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {escalated_raw}"})
        assert me.status_code == 200

        await ops.overscoped_tokens(revoke=True)
        me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {escalated_raw}"})
        assert me.status_code == 401
        assert [item["id"] for item in await ops.overscoped_tokens()] == [unowned_id]


@pytest.mark.asyncio
async def test_api_token_validation_returns_product_metadata_and_policy_checks():
    async with await client() as ac:
        owner = await register(
            ac,
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "display_name": "Owner User",
            },
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        owner_id = owner.json()["user"]["id"]
        org_id = owner.json()["orgs"][0]["id"]

        project = await ac.post(
            "/api/v1/projects",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "org_id": org_id,
                "name": "Stables API",
                "slug": "stables-api",
                "audience": "stables-api",
            },
        )
        assert project.status_code == 200

        created = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "name": "Stables project key",
                "token_type": "project",
                "org_id": org_id,
                "project_id": project.json()["id"],
                "scopes": ["payments:*"],
                "audiences": ["stables-api"],
            },
        )
        assert created.status_code == 200
        raw_token = created.json()["token"]

        validated = await ac.post(
            "/api/v1/tokens/validate",
            json={
                "token": raw_token,
                "audience": "stables-api",
                "required_scopes": ["payments:read"],
                "org_id": org_id,
                "project_id": project.json()["id"],
            },
        )
        assert validated.status_code == 200
        payload = validated.json()
        assert payload["active"] is True
        assert payload["reason"] is None
        assert payload["token_id"] == created.json()["id"]
        assert payload["token_type"] == "project"
        assert payload["org_id"] == org_id
        assert payload["org_slug"] == "example"
        assert payload["project_id"] == project.json()["id"]
        assert payload["project_audience"] == "stables-api"
        assert payload["scopes"] == ["payments:*"]
        assert payload["audiences"] == ["stables-api"]
        assert payload["missing_scopes"] == []
        assert payload["last_used_at"] is not None

        missing_scope = await ac.post(
            "/api/v1/tokens/validate",
            json={"token": raw_token, "audience": "stables-api", "required_scopes": ["admin:read"]},
        )
        assert missing_scope.status_code == 200
        assert missing_scope.json()["active"] is False
        assert missing_scope.json()["reason"] == "scope_mismatch"
        assert missing_scope.json()["missing_scopes"] == ["admin:read"]

        wrong_audience = await ac.post(
            "/api/v1/tokens/validate",
            json={"token": raw_token, "audience": "other-api", "required_scopes": ["payments:read"]},
        )
        assert wrong_audience.status_code == 200
        assert wrong_audience.json()["active"] is False
        assert wrong_audience.json()["reason"] == "audience_mismatch"
        assert wrong_audience.json()["audience_ok"] is False

        personal = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={
                "name": "Owner personal key",
                "token_type": "personal",
                "org_id": org_id,
                "scopes": ["auth:read"],
                "audiences": ["gatekeeper-api"],
            },
        )
        assert personal.status_code == 200
        personal_validation = await ac.post(
            "/api/v1/tokens/validate",
            json={"token": personal.json()["token"], "audience": "gatekeeper-api"},
        )
        assert personal_validation.status_code == 200
        personal_payload = personal_validation.json()
        assert personal_payload["active"] is True
        assert personal_payload["user_id"] == owner_id
        assert personal_payload["user_email"] == "owner@example.com"
        assert personal_payload["user_display_name"] == "Owner User"

        unsupported = await ac.post("/api/v1/tokens/validate", json={"token": "not-a-gatekeeper-token"})
        assert unsupported.status_code == 200
        assert unsupported.json() == {
            "active": False,
            "reason": "unsupported_token",
            "token_id": None,
            "token_type": None,
            "token_hint": None,
            "org_id": None,
            "org_name": None,
            "org_slug": None,
            "user_id": None,
            "user_email": None,
            "user_display_name": None,
            "project_id": None,
            "project_name": None,
            "project_audience": None,
            "auth_client_id": None,
            "scopes": [],
            "audiences": [],
            "missing_scopes": [],
            "audience_ok": True,
            "scope_ok": True,
            "expires_at": None,
            "last_used_at": None,
        }

        revoked = await ac.delete(
            f"/api/v1/tokens/{created.json()['id']}",
            headers={"Authorization": f"Bearer {owner_access}"},
        )
        assert revoked.status_code == 200
        after_revoke = await ac.post("/api/v1/tokens/validate", json={"token": raw_token})
        assert after_revoke.status_code == 200
        assert after_revoke.json()["active"] is False
        assert after_revoke.json()["reason"] == "revoked"


@pytest.mark.asyncio
async def test_client_token_management_and_audit_filters():
    async with await client() as ac:
        signup = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        access = signup.json()["access_token"]

        invalid_origin = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Invalid",
                "public": True,
                "redirect_uris": ["https://app.example/callback"],
                "allowed_origins": ["https://app.example/callback"],
                "audiences": ["app-api"],
                "scopes": ["auth:read"],
            },
        )
        assert invalid_origin.status_code == 422

        client_response = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "Service app",
                "public": False,
                "redirect_uris": ["https://service.example/oauth/callback"],
                "allowed_origins": ["https://service.example"],
                "audiences": ["service-api"],
                "scopes": ["auth:read", "token:*"],
            },
        )
        assert client_response.status_code == 200
        created_client = client_response.json()
        assert created_client["client_secret"].startswith("gkcs_")

        rotated_secret = await ac.post(
            f"/api/v1/clients/{created_client['id']}/rotate-secret",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert rotated_secret.status_code == 200
        assert rotated_secret.json()["client_secret"].startswith("gkcs_")
        assert rotated_secret.json()["client_secret"] != created_client["client_secret"]

        disabled = await ac.patch(
            f"/api/v1/clients/{created_client['id']}",
            headers={"Authorization": f"Bearer {access}"},
            json={"enabled": False},
        )
        assert disabled.status_code == 200
        assert disabled.json()["enabled"] is False

        enabled = await ac.patch(
            f"/api/v1/clients/{created_client['id']}",
            headers={"Authorization": f"Bearer {access}"},
            json={"enabled": True},
        )
        assert enabled.status_code == 200
        assert enabled.json()["enabled"] is True

        workspace = await ac.post(
            "/api/v1/workspaces",
            headers={"Authorization": f"Bearer {access}"},
            json={"org_id": signup.json()["orgs"][0]["id"], "name": "Default", "slug": "default"},
        )
        assert workspace.status_code == 200
        project = await ac.post(
            "/api/v1/projects",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "org_id": signup.json()["orgs"][0]["id"],
                "workspace_id": workspace.json()["id"],
                "name": "Service",
                "slug": "service",
                "audience": "service-api",
            },
        )
        assert project.status_code == 200
        assert (await ac.get("/api/v1/workspaces", headers={"Authorization": f"Bearer {access}"})).status_code == 200
        assert (await ac.get("/api/v1/projects", headers={"Authorization": f"Bearer {access}"})).status_code == 200
        assert (await ac.get("/api/v1/roles", headers={"Authorization": f"Bearer {access}"})).status_code == 200

        token_response = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {access}"},
            json={
                "name": "service token",
                "token_type": "service",
                "client_id": created_client["id"],
                "scopes": ["auth:read"],
                "audiences": ["service-api"],
            },
        )
        assert token_response.status_code == 200
        raw_token = token_response.json()["token"]

        delete_with_artifacts = await ac.delete(
            f"/api/v1/clients/{created_client['id']}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert delete_with_artifacts.status_code == 409

        rotated_token = await ac.post(
            f"/api/v1/tokens/{token_response.json()['id']}/rotate",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert rotated_token.status_code == 200
        new_raw_token = rotated_token.json()["token"]
        assert new_raw_token != raw_token
        assert (await ac.post("/oauth/introspect", data={"token": raw_token})).json()["active"] is False
        assert (await ac.post("/oauth/introspect", data={"token": new_raw_token})).json()["active"] is True

        rotate_events = await ac.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {access}"},
            params={"action": "token.rotate"},
        )
        assert rotate_events.status_code == 200
        assert len(rotate_events.json()) == 1


@pytest.mark.asyncio
async def test_admin_user_lifecycle_role_assignment_and_session_revocation():
    async with await client() as ac:
        owner = await register(
            ac,
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert owner.status_code == 200
        owner_payload = owner.json()
        owner_access = owner_payload["access_token"]
        owner_id = owner_payload["user"]["id"]
        org_id = owner_payload["orgs"][0]["id"]

        viewer = await register(
            ac,
            json={"email": "viewer@example.com", "password": "correct horse battery"},
        )
        assert viewer.status_code == 200
        viewer_payload = viewer.json()
        viewer_access = viewer_payload["access_token"]
        viewer_refresh = viewer_payload["refresh_token"]
        viewer_id = viewer_payload["user"]["id"]

        viewer_forbidden = await ac.get("/api/v1/users", headers={"Authorization": f"Bearer {viewer_access}"})
        assert viewer_forbidden.status_code == 403

        users = await ac.get("/api/v1/users", headers={"Authorization": f"Bearer {owner_access}"})
        assert users.status_code == 200
        assert {user["email"] for user in users.json()} == {"owner@example.com", "viewer@example.com"}
        viewer_row = next(user for user in users.json() if user["email"] == "viewer@example.com")
        assert viewer_row["disabled"] is False
        assert viewer_row["memberships"][0]["role"] == "viewer"

        last_owner_disable = await ac.patch(
            f"/api/v1/users/{owner_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"disabled": True},
        )
        assert last_owner_disable.status_code == 400

        promoted = await ac.put(
            f"/api/v1/users/{viewer_id}/membership",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"org_id": org_id, "role": "owner", "status": "active"},
        )
        assert promoted.status_code == 200
        assert promoted.json()["memberships"][0]["role"] == "owner"

        stale_viewer_me = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {viewer_access}"})
        assert stale_viewer_me.status_code == 401
        stale_viewer_refresh = await ac.post("/api/v1/auth/refresh", json={"refresh_token": viewer_refresh})
        assert stale_viewer_refresh.status_code == 401

        viewer_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "viewer@example.com", "password": "correct horse battery"},
        )
        assert viewer_login.status_code == 200
        viewer_owner_access = viewer_login.json()["access_token"]
        assert decode_access_token(viewer_owner_access)["org_role"] == "owner"

        disabled = await ac.patch(
            f"/api/v1/users/{viewer_id}",
            headers={"Authorization": f"Bearer {owner_access}"},
            json={"disabled": True, "email_verified": True, "display_name": "Suspended Viewer"},
        )
        assert disabled.status_code == 200
        assert disabled.json()["disabled"] is True
        assert disabled.json()["email_verified"] is True
        assert disabled.json()["display_name"] == "Suspended Viewer"

        disabled_access = await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {viewer_owner_access}"})
        assert disabled_access.status_code == 401
        disabled_login = await ac.post(
            "/api/v1/auth/login",
            json={"email": "viewer@example.com", "password": "correct horse battery"},
        )
        assert disabled_login.status_code == 401

        revoked = await ac.post(
            f"/api/v1/users/{viewer_id}/sessions/revoke",
            headers={"Authorization": f"Bearer {owner_access}"},
        )
        assert revoked.status_code == 200
        assert revoked.json()["status"] == "revoked"


@pytest.mark.asyncio
async def test_security_alert_is_sent_through_sendy_in_the_background(monkeypatch):
    sent: list[httpx.Request] = []

    def accept(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(202, json={"data": {"id": "email-1"}})

    monkeypatch.setattr(alerts, "_transport", httpx.MockTransport(accept))
    for key, recipient in (("", "ops@example.com"), ("test-sendy-key", "")):
        monkeypatch.setattr(settings, "sendy_api_key", key)
        monkeypatch.setattr(settings, "alert_email_to", recipient)
        alerts.send_security_alert("Skipped", ["Action: none"], "gatekeeper-skip")
        assert not alerts._pending

    monkeypatch.setattr(settings, "alert_email_to", "ops@example.com")
    alerts.send_security_alert("Role set\r\nto owner", ["Action: user.membership.update"], "gatekeeper-audit-1")
    assert alerts._pending
    await asyncio.gather(*alerts._pending)

    assert len(sent) == 1
    request = sent[0]
    assert request.method == "POST"
    assert str(request.url) == "https://usesendy.com/api/v1/emails"
    assert request.headers["authorization"] == "Bearer test-sendy-key"
    assert request.headers["content-type"] == "application/vnd.api+json"
    assert request.headers["accept"] == "application/vnd.api+json"
    assert request.headers["idempotency-key"] == "gatekeeper-audit-1"
    assert json.loads(request.content) == {
        "data": {
            "type": "emails",
            "attributes": {
                "from": settings.alert_email_from,
                "to": "ops@example.com",
                "subject": "[GateKeeper] Role set to owner",
                "text": "Action: user.membership.update",
            },
        }
    }

    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sendy unreachable")

    monkeypatch.setattr(alerts, "_transport", httpx.MockTransport(fail))
    alerts.send_security_alert("Unreachable", ["Action: none"], "gatekeeper-audit-2")
    await asyncio.gather(*alerts._pending)


@pytest.mark.asyncio
async def test_security_events_queue_alerts_without_secret_values(monkeypatch):
    sent: list[dict] = []

    def accept(request: httpx.Request) -> httpx.Response:
        sent.append({"key": request.headers["idempotency-key"], **json.loads(request.content)["data"]["attributes"]})
        return httpx.Response(202)

    monkeypatch.setattr(alerts, "_transport", httpx.MockTransport(accept))
    monkeypatch.setattr(settings, "sendy_api_key", "test-sendy-key")
    monkeypatch.setattr(settings, "alert_email_to", "ops@example.com")
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        token = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {owner.json()['access_token']}"},
            json={"name": "automation", "token_type": "personal", "scopes": ["admin:*"]},
        )
        assert token.status_code == 200
        for _attempt in range(2):
            refused = await ac.post("/api/v1/auth/signup", json={"email": "intruder@example.com", "password": password})
            assert refused.status_code == 403
        await asyncio.gather(*alerts._pending)

    by_subject = {item["subject"]: item for item in sent}
    assert {
        "[GateKeeper] User created",
        "[GateKeeper] Privileged login from a new IP",
        "[GateKeeper] API token created",
        "[GateKeeper] Signup refused",
    }.issubset(by_subject)
    token_alert = by_subject["[GateKeeper] API token created"]["text"]
    assert "Actor: owner@example.com" in token_alert
    assert "Client IP: 127.0.0.1" in token_alert
    assert "scopes: admin:*" in token_alert
    assert "Time (UTC): " in token_alert
    refusal_keys = [item["key"] for item in sent if item["subject"] == "[GateKeeper] Signup refused"]
    assert len(refusal_keys) == 1
    for item in sent:
        assert token.json()["token"] not in item["text"]
        assert password not in item["text"]
        assert owner.json()["access_token"] not in item["text"]


@pytest.mark.asyncio
async def test_switch_org_is_limited_to_hosted_sessions_and_never_widens_a_token():
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        owner_token = owner.json()["access_token"]
        second = await ac.post(
            "/api/v1/orgs", headers=bearer(owner_token), json={"name": "Second", "slug": "second"}
        )
        assert second.status_code == 200

        device = await ac.post(
            "/oauth/device_authorization", json={"client_id": "gatekeeper-cli", "scope": "auth:read"}
        )
        approved = await ac.post(
            "/api/v1/auth/device/approve",
            headers=bearer(owner_token),
            json={"user_code": device.json()["user_code"], "approve": True},
        )
        assert approved.status_code == 200
        cli = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device.json()["device_code"],
                "client_id": "gatekeeper-cli",
            },
        )
        assert cli.json()["scope"] == "auth:read"
        widened = await ac.post(
            "/api/v1/auth/session/switch-org",
            headers=bearer(cli.json()["access_token"]),
            json={"org_id": second.json()["id"]},
        )
        assert widened.status_code == 403
        assert widened.json()["detail"] == "Organization switching is limited to hosted sessions"

        for extra in ({"client_id": "gatekeeper-cli"}, {"audience": "gatekeeper-api"}, {"scope": "auth:read"}):
            changed = await ac.post(
                "/api/v1/auth/session/switch-org",
                headers=bearer(owner_token),
                json={"org_id": second.json()["id"], **extra},
            )
            assert changed.status_code == 400

        hosted = await ac.post(
            "/api/v1/auth/session/switch-org", headers=bearer(owner_token), json={"org_id": second.json()["id"]}
        )
        assert hosted.status_code == 200
        claims = decode_access_token(hosted.json()["access_token"])
        assert claims["org_id"] == second.json()["id"]
        assert claims["aud"] == settings.issuer
        assert claims.get("azp") is None
        assert claims["scope"] == "*"


async def bootstrap_owner_and_admin(ac: AsyncClient, password: str = "correct horse battery"):
    """Owner (platform admin) plus an org admin of the bootstrap org who is not a platform admin."""
    owner = await register(ac, json={"email": "owner@example.com", "password": password})
    owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = owner.json()["orgs"][0]["id"]
    admin = await register(ac, json={"email": "admin@corp.example.com", "password": password})
    promoted = await ac.put(
        f"/api/v1/users/{admin.json()['user']['id']}/membership",
        headers=owner_headers,
        json={"org_id": org_id, "role": "admin", "status": "active"},
    )
    assert promoted.status_code == 200
    login = await ac.post("/api/v1/auth/login", json={"email": "admin@corp.example.com", "password": password})
    admin_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    return owner_headers, admin_headers, org_id, admin.json()["user"]["id"]


@pytest.mark.asyncio
async def test_gatekeeper_audiences_including_the_issuer_are_reserved():
    body = {"name": "Product", "public": True, "redirect_uris": ["https://app.example.com/callback"]}
    async with await client() as ac:
        owner_headers, admin_headers, _org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        for audiences in ([settings.issuer], ["gatekeeper-api"]):
            denied = await ac.post("/api/v1/clients", headers=admin_headers, json={**body, "audiences": audiences})
            assert denied.status_code == 403
        for audiences, expected in (([settings.issuer], 200), (["gatekeeper-api"], 200), (["sentinel-api"], 403)):
            token = await ac.post(
                "/api/v1/tokens",
                headers=admin_headers,
                json={"name": "bound", "token_type": "personal", "audiences": audiences},
            )
            assert token.status_code == expected
        owned = await ac.post("/api/v1/clients", headers=admin_headers, json={**body, "audiences": ["my-api"]})
        assert owned.status_code == 200
        retarget = await ac.patch(
            f"/api/v1/clients/{owned.json()['id']}", headers=admin_headers, json={"audiences": [settings.issuer]}
        )
        assert retarget.status_code == 403

        first_party = await ac.post(
            "/api/v1/clients", headers=owner_headers, json={**body, "audiences": [settings.issuer]}
        )
        assert first_party.status_code == 200
        removed = await ac.delete(f"/api/v1/clients/{first_party.json()['id']}", headers=admin_headers)
        assert removed.status_code == 403
        assert (await ac.delete(f"/api/v1/clients/{owned.json()['id']}", headers=admin_headers)).status_code == 200
        owner_token = await ac.post(
            "/api/v1/tokens",
            headers=owner_headers,
            json={"name": "bound", "token_type": "personal", "audiences": ["sentinel-api"]},
        )
        assert owner_token.status_code == 200


async def approve_consent(ac: AsyncClient, headers: dict[str, str], params: dict[str, str]) -> str:
    """Approve the way the hosted consent page does: nonce from the context endpoint, then POST."""
    context = await ac.get("/api/v1/oauth/authorize/context", headers=headers, params=params)
    assert context.status_code == 200
    approved = await ac.post(
        "/oauth/authorize",
        headers=headers,
        json={**params, "approve": True, "consent_nonce": context.json()["consent_nonce"]},
    )
    assert approved.status_code == 200
    return approved.json()["redirect_to"]


@pytest.mark.asyncio
async def test_consent_needs_a_session_bound_nonce_and_post_and_only_platform_admins_verify_clients():
    body = {
        "name": "Product",
        "public": True,
        "redirect_uris": ["https://app.example.com/callback", "https://evil.example.com/callback"],
        "audiences": ["example-api"],
        "scopes": ["openid", "auth:read"],
    }
    async with await client() as ac:
        owner_headers, admin_headers, _org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        verified = await ac.post("/api/v1/clients", headers=admin_headers, json={**body, "verified": True})
        assert verified.status_code == 403
        own = await ac.post("/api/v1/clients", headers=admin_headers, json=body)
        assert own.status_code == 200
        marked = await ac.patch(f"/api/v1/clients/{own.json()['id']}", headers=admin_headers, json={"verified": True})
        assert marked.status_code == 403
        unchanged = await ac.patch(
            f"/api/v1/clients/{own.json()['id']}", headers=admin_headers, json={"verified": False, "name": "Renamed"}
        )
        assert unchanged.status_code == 200

        created = await ac.post("/api/v1/clients", headers=owner_headers, json={**body, "verified": True})
        assert created.status_code == 200
        params = {
            "response_type": "code",
            "client_id": created.json()["client_id"],
            "redirect_uri": "https://app.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
            "scope": "openid auth:read",
            "audience": "example-api",
            "state": "s1",
        }
        forged = await ac.get("/oauth/authorize", headers=owner_headers, params={**params, "approve": "true"})
        assert forged.status_code == 302
        assert urlparse(forged.headers["location"]).path == "/authorize"

        context = await ac.get("/api/v1/oauth/authorize/context", headers=owner_headers, params=params)
        nonce = context.json()["consent_nonce"]
        for submitted in (
            {**params, "approve": True},
            {**params, "approve": True, "consent_nonce": "0" * 64},
            {**params, "approve": True, "consent_nonce": nonce, "code_challenge": "attacker"},
            {**params, "approve": True, "consent_nonce": nonce, "redirect_uri": "https://evil.example.com/callback"},
        ):
            refused = await ac.post("/oauth/authorize", headers=owner_headers, json=submitted)
            assert refused.status_code == 403
        other_session = await ac.post(
            "/api/v1/auth/login", json={"email": "owner@example.com", "password": "correct horse battery"}
        )
        replayed = await ac.post(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {other_session.json()['access_token']}"},
            json={**params, "approve": True, "consent_nonce": nonce},
        )
        assert replayed.status_code == 403

        location = urlparse(await approve_consent(ac, owner_headers, params))
        assert f"{location.scheme}://{location.netloc}{location.path}" == "https://app.example.com/callback"
        assert parse_qs(location.query)["code"][0].startswith("gkc_")


@pytest.mark.asyncio
async def test_org_admins_cannot_hand_out_roles_or_policies_above_their_own():
    async with await client() as ac:
        owner_headers, admin_headers, org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        member = await register(ac, json={"email": "member@example.com", "password": "correct horse battery"})
        member_id = member.json()["user"]["id"]
        owner_id = (await ac.get("/api/v1/auth/me", headers=owner_headers)).json()["user"]["id"]
        superuser = await ac.post(
            "/api/v1/roles", headers=owner_headers, json={"org_id": org_id, "name": "superuser", "permissions": ["*"]}
        )
        assert superuser.status_code == 200

        for role in ({"role": "owner"}, {"role_id": superuser.json()["id"]}, {"role": "operator"}):
            promoted = await ac.put(
                f"/api/v1/users/{member_id}/membership",
                headers=admin_headers,
                json={"org_id": org_id, "status": "active", **role},
            )
            assert promoted.status_code == 403
            invited = await ac.post(
                "/api/v1/invitations",
                headers=admin_headers,
                json={"email": "new@example.com", "org_id": org_id, **role},
            )
            assert invited.status_code == 403
            provisioned = await ac.post(
                "/api/v1/users/provision",
                headers=admin_headers,
                json={"email": "new@example.com", "org_id": org_id, **role},
            )
            assert provisioned.status_code == 403
        demoted = await ac.put(
            f"/api/v1/users/{owner_id}/membership",
            headers=admin_headers,
            json={"org_id": org_id, "role": "viewer", "status": "active"},
        )
        assert demoted.status_code == 403
        peer = await ac.put(
            f"/api/v1/users/{member_id}/membership",
            headers=admin_headers,
            json={"org_id": org_id, "role": "admin", "status": "active"},
        )
        assert peer.status_code == 200

        for name, permissions, expected in (
            ("support", ["*"], 403),
            ("support", ["token:*"], 403),
            ("Owner", ["auth:read"], 400),
            (" ADMIN ", ["auth:read"], 400),
            ("oper-ator", ["auth:read"], 400),
            ("support", ["auth:read"], 200),
        ):
            created = await ac.post(
                "/api/v1/roles",
                headers=admin_headers,
                json={"org_id": org_id, "name": name, "permissions": permissions},
            )
            assert created.status_code == expected

        roles = {role["name"]: role["id"] for role in (await ac.get("/api/v1/roles", headers=owner_headers)).json()}
        renamed_owner = await ac.put(
            f"/scim/v2/Groups/{roles['owner']}", headers=admin_headers, json={"displayName": "former", "members": []}
        )
        assert renamed_owner.status_code == 403
        renamed_admin = await ac.patch(
            f"/scim/v2/Groups/{roles['admin']}",
            headers=admin_headers,
            json={"Operations": [{"op": "replace", "path": "displayName", "value": "Owner"}]},
        )
        assert renamed_admin.status_code == 400
        lookalike = await ac.post("/scim/v2/Groups", headers=admin_headers, json={"displayName": "OWNER"})
        assert lookalike.status_code == 400
        owner_group = await ac.patch(
            f"/scim/v2/Groups/{roles['owner']}",
            headers=admin_headers,
            json={"Operations": [{"op": "add", "path": "members", "value": [{"value": member_id}]}]},
        )
        assert owner_group.status_code == 403
        scim_owner = await ac.patch(
            f"/scim/v2/Users/{member_id}",
            headers=admin_headers,
            json={"Operations": [{"op": "replace", "path": "roles", "value": [{"value": "owner"}]}]},
        )
        assert scim_owner.status_code == 403

        for policy in ({"require_mfa": True}, {"admin_step_up_mfa_required": True}):
            changed = await ac.patch(f"/api/v1/orgs/{org_id}", headers=admin_headers, json=policy)
            assert changed.status_code == 403
        renamed = await ac.patch(f"/api/v1/orgs/{org_id}", headers=admin_headers, json={"name": "Renamed"})
        assert renamed.status_code == 200
        owner_promotes = await ac.put(
            f"/api/v1/users/{member_id}/membership",
            headers=owner_headers,
            json={"org_id": org_id, "role": "owner", "status": "active"},
        )
        assert owner_promotes.status_code == 200

    async with async_session_factory() as db:
        actions = set((await db.execute(select(AuditEvent.action))).scalars())
    assert "role.create" in actions


@pytest.mark.asyncio
async def test_user_api_tokens_follow_the_owners_current_role():
    async with await client() as ac:
        owner_headers, admin_headers, org_id, admin_id = await bootstrap_owner_and_admin(ac)
        created = await ac.post(
            "/api/v1/tokens",
            headers=admin_headers,
            json={
                "name": "automation",
                "token_type": "personal",
                "org_id": org_id,
                "scopes": ["admin:*", "auth:*"],
            },
        )
        assert created.status_code == 200
        raw = created.json()["token"]
        token_headers = {"Authorization": f"Bearer {raw}"}
        validate = {"token": raw, "required_scopes": ["admin:*"]}
        assert (await ac.get("/api/v1/users", headers=token_headers)).status_code == 200
        assert (await ac.post("/api/v1/tokens/validate", json=validate)).json()["scope_ok"] is True

        demoted = await ac.put(
            f"/api/v1/users/{admin_id}/membership",
            headers=owner_headers,
            json={"org_id": org_id, "role": "viewer", "status": "active"},
        )
        assert demoted.status_code == 200
        assert (await ac.get("/api/v1/users", headers=token_headers)).status_code == 403
        checked = (await ac.post("/api/v1/tokens/validate", json=validate)).json()
        assert checked["scope_ok"] is False
        assert checked["scopes"] == []

        removed = await ac.put(
            f"/api/v1/users/{admin_id}/membership",
            headers=owner_headers,
            json={"org_id": org_id, "role": "viewer", "status": "revoked"},
        )
        assert removed.status_code == 200
        assert (await ac.get("/api/v1/auth/me", headers=token_headers)).status_code == 401
        assert (await ac.post("/api/v1/tokens/validate", json=validate)).json()["active"] is False

    async with async_session_factory() as db:
        user = (await db.execute(select(User).where(User.email == "admin@corp.example.com"))).scalar_one()
        token, orgless_raw = await services.create_api_token(
            db,
            name="org-less",
            token_type_value="personal",
            org_id=None,
            user_id=user.id,
            project_id=None,
            client_id=None,
            scopes=["admin:*", "auth:read"],
            audiences=[],
            expires_at=None,
        )
        await db.commit()
    async with await client() as ac:
        orgless = await ac.post("/api/v1/tokens/validate", json={"token": orgless_raw})
        assert orgless.json()["scopes"] == ["auth:read"]


@pytest.mark.asyncio
async def test_scim_and_provisioning_cannot_reenable_or_attach_accounts_from_other_orgs():
    async with await client() as ac:
        owner_headers, admin_headers, org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        other = await ac.post("/api/v1/orgs", headers=owner_headers, json={"name": "Other", "slug": "other"})
        other_id = other.json()["id"]
        async with async_session_factory() as db:
            role_ids = {(role.org_id, role.name): role.id for role in (await db.execute(select(Role))).scalars()}
            users = {}
            for email, org_ids in (
                ("elsewhere@example.com", [other_id]),
                ("both@example.com", [org_id, other_id]),
                ("local@example.com", [org_id]),
            ):
                user = User(email=email, password_hash=None, disabled=True)
                db.add(user)
                await db.flush()
                for member_org in org_ids:
                    db.add(Membership(org_id=member_org, user_id=user.id, role_id=role_ids[(member_org, "viewer")]))
                users[email] = user.id
            await db.commit()
        viewer_group = role_ids[(org_id, "viewer")]

        attach = await ac.post(
            f"/scim/v2/Users?org_id={org_id}",
            headers=admin_headers,
            json={"userName": "elsewhere@example.com", "active": True, "roles": [{"value": "viewer"}]},
        )
        assert attach.status_code == 403
        provision = await ac.post(
            "/api/v1/users/provision", headers=admin_headers, json={"email": "elsewhere@example.com", "org_id": org_id}
        )
        assert provision.status_code == 403
        for member in (users["elsewhere@example.com"], users["both@example.com"]):
            grouped = await ac.patch(
                f"/scim/v2/Groups/{viewer_group}",
                headers=admin_headers,
                json={"Operations": [{"op": "add", "path": "members", "value": [{"value": member}]}]},
            )
            assert grouped.status_code == 403
        reenable = {"Operations": [{"op": "replace", "path": "active", "value": True}]}
        both = await ac.patch(f"/scim/v2/Users/{users['both@example.com']}", headers=admin_headers, json=reenable)
        assert both.status_code == 403
        local = await ac.patch(f"/scim/v2/Users/{users['local@example.com']}", headers=admin_headers, json=reenable)
        assert local.status_code == 200
        assert local.json()["active"] is True

    async with async_session_factory() as db:
        disabled = dict((await db.execute(select(User.email, User.disabled))).all())
        members = set((await db.execute(select(Membership.user_id).where(Membership.org_id == org_id))).scalars())
    assert disabled["elsewhere@example.com"] is True
    assert disabled["both@example.com"] is True
    assert users["elsewhere@example.com"] not in members


@pytest.mark.asyncio
async def test_api_tokens_bind_only_projects_clients_and_audiences_of_their_own_org():
    client_body = {"name": "Other app", "public": True, "redirect_uris": ["https://other.example.com/callback"]}
    async with await client() as ac:
        owner_headers, admin_headers, org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        other = await ac.post("/api/v1/orgs", headers=owner_headers, json={"name": "Other", "slug": "other"})
        other_id = other.json()["id"]
        switched = await ac.post("/api/v1/auth/session/switch-org", headers=owner_headers, json={"org_id": other_id})
        other_headers = {"Authorization": f"Bearer {switched.json()['access_token']}"}
        foreign_project = await ac.post(
            "/api/v1/projects",
            headers=other_headers,
            json={"org_id": other_id, "name": "Theirs", "slug": "theirs", "audience": "their-api"},
        )
        foreign_client = await ac.post(
            "/api/v1/clients", headers=other_headers, json={**client_body, "audiences": ["their-api"]}
        )
        own_project = await ac.post(
            "/api/v1/projects",
            headers=admin_headers,
            json={"org_id": org_id, "name": "Ours", "slug": "ours", "audience": "our-api"},
        )
        own_client = await ac.post(
            "/api/v1/clients", headers=admin_headers, json={**client_body, "audiences": ["our-app-api"]}
        )
        assert {foreign_project.status_code, foreign_client.status_code, own_project.status_code} == {200}
        assert own_client.status_code == 200

        token = {"name": "bound", "token_type": "service", "org_id": org_id, "scopes": ["auth:read"]}
        for binding, expected in (
            ({"project_id": foreign_project.json()["id"]}, 403),
            ({"client_id": foreign_client.json()["id"]}, 403),
            ({"project_id": own_project.json()["id"], "audiences": ["their-api"]}, 400),
            ({"client_id": own_client.json()["id"], "audiences": ["our-api"]}, 400),
            ({"project_id": own_project.json()["id"], "audiences": ["our-api"]}, 200),
            ({"client_id": own_client.json()["id"], "audiences": ["our-app-api"]}, 200),
        ):
            created = await ac.post("/api/v1/tokens", headers=admin_headers, json={**token, **binding})
            assert created.status_code == expected, binding


@pytest.mark.asyncio
async def test_federated_login_never_bypasses_mfa_or_links_by_email(monkeypatch):
    monkeypatch.setattr(settings, "google_client_id", "")
    monkeypatch.setattr(settings, "google_client_secret", "")
    monkeypatch.setattr(
        settings,
        "oauth_providers_json",
        """[{"id":"example","name":"Example","client_id":"c","client_secret":"s",
        "authorization_url":"https://login.example.com/authorize","token_url":"https://login.example.com/token",
        "userinfo_url":"https://login.example.com/userinfo",
        "redirect_uri":"https://auth.example.com/api/v1/auth/oauth/example/callback"}]""",
    )

    async def fake_profile(provider, code):
        return {"sub": "ext-owner", "email": "owner@example.com", "name": "Owner", "email_verified": True}

    monkeypatch.setattr(main_module, "fetch_oauth_provider_profile", fake_profile)

    async def federated_login(ac: AsyncClient):
        ac.cookies.clear()
        started = await ac.get("/api/v1/auth/oauth/example/start", params={"redirect": "/account"})
        return await ac.get(
            "/api/v1/auth/oauth/example/callback", params={"code": "c", "state": started.json()["state"]}
        )

    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        owner_id = owner.json()["user"]["id"]
        assert (await federated_login(ac)).status_code == 403
        async with async_session_factory() as db:
            assert (await db.execute(select(Identity.id))).first() is None
            user = await db.get(User, owner_id)
            user.mfa_totp_enabled_at = services.now_utc()
            db.add(Identity(user_id=owner_id, provider="example", provider_subject="ext-owner", email=user.email))
            await db.commit()
        refused = await federated_login(ac)
        assert refused.status_code == 401
        assert (await ac.get("/api/v1/auth/me")).status_code == 401

        async with async_session_factory() as db:
            user = await db.get(User, owner_id)
            user.mfa_totp_enabled_at = None
            await db.commit()
        assert (await federated_login(ac)).status_code == 302


@pytest.mark.asyncio
async def test_signup_is_rate_limited_per_ip_and_refusal_alerts_are_deduplicated(monkeypatch):
    sent: list[str] = []

    def accept(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content)["data"]["attributes"]["subject"])
        return httpx.Response(202)

    monkeypatch.setattr(alerts, "_transport", httpx.MockTransport(accept))
    monkeypatch.setattr(settings, "sendy_api_key", "test-sendy-key")
    monkeypatch.setattr(settings, "alert_email_to", "ops@example.com")
    async with await client() as ac:
        await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        statuses = []
        for attempt in range(6):
            refused = await ac.post(
                "/api/v1/auth/signup", json={"email": f"intruder{attempt}@example.com", "password": "x" * 12}
            )
            statuses.append(refused.status_code)
        await asyncio.gather(*alerts._pending)
    assert statuses == [403, 403, 403, 403, 429, 429]
    assert sent.count("[GateKeeper] Signup refused") == 1


@pytest.mark.asyncio
async def test_incident_sweep_lists_what_new_accounts_touched_and_revoke_takes_filters():
    client_body = {"name": "Flagged", "public": True, "redirect_uris": ["https://app.example.com/callback"]}
    async with await client() as ac:
        owner_headers, admin_headers, org_id, admin_id = await bootstrap_owner_and_admin(ac)
        owner_id = (await ac.get("/api/v1/auth/me", headers=owner_headers)).json()["user"]["id"]
        evil = await ac.post("/api/v1/orgs", headers=owner_headers, json={"name": "Evil", "slug": "evil"})
        switched = await ac.post(
            "/api/v1/auth/session/switch-org", headers=owner_headers, json={"org_id": evil.json()["id"]}
        )
        await ac.put(
            f"/api/v1/users/{admin_id}/membership",
            headers={"Authorization": f"Bearer {switched.json()['access_token']}"},
            json={"org_id": evil.json()["id"], "role": "owner", "status": "active"},
        )
        admin_login = await ac.post(
            "/api/v1/auth/login", json={"email": "admin@corp.example.com", "password": "correct horse battery"}
        )
        admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}
        flagged = await ac.post(
            "/api/v1/clients",
            headers=owner_headers,
            json={**client_body, "audiences": ["x-api"], "scopes": ["openid", "admin:*"]},
        )
        quiet = await ac.post(
            "/api/v1/clients",
            headers=owner_headers,
            json={**client_body, "audiences": ["y-api"], "scopes": ["openid"]},
        )
        token = await ac.post("/api/v1/tokens", headers=admin_headers, json={"name": "mine", "token_type": "personal"})
        role = await ac.post(
            "/api/v1/roles", headers=owner_headers, json={"org_id": org_id, "name": "support", "permissions": []}
        )
        invite = await ac.post(
            "/api/v1/invitations", headers=owner_headers, json={"email": "pending@example.com", "org_id": org_id}
        )
        for created in (flagged, quiet, token, role, invite):
            assert created.status_code == 200
        await approve_consent(
            ac,
            admin_headers,
            {
                "response_type": "code",
                "client_id": flagged.json()["client_id"],
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": "abc",
                "code_challenge_method": "plain",
                "scope": "openid",
                "audience": "x-api",
            },
        )

    async with async_session_factory() as db:
        owner = await db.get(User, owner_id)
        owner.created_at = services.now_utc() - timedelta(days=30)
        await db.commit()
    sweep = await ops.incident_sweep(services.now_utc() - timedelta(days=1))
    assert [row["email"] for row in sweep["accounts"]] == ["admin@corp.example.com"]
    assert {(row["org"], row["role"]) for row in sweep["memberships"]} == {("example", "admin"), ("evil", "owner")}
    assert [row["slug"] for row in sweep["owned_orgs"]] == ["evil"]
    listed_clients = {row["client_id"] for row in sweep["clients"]}
    assert flagged.json()["client_id"] in listed_clients
    assert quiet.json()["client_id"] in listed_clients  # created since the cutoff
    assert token.json()["id"] in {row["id"] for row in sweep["api_tokens"]}
    assert [row["email"] for row in sweep["invitations"]] == ["pending@example.com"]
    assert [row["client_id"] for row in sweep["oauth_grants"]] == [flagged.json()["client_id"]]
    assert [row["name"] for row in sweep["roles"]] == ["support"]
    assert "admin@corp.example.com" in {row["user"] for row in sweep["sessions"]}
    assert all("token_hash" not in row and "secret" not in str(row) for rows in sweep.values() for row in rows)

    async with async_session_factory() as db:
        overscoped, _raw = await services.create_api_token(
            db,
            name="overscoped",
            token_type_value="personal",
            org_id=org_id,
            user_id=admin_id,
            project_id=None,
            client_id=None,
            scopes=["*"],
            audiences=[],
            expires_at=None,
        )
        await db.commit()
    assert [item["id"] for item in await ops.overscoped_tokens()] == [overscoped.id]
    assert await ops.overscoped_tokens(revoke=True, ids=["no-such-token"]) == []
    assert await ops.overscoped_tokens(revoke=True, exclude_users=["admin@corp.example.com"]) == []
    assert [item["id"] for item in await ops.overscoped_tokens()] == [overscoped.id]
    revoked = await ops.overscoped_tokens(revoke=True, ids=[overscoped.id])
    assert [item["id"] for item in revoked] == [overscoped.id]
    assert await ops.overscoped_tokens() == []


@pytest.mark.asyncio
async def test_password_reset_revokes_sessions_and_api_tokens():
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        session_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        token = await ac.post("/api/v1/tokens", headers=session_headers, json={"name": "cli", "token_type": "personal"})
        token_headers = {"Authorization": f"Bearer {token.json()['token']}"}
        assert (await ac.get("/api/v1/auth/me", headers=token_headers)).status_code == 200
        async with async_session_factory() as db:
            user_id = owner.json()["user"]["id"]
            code = await services.create_one_time_code(
                db, email="owner@example.com", purpose="reset_password", user_id=user_id
            )
            await db.commit()
        reset = await ac.post(
            "/api/v1/auth/password/reset/confirm",
            json={"email": "owner@example.com", "code": code, "new_password": "a brand new passphrase"},
        )
        assert reset.status_code == 200
        ac.cookies.clear()
        assert (await ac.get("/api/v1/auth/me", headers=session_headers)).status_code == 401
        assert (await ac.get("/api/v1/auth/me", headers=token_headers)).status_code == 401
        refreshed = await ac.post("/api/v1/auth/refresh", json={"refresh_token": owner.json()["refresh_token"]})
        assert refreshed.status_code == 401


@pytest.mark.asyncio
async def test_org_admins_cannot_take_over_owner_or_platform_admin_accounts(monkeypatch):
    password = "correct horse battery"
    new_password = {"Operations": [{"op": "replace", "path": "password", "value": "attacker chosen secret"}]}
    async with await client() as ac:
        owner_headers, admin_headers, org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        owner_id = (await ac.get("/api/v1/auth/me", headers=owner_headers)).json()["user"]["id"]
        attempts = (
            ("patch", f"/scim/v2/Users/{owner_id}", new_password),
            ("post", f"/api/v1/users/{owner_id}/mfa/totp/reset", None),
            ("patch", f"/api/v1/users/{owner_id}", {"display_name": "Taken"}),
            ("post", f"/api/v1/users/{owner_id}/delete", {"dry_run": True}),
            ("post", f"/api/v1/users/{owner_id}/sessions/revoke", None),
        )
        for method, path, body in attempts:
            response = await getattr(ac, method)(path, headers=admin_headers, **({"json": body} if body else {}))
            assert response.status_code == 403, path
        stolen = await ac.post(
            "/api/v1/auth/login", json={"email": "owner@example.com", "password": "attacker chosen secret"}
        )
        assert stolen.status_code == 401

        async with async_session_factory() as db:
            roles = {(role.org_id, role.name): role.id for role in (await db.execute(select(Role))).scalars()}
            second = Organization(name="Second", slug="second")
            db.add(second)
            await db.flush()
            for name in ("owner", "admin"):
                permissions = ["*"] if name == "owner" else ["admin:*", "auth:*"]
                role = Role(org_id=second.id, name=name, permissions=permissions)
                db.add(role)
                await db.flush()
                roles[(second.id, name)] = role.id
            people = {}
            for email, role_name in (("tenant-owner@example.com", "owner"), ("tenant-admin@example.com", "admin")):
                user = await services.create_user(db, email=email, password=password)
                db.add(Membership(org_id=second.id, user_id=user.id, role_id=roles[(second.id, role_name)]))
                people[role_name] = user.id
            platform = await services.create_user(db, email="platform@example.com", password=password)
            await db.commit()
        tenant_admin = await ac.post(
            "/api/v1/auth/login", json={"email": "tenant-admin@example.com", "password": password}
        )
        tenant_headers = {"Authorization": f"Bearer {tenant_admin.json()['access_token']}"}
        tenant_takeover = await ac.patch(f"/scim/v2/Users/{people['owner']}", headers=tenant_headers, json=new_password)
        assert tenant_takeover.status_code == 403

        monkeypatch.setattr(settings, "platform_admin_user_ids", platform.id)
        adopted = await ac.post(
            "/api/v1/users/provision", headers=admin_headers, json={"email": "platform@example.com", "org_id": org_id}
        )
        assert adopted.status_code == 403

        member = await register(ac, json={"email": "member@example.com", "password": password})
        member_id = member.json()["user"]["id"]
        promoted = await ac.put(
            f"/api/v1/users/{member_id}/membership",
            headers=owner_headers,
            json={"org_id": org_id, "role": "owner", "status": "active"},
        )
        assert promoted.status_code == 200
        reset = await ac.post(f"/api/v1/users/{member_id}/mfa/totp/reset", headers=owner_headers)
        assert reset.status_code == 200
        renamed = await ac.patch(f"/api/v1/users/{member_id}", headers=owner_headers, json={"display_name": "Co-owner"})
        assert renamed.status_code == 200


@pytest.mark.asyncio
async def test_consent_accepts_only_hosted_sessions():
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        app_client = await ac.post(
            "/api/v1/clients",
            headers=owner_headers,
            json={
                "name": "App",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["x-api"],
                "scopes": ["openid", "auth:*", "admin:*", "token:*"],
            },
        )
        params = {
            "response_type": "code",
            "client_id": app_client.json()["client_id"],
            "redirect_uri": "https://app.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
            "scope": "openid auth:* admin:* token:*",
            "audience": "x-api",
        }
        api_token = await ac.post(
            "/api/v1/tokens", headers=owner_headers, json={"name": "narrow", "token_type": "personal"}
        )
        device = await ac.post(
            "/oauth/device_authorization", json={"client_id": "gatekeeper-cli", "scope": "auth:read"}
        )
        await ac.post(
            "/api/v1/auth/device/approve",
            headers=owner_headers,
            json={"user_code": device.json()["user_code"], "approve": True},
        )
        cli = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device.json()["device_code"],
                "client_id": "gatekeeper-cli",
            },
        )
        product = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "client_id": app_client.json()["client_id"],
            },
        )
        ac.cookies.clear()
        outsiders = [api_token.json()["token"], cli.json()["access_token"], product.json()["access_token"]]

        async def refused(raw: str) -> None:
            headers = {"Authorization": f"Bearer {raw}"}
            context = await ac.get("/api/v1/oauth/authorize/context", headers=headers, params=params)
            assert context.status_code == 401
            got = await ac.get("/oauth/authorize", headers=headers, params=params)
            assert got.status_code == 302 and urlparse(got.headers["location"]).path == "/login"
            posted = await ac.post(
                "/oauth/authorize", headers=headers, json={**params, "approve": True, "consent_nonce": "0" * 64}
            )
            assert urlparse(posted.json()["redirect_to"]).path == "/login"

        for raw in outsiders:
            await refused(raw)
        approved = await approve_consent(ac, owner_headers, params)
        assert "code=" in approved
        for raw in outsiders:
            await refused(raw)
        ac.cookies.clear()
        remembered = await ac.get("/oauth/authorize", headers=owner_headers, params=params)
        assert "code=" in remembered.headers["location"]


@pytest.mark.asyncio
async def test_clients_without_an_audience_need_a_platform_admin():
    body = {"name": "Backend", "public": False, "redirect_uris": ["https://app.example.com/callback"]}
    async with await client() as ac:
        owner_headers, admin_headers, _org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        empty = await ac.post("/api/v1/clients", headers=admin_headers, json={**body, "scopes": ["auth:read"]})
        assert empty.status_code == 403
        own = await ac.post(
            "/api/v1/clients", headers=admin_headers, json={**body, "audiences": ["my-api"], "scopes": ["auth:read"]}
        )
        assert own.status_code == 200
        cleared = await ac.patch(f"/api/v1/clients/{own.json()['id']}", headers=admin_headers, json={"audiences": []})
        assert cleared.status_code == 403
        service = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": own.json()["client_id"],
                "client_secret": own.json()["client_secret"],
            },
        )
        assert decode_access_token(service.json()["access_token"], audience="my-api")["aud"] == "my-api"
        service_headers = {"Authorization": f"Bearer {service.json()['access_token']}"}
        assert (await ac.get("/api/v1/orgs", headers=service_headers)).status_code == 401
        platform = await ac.post("/api/v1/clients", headers=owner_headers, json={**body, "scopes": ["auth:read"]})
        assert platform.status_code == 200


@pytest.mark.asyncio
async def test_scim_group_add_cannot_demote_an_owner():
    async with await client() as ac:
        owner_headers, admin_headers, org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        member = await register(ac, json={"email": "co-owner@example.com", "password": "correct horse battery"})
        member_id = member.json()["user"]["id"]
        promoted = await ac.put(
            f"/api/v1/users/{member_id}/membership",
            headers=owner_headers,
            json={"org_id": org_id, "role": "owner", "status": "active"},
        )
        assert promoted.status_code == 200
        roles = {role["name"]: role["id"] for role in (await ac.get("/api/v1/roles", headers=owner_headers)).json()}
        demoted = await ac.patch(
            f"/scim/v2/Groups/{roles['viewer']}",
            headers=admin_headers,
            json={"Operations": [{"op": "add", "path": "members", "value": [{"value": member_id}]}]},
        )
        assert demoted.status_code == 403
    async with async_session_factory() as db:
        role_id = (
            await db.execute(select(Membership.role_id).where(Membership.user_id == member_id))
        ).scalar_one()
    assert role_id == roles["owner"]


@pytest.mark.asyncio
async def test_only_owners_change_org_policy_or_prune_the_audit_log():
    async with await client() as ac:
        owner_headers, admin_headers, org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        for policy in (
            {"audit_retention_days": 1},
            {"trusted_device_mfa_bypass": True},
            {"session_idle_timeout_minutes": 5},
            {"allow_user_hard_delete": True},
        ):
            changed = await ac.patch(f"/api/v1/orgs/{org_id}", headers=admin_headers, json=policy)
            assert changed.status_code == 403, policy
        same = await ac.patch(
            f"/api/v1/orgs/{org_id}", headers=admin_headers, json={"name": "Renamed", "require_mfa": False}
        )
        assert same.status_code == 200
        retention = await ac.patch(f"/api/v1/orgs/{org_id}", headers=owner_headers, json={"audit_retention_days": 30})
        assert retention.status_code == 200
        prune = {"org_id": org_id, "dry_run": False}
        assert (await ac.post("/api/v1/audit/prune", headers=admin_headers, json=prune)).status_code == 403
        assert (await ac.post("/api/v1/audit/prune", headers=owner_headers, json=prune)).status_code == 200


@pytest.mark.asyncio
async def test_consent_post_without_a_session_returns_to_the_same_authorize_request():
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        app_client = await ac.post(
            "/api/v1/clients",
            headers=owner_headers,
            json={
                "name": "App",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["x-api"],
                "scopes": ["openid"],
            },
        )
        params = {
            "response_type": "code",
            "client_id": app_client.json()["client_id"],
            "redirect_uri": "https://app.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
            "scope": "openid",
            "audience": "x-api",
            "state": "keep-me",
        }
        ac.cookies.clear()
        posted = await ac.post("/oauth/authorize", json={**params, "approve": True, "consent_nonce": "0" * 64})
        login = urlparse(posted.json()["redirect_to"])
        assert login.path == "/login"
        resume = parse_qs(login.query)["redirect"][0]
        assert "approve" not in resume and "consent_nonce" not in resume
        resumed = await ac.get(resume, headers=owner_headers)
        assert resumed.status_code == 302
        consent = urlparse(resumed.headers["location"])
        assert consent.path == "/authorize"
        assert parse_qs(consent.query)["state"] == ["keep-me"]


@pytest.mark.asyncio
async def test_migration_turns_off_email_linking_on_existing_providers():
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    from app.models import OAuthProvider

    path = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "20261105_0023_disable_email_linking.py"
    spec = importlib.util.spec_from_file_location("migration_0023", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    async with async_session_factory() as db:
        db.add(
            OAuthProvider(
                provider_id="legacy",
                name="Legacy",
                authorization_url="https://login.example.com/authorize",
                token_url="https://login.example.com/token",
                userinfo_url="https://login.example.com/userinfo",
                allow_email_linking=True,
            )
        )
        await db.commit()

    def upgrade(connection) -> None:
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()

    async with engine.begin() as conn:
        await conn.run_sync(upgrade)
    async with async_session_factory() as db:
        assert (await db.execute(select(OAuthProvider.allow_email_linking))).scalars().all() == [False]


@pytest.mark.asyncio
async def test_incident_sweep_lists_new_and_audience_less_clients_and_recent_changes():
    body = {"name": "App", "public": True, "redirect_uris": ["https://app.example.com/callback"], "scopes": ["openid"]}
    async with await client() as ac:
        owner_headers, _admin_headers, org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        created = {}
        for name, audiences in (("new", ["plain-api"]), ("empty", []), ("old", ["quiet-api"])):
            response = await ac.post(
                "/api/v1/clients", headers=owner_headers, json={**body, "name": name, "audiences": audiences}
            )
            assert response.status_code == 200
            created[name] = response.json()
        role = await ac.post(
            "/api/v1/roles", headers=owner_headers, json={"org_id": org_id, "name": "support", "permissions": []}
        )
        assert role.status_code == 200
    long_ago = services.now_utc() - timedelta(days=30)
    async with async_session_factory() as db:
        for user in (await db.execute(select(User))).scalars():
            user.created_at = long_ago
        for name in ("empty", "old"):
            row = (
                await db.execute(select(main_module.AuthClient).where(main_module.AuthClient.id == created[name]["id"]))
            ).scalar_one()
            row.created_at = long_ago
        await db.commit()
    sweep = await ops.incident_sweep(services.now_utc() - timedelta(days=1))
    listed = {row["client_id"] for row in sweep["clients"]}
    assert created["new"]["client_id"] in listed
    assert created["empty"]["client_id"] in listed
    assert created["old"]["client_id"] not in listed
    actions = {row["action"] for row in sweep["audit_events"]}
    assert {"client.create", "role.create", "user.membership.update"} <= actions
    assert "auth.login" not in actions


@pytest.mark.asyncio
async def test_rotating_an_api_token_rechecks_its_bindings():
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        org_id = owner.json()["orgs"][0]["id"]
        other = await ac.post("/api/v1/orgs", headers=owner_headers, json={"name": "Other", "slug": "other"})
        switched = await ac.post(
            "/api/v1/auth/session/switch-org", headers=owner_headers, json={"org_id": other.json()["id"]}
        )
        project = await ac.post(
            "/api/v1/projects",
            headers={"Authorization": f"Bearer {switched.json()['access_token']}"},
            json={"org_id": other.json()["id"], "name": "Theirs", "slug": "theirs", "audience": "their-api"},
        )
        assert project.status_code == 200
        async with async_session_factory() as db:
            legacy, _raw = await services.create_api_token(
                db,
                name="legacy",
                token_type_value="service",
                org_id=org_id,
                user_id=None,
                project_id=project.json()["id"],
                client_id=None,
                scopes=["auth:read"],
                audiences=["their-api"],
                expires_at=None,
            )
            await db.commit()
        rotated = await ac.post(f"/api/v1/tokens/{legacy.id}/rotate", headers=owner_headers)
        assert rotated.status_code == 403


@pytest.mark.asyncio
async def test_platform_admins_may_assign_any_role(monkeypatch):
    async with await client() as ac:
        _owner_headers, admin_headers, org_id, admin_id = await bootstrap_owner_and_admin(ac)
        member = await register(ac, json={"email": "member@example.com", "password": "correct horse battery"})
        monkeypatch.setattr(settings, "platform_admin_user_ids", admin_id)
        promoted = await ac.put(
            f"/api/v1/users/{member.json()['user']['id']}/membership",
            headers=admin_headers,
            json={"org_id": org_id, "role": "owner", "status": "active"},
        )
        assert promoted.status_code == 200


@pytest.mark.asyncio
async def test_password_reset_and_change_close_pending_codes_grants_and_tokens():
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        app_client = await ac.post(
            "/api/v1/clients",
            headers=owner_headers,
            json={
                "name": "App",
                "public": True,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["x-api"],
                "scopes": ["openid"],
            },
        )
        params = {
            "response_type": "code",
            "client_id": app_client.json()["client_id"],
            "redirect_uri": "https://app.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
            "scope": "openid",
            "audience": "x-api",
        }
        code = parse_qs(urlparse(await approve_consent(ac, owner_headers, params)).query)["code"][0]
        device = await ac.post("/oauth/device_authorization", json={"client_id": "gatekeeper-cli"})
        await ac.post(
            "/api/v1/auth/device/approve",
            headers=owner_headers,
            json={"user_code": device.json()["user_code"], "approve": True},
        )
        async with async_session_factory() as db:
            reset_code = await services.create_one_time_code(
                db, email="owner@example.com", purpose="reset_password", user_id=owner.json()["user"]["id"]
            )
            await db.commit()
        reset = await ac.post(
            "/api/v1/auth/password/reset/confirm",
            json={"email": "owner@example.com", "code": reset_code, "new_password": "a brand new passphrase"},
        )
        assert reset.status_code == 200
        exchanged = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": app_client.json()["client_id"],
                "redirect_uri": "https://app.example.com/callback",
                "code": code,
                "code_verifier": "abc",
            },
        )
        assert exchanged.status_code == 400
        polled = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device.json()["device_code"],
                "client_id": "gatekeeper-cli",
            },
        )
        assert polled.status_code == 400

        ac.cookies.clear()
        login = {"email": "owner@example.com", "password": "a brand new passphrase"}
        current = (await ac.post("/api/v1/auth/login", json=login)).json()["access_token"]
        other = (await ac.post("/api/v1/auth/login", json=login)).json()["access_token"]
        ac.cookies.clear()
        api_token = await ac.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {current}"},
            json={"name": "cli", "token_type": "personal"},
        )
        changed = await ac.post(
            "/api/v1/auth/password/change",
            headers={"Authorization": f"Bearer {current}"},
            json={"current_password": "a brand new passphrase", "new_password": "another new passphrase"},
        )
        assert changed.status_code == 200
        assert (await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {current}"})).status_code == 200
        assert (await ac.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {other}"})).status_code == 401
        token_headers = {"Authorization": f"Bearer {api_token.json()['token']}"}
        assert (await ac.get("/api/v1/auth/me", headers=token_headers)).status_code == 401


@pytest.mark.asyncio
async def test_client_tokens_never_fall_back_to_the_issuer_audience():
    from jose import jwt as jose_jwt

    mcp = {
        "name": "MCP",
        "redirect_uris": ["https://mcp.example.com/callback"],
        "audiences": [],
        "mcp_resource_uri": "https://mcp.example.com/mcp",
        "scopes": ["openid", "auth:read"],
    }
    async with await client() as ac:
        owner_headers, admin_headers, _org_id, _admin_id = await bootstrap_owner_and_admin(ac)
        mcp_only = await ac.post("/api/v1/clients", headers=admin_headers, json={**mcp, "public": True})
        assert mcp_only.status_code == 403
        own = await ac.post(
            "/api/v1/clients", headers=admin_headers, json={**mcp, "public": True, "audiences": ["mine-api"]}
        )
        emptied = await ac.patch(
            f"/api/v1/clients/{own.json()['id']}",
            headers=admin_headers,
            json={"audiences": [], "mcp_resource_uri": "https://mcp.example.com/mcp"},
        )
        assert emptied.status_code == 403

        public = await ac.post("/api/v1/clients", headers=owner_headers, json={**mcp, "public": True})
        params = {
            "response_type": "code",
            "client_id": public.json()["client_id"],
            "redirect_uri": "https://mcp.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
            "scope": "openid auth:read",
        }
        code = parse_qs(urlparse(await approve_consent(ac, owner_headers, params)).query)["code"][0]
        exchanged = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": public.json()["client_id"],
                "redirect_uri": "https://mcp.example.com/callback",
                "code": code,
                "code_verifier": "abc",
            },
        )
        app_token = exchanged.json()["access_token"]
        assert settings.issuer not in str(jose_jwt.get_unverified_claims(app_token)["aud"])
        app_headers = {"Authorization": f"Bearer {app_token}"}
        assert (await ac.get("/api/v1/oauth/authorize/context", headers=app_headers, params=params)).status_code == 401
        refreshed = await ac.post("/api/v1/auth/refresh", json={"refresh_token": exchanged.json()["refresh_token"]})
        assert settings.issuer not in str(jose_jwt.get_unverified_claims(refreshed.json()["access_token"])["aud"])

        confidential = await ac.post("/api/v1/clients", headers=owner_headers, json={**mcp, "public": False})
        service = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": confidential.json()["client_id"],
                "client_secret": confidential.json()["client_secret"],
            },
        )
        service_headers = {"Authorization": f"Bearer {service.json()['access_token']}"}
        assert (await ac.get("/api/v1/orgs", headers=service_headers)).status_code == 401
        assert "code=" in await approve_consent(ac, owner_headers, params)


@pytest.mark.asyncio
async def test_app_sessions_stored_with_the_issuer_audience_refresh_to_the_client_audience():
    from jose import jwt as jose_jwt

    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        created = await ac.post(
            "/api/v1/clients",
            headers=owner_headers,
            json={
                "name": "MCP",
                "public": True,
                "redirect_uris": ["https://mcp.example.com/callback"],
                "audiences": [],
                "mcp_resource_uri": "https://mcp.example.com/mcp",
                "scopes": ["openid", "auth:read"],
            },
        )
        client_id = created.json()["client_id"]
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://mcp.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
            "scope": "openid auth:read",
        }
        code = parse_qs(urlparse(await approve_consent(ac, owner_headers, params)).query)["code"][0]
        exchanged = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "redirect_uri": "https://mcp.example.com/callback",
                "code": code,
                "code_verifier": "abc",
            },
        )
        session_id = jose_jwt.get_unverified_claims(exchanged.json()["access_token"])["session_id"]
        async with async_session_factory() as db:
            stored = await db.get(Session, session_id)
            stored.audience = settings.issuer  # an app session stored before the deploy
            await db.commit()
        ac.cookies.clear()
        refreshed = await ac.post("/api/v1/auth/refresh", json={"refresh_token": exchanged.json()["refresh_token"]})
        assert refreshed.status_code == 200
        app_token = refreshed.json()["access_token"]
        assert settings.issuer not in str(jose_jwt.get_unverified_claims(app_token)["aud"])
        app_headers = {"Authorization": f"Bearer {app_token}"}
        assert (await ac.get("/api/v1/oauth/authorize/context", headers=app_headers, params=params)).status_code == 401

        hosted = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "client_id": client_id,
                "audience": settings.issuer,
            },
        )
        ac.cookies.clear()
        hosted_refresh = await ac.post("/api/v1/auth/refresh", json={"refresh_token": hosted.json()["refresh_token"]})
        hosted_token = hosted_refresh.json()["access_token"]
        assert jose_jwt.get_unverified_claims(hosted_token)["aud"] == settings.issuer
        hosted_context = await ac.get(
            "/api/v1/oauth/authorize/context", headers={"Authorization": f"Bearer {hosted_token}"}, params=params
        )
        assert hosted_context.status_code == 200


@pytest.mark.asyncio
async def test_device_grants_need_a_hosted_approver_and_a_public_or_authenticated_client():
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        owner_id = owner.json()["user"]["id"]

        async def start_and_approve(headers: dict[str, str]):
            device = await ac.post("/oauth/device_authorization", json={"client_id": "gatekeeper-cli"})
            approved = await ac.post(
                "/api/v1/auth/device/approve",
                headers=headers,
                json={"user_code": device.json()["user_code"], "approve": True},
            )
            return device, approved

        device, approved = await start_and_approve(owner_headers)
        assert approved.status_code == 200
        cli = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device.json()["device_code"],
                "client_id": "gatekeeper-cli",
            },
        )
        pat = await ac.post("/api/v1/tokens", headers=owner_headers, json={"name": "pat", "token_type": "personal"})
        ac.cookies.clear()
        for raw in (cli.json()["access_token"], pat.json()["token"]):
            _device, refused = await start_and_approve({"Authorization": f"Bearer {raw}"})
            assert refused.status_code == 401
            options = await ac.post(
                "/api/v1/auth/device/passkey/options",
                headers={"Authorization": f"Bearer {raw}"},
                json={"user_code": _device.json()["user_code"]},
            )
            assert options.status_code == 401

        confidential = await ac.post(
            "/api/v1/clients",
            headers=owner_headers,
            json={
                "name": "Backend",
                "public": False,
                "redirect_uris": ["https://app.example.com/callback"],
                "audiences": ["backend-api"],
                "scopes": ["openid", "auth:read"],
            },
        )
        started = await ac.post("/oauth/device_authorization", json={"client_id": confidential.json()["client_id"]})
        assert started.status_code == 400
        async with async_session_factory() as db:
            db.add(
                main_module.DeviceGrant(
                    device_code_hash=security.token_hash("gkd_legacy"),
                    user_code_hash=security.token_hash("LEGACY-CODE"),
                    user_code_hint="LEGA",
                    client_id=confidential.json()["id"],
                    scope="openid",
                    user_id=owner_id,
                    amr=["pwd"],
                    expires_at=services.now_utc() + timedelta(minutes=5),
                    approved_at=services.now_utc(),
                )
            )
            await db.commit()
        exchange = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": "gkd_legacy",
            "client_id": confidential.json()["client_id"],
        }
        assert (await ac.post("/oauth/token", data=exchange)).status_code == 401
        assert (await ac.post("/oauth/token", data={**exchange, "client_secret": "wrong"})).status_code == 401
        secret = confidential.json()["client_secret"]
        assert (await ac.post("/oauth/token", data={**exchange, "client_secret": secret})).status_code == 200


async def second_tenant_with_admin(ac: AsyncClient, password: str = "correct horse battery"):
    """A second org whose only member is its admin, who is not a platform admin."""
    async with async_session_factory() as db:
        tenant = Organization(name="Tenant", slug="tenant")
        db.add(tenant)
        await db.flush()
        roles = await services.add_default_org_roles(db, tenant)
        admin = await services.create_user(db, email="tenant-admin@example.com", password=password)
        db.add(Membership(org_id=tenant.id, user_id=admin.id, role_id=roles["admin"].id))
        await db.commit()
        tenant_id, role_ids = tenant.id, {name: role.id for name, role in roles.items()}
    login = await ac.post("/api/v1/auth/login", json={"email": "tenant-admin@example.com", "password": password})
    return {"Authorization": f"Bearer {login.json()['access_token']}"}, tenant_id, role_ids


@pytest.mark.asyncio
async def test_tenant_admins_cannot_pull_existing_accounts_into_their_org(monkeypatch):
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        owner_headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
        owner_id = owner.json()["user"]["id"]
        tenant_headers, tenant_id, tenant_roles = await second_tenant_with_admin(ac)
        async with async_session_factory() as db:
            orphan = await services.create_user(db, email="orphan@example.com", password="correct horse battery")
            platform = await services.create_user(db, email="platform@example.com", password="correct horse battery")
            await db.commit()
        monkeypatch.setattr(settings, "platform_admin_user_ids", platform.id)
        for user_id in (owner_id, orphan.id, platform.id):
            pulled = await ac.put(
                f"/api/v1/users/{user_id}/membership",
                headers=tenant_headers,
                json={"org_id": tenant_id, "role": "viewer", "status": "active"},
            )
            assert pulled.status_code == 403, user_id
        assert (await ac.get("/api/v1/auth/me", headers=owner_headers)).status_code == 200

        async with async_session_factory() as db:
            db.add(Membership(org_id=tenant_id, user_id=owner_id, role_id=tenant_roles["viewer"]))
            await db.commit()
        touched = await ac.put(
            f"/api/v1/users/{owner_id}/membership",
            headers=tenant_headers,
            json={"org_id": tenant_id, "role": "viewer", "status": "active"},
        )
        assert touched.status_code == 403
        assert (await ac.get("/api/v1/auth/me", headers=owner_headers)).status_code == 200

        bootstrap_id = owner.json()["orgs"][0]["id"]
        adopted = await ac.put(
            f"/api/v1/users/{orphan.id}/membership",
            headers=owner_headers,
            json={"org_id": bootstrap_id, "role": "viewer", "status": "active"},
        )
        assert adopted.status_code == 200


@pytest.mark.asyncio
async def test_scim_deactivation_cannot_disable_platform_admins_or_owners(monkeypatch):
    async with await client() as ac:
        await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        tenant_headers, tenant_id, tenant_roles = await second_tenant_with_admin(ac)
        async with async_session_factory() as db:
            platform = await services.create_user(db, email="platform@example.com", password="correct horse battery")
            tenant_owner = await services.create_user(db, email="t-owner@example.com", password="correct horse battery")
            db.add(Membership(org_id=tenant_id, user_id=platform.id, role_id=tenant_roles["viewer"]))
            db.add(Membership(org_id=tenant_id, user_id=tenant_owner.id, role_id=tenant_roles["owner"]))
            await db.commit()
        monkeypatch.setattr(settings, "platform_admin_user_ids", platform.id)
        deactivate = {"Operations": [{"op": "replace", "path": "active", "value": False}]}
        for user_id in (platform.id, tenant_owner.id):
            patched = await ac.patch(f"/scim/v2/Users/{user_id}", headers=tenant_headers, json=deactivate)
            assert patched.status_code == 403, user_id
            deleted = await ac.delete(f"/scim/v2/Users/{user_id}", headers=tenant_headers)
            assert deleted.status_code == 403, user_id
    async with async_session_factory() as db:
        disabled = dict((await db.execute(select(User.email, User.disabled))).all())
    assert disabled["platform@example.com"] is False
    assert disabled["t-owner@example.com"] is False


@pytest.mark.asyncio
async def test_scim_cannot_revoke_or_rename_an_owner_who_joined_a_tenant():
    password = "correct horse battery"
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": password})
        owner_id = owner.json()["user"]["id"]
        await ac.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": password})
        tenant_headers, tenant_id, tenant_roles = await second_tenant_with_admin(ac)
        async with async_session_factory() as db:
            db.add(Membership(org_id=tenant_id, user_id=owner_id, role_id=tenant_roles["viewer"]))
            await db.commit()

        async def live_sessions() -> int:
            async with async_session_factory() as db:
                live = select(Session.id).where(Session.user_id == owner_id, Session.revoked_at.is_(None))
                return len((await db.execute(live)).all())

        assert await live_sessions() == 2
        members = [{"value": owner_id}]
        removed = await ac.patch(
            f"/scim/v2/Groups/{tenant_roles['viewer']}",
            headers=tenant_headers,
            json={"Operations": [{"op": "remove", "path": "members", "value": members}]},
        )
        assert removed.status_code == 403
        moved = await ac.patch(
            f"/scim/v2/Groups/{tenant_roles['admin']}",
            headers=tenant_headers,
            json={"Operations": [{"op": "add", "path": "members", "value": members}]},
        )
        assert moved.status_code == 403
        deleted = await ac.delete(f"/scim/v2/Users/{owner_id}", headers=tenant_headers)
        assert deleted.status_code == 403
        renamed = await ac.patch(
            f"/scim/v2/Users/{owner_id}",
            headers=tenant_headers,
            json={"Operations": [{"op": "replace", "path": "displayName", "value": "Taken Over"}]},
        )
        assert renamed.status_code == 403
        assert await live_sessions() == 2
    async with async_session_factory() as db:
        assert (await db.get(User, owner_id)).display_name != "Taken Over"
        status = await db.scalar(
            select(Membership.status).where(Membership.user_id == owner_id, Membership.org_id == tenant_id)
        )
        assert status == "active"


@pytest.mark.asyncio
async def test_incident_sweep_flags_mcp_only_clients():
    async with await client() as ac:
        owner = await register(ac, json={"email": "owner@example.com", "password": "correct horse battery"})
        created = await ac.post(
            "/api/v1/clients",
            headers={"Authorization": f"Bearer {owner.json()['access_token']}"},
            json={
                "name": "MCP",
                "public": True,
                "redirect_uris": ["https://mcp.example.com/callback"],
                "audiences": [],
                "mcp_resource_uri": "https://mcp.example.com/mcp",
                "scopes": ["openid"],
            },
        )
        assert created.status_code == 200
    long_ago = services.now_utc() - timedelta(days=30)
    async with async_session_factory() as db:
        row = await db.get(main_module.AuthClient, created.json()["id"])
        row.created_at = long_ago
        for user in (await db.execute(select(User))).scalars():
            user.created_at = long_ago
        await db.commit()
    sweep = await ops.incident_sweep(services.now_utc() - timedelta(days=1))
    assert sweep["owned_orgs"] == []
    assert created.json()["client_id"] in {row["client_id"] for row in sweep["clients"]}


@pytest.mark.asyncio
async def test_star_scope_cannot_revoke_sessions_in_other_orgs():
    password = "correct horse battery"
    async with await client() as ac:
        await register(ac, json={"email": "owner@example.com", "password": password})
        member = await register(ac, json={"email": "member@example.com", "password": password})
        member_session = decode_access_token(member.json()["access_token"])["session_id"]
        async with async_session_factory() as db:
            tenant = Organization(name="Tenant", slug="tenant")
            db.add(tenant)
            await db.flush()
            roles = await services.add_default_org_roles(db, tenant)
            tenant_owner = await services.create_user(db, email="t-owner@example.com", password=password)
            db.add(Membership(org_id=tenant.id, user_id=tenant_owner.id, role_id=roles["owner"].id))
            await db.commit()
        login = await ac.post("/api/v1/auth/login", json={"email": "t-owner@example.com", "password": password})
        assert login.json()["scope"] == "*"
        revoked = await ac.delete(
            f"/api/v1/sessions/{member_session}", headers={"Authorization": f"Bearer {login.json()['access_token']}"}
        )
        assert revoked.status_code in (403, 404)
        member_headers = {"Authorization": f"Bearer {member.json()['access_token']}"}
        assert (await ac.get("/api/v1/auth/me", headers=member_headers)).status_code == 200
