from __future__ import annotations

import os
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import pytest
from httpx import ASGITransport, AsyncClient

from app import main as main_module
from app import security, services
from app.config import settings
from app.database import Base, async_session_factory, engine
from app.main import app
from app.models import AuditEvent, Identity, Session, User
from app.security import create_access_token, decode_access_token, public_jwk, totp_code


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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
async def test_refresh_can_rotate_from_browser_refresh_cookie():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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

        app_login = await ac.post(
            "/api/v1/auth/login",
            json={
                "email": "operator@example.com",
                "password": "correct horse battery",
                "client_id": created_client["client_id"],
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
async def test_org_creation_seeds_owner_membership_and_session_switching():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        assert switched.status_code == 200
        assert switched.json()["scope"] == "api:read"
        switched_claims = decode_access_token(switched.json()["access_token"], audience="second-product-api")
        assert switched_claims["org_id"] == second_org["id"]
        assert switched_claims["org_slug"] == "second-product"
        assert switched_claims["org_role"] == "owner"
        assert switched_claims["permissions"] == ["*"]

        setup = await ac.get(
            "/api/v1/setup/status",
            headers={"Authorization": f"Bearer {switched.json()['access_token']}"},
        )
        assert setup.status_code == 200
        assert setup.json()["org"]["id"] == second_org["id"]
        assert setup.json()["can_manage_clients"] is True

        other_signup = await ac.post(
            "/api/v1/auth/signup",
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
async def test_client_management_is_scoped_to_current_organization():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert owner.status_code == 200
        first_access = owner.json()["access_token"]
        first_org_id = owner.json()["orgs"][0]["id"]

        first_only_user = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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

        duplicate = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
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

        backup_owner = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        target = await ac.post(
            "/api/v1/auth/signup",
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
async def test_admin_user_provisioning_creates_and_updates_org_memberships():
    async with await client() as ac:
        owner = await ac.post(
            "/api/v1/auth/signup",
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

        target = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
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

        target = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "owner@example.com", "password": "correct horse battery", "display_name": "Owner"},
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        target = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
            access, _refresh, _session, _refresh_model = await services.create_session_tokens(
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
                "allow_email_linking": True,
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
        owner = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        second = await second_client.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
async def test_client_mfa_policy_enforces_login_oauth_refresh_and_device_flows():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
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

        refreshed = await ac.post("/api/v1/auth/refresh", json={"refresh_token": mfa_payload["refresh_token"]})
        assert refreshed.status_code == 200
        refreshed_claims = decode_access_token(refreshed.json()["access_token"], audience="mfa-api")
        assert refreshed_claims["amr"] == ["pwd", "otp"]

        approved = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {mfa_payload['access_token']}"},
            params={
                "response_type": "code",
                "client_id": created.json()["client_id"],
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": "abc",
                "code_challenge_method": "plain",
                "scope": "openid profile email api:read",
                "audience": "mfa-api",
                "approve": "true",
            },
        )
        assert approved.status_code == 302
        code = parse_qs(urlparse(approved.headers["location"]).query)["code"][0]
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
            headers={"Authorization": f"Bearer {mfa_payload['access_token']}"},
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


@pytest.mark.asyncio
async def test_trusted_device_mfa_bypass_requires_policy_and_active_trust():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
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
                "totp_code": totp_code(secret),
            },
        )
        assert mfa_login.status_code == 200
        mfa_claims = decode_access_token(mfa_login.json()["access_token"], audience="trusted-api")
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
            },
        )
        assert trusted_login.status_code == 200
        trusted_claims = decode_access_token(trusted_login.json()["access_token"], audience="trusted-api")
        assert trusted_claims["amr"] == ["pwd", "trusted_device"]
        current_session = await ac.get(
            "/api/v1/sessions",
            headers={"Authorization": f"Bearer {trusted_login.json()['access_token']}"},
        )
        assert current_session.status_code == 200
        assert next(item for item in current_session.json() if item["current"])["trusted"] is True

        refreshed = await ac.post("/api/v1/auth/refresh", json={"refresh_token": trusted_login.json()["refresh_token"]})
        assert refreshed.status_code == 200
        refreshed_claims = decode_access_token(refreshed.json()["access_token"], audience="trusted-api")
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
async def test_invitation_create_accept_reuse_and_revoke():
    async with await client() as ac:
        owner = await ac.post(
            "/api/v1/auth/signup",
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
        first = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "first@example.com", "password": "correct horse battery"},
        )
        assert first.status_code == 200
        assert first.json()["orgs"][0]["role"] == "owner"

        bootstrap_admin = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "admin@example.com", "password": "correct horse battery"},
        )
        assert bootstrap_admin.status_code == 200
        assert bootstrap_admin.json()["orgs"][0]["role"] == "owner"

        viewer = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "viewer@example.com", "password": "correct horse battery"},
        )
        assert viewer.status_code == 200
        assert viewer.json()["orgs"][0]["role"] == "viewer"

        duplicate = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "viewer@example.com", "password": "correct horse battery"},
        )
        assert duplicate.status_code == 409


@pytest.mark.asyncio
async def test_cookie_auth_and_refresh_preserve_owner_scope(monkeypatch):
    monkeypatch.setattr(settings, "cookie_name", "gk_custom_session")
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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

        other = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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

        invalid_approve = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {access}"},
            params={**params, "approve": "true", "org_id": "not-an-org"},
        )
        assert invalid_approve.status_code == 403

        approved = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {access}"},
            params={**params, "approve": "true", "org_id": selected_org_id},
        )
        assert approved.status_code == 302
        callback = urlparse(approved.headers["location"])
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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

        approved = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {access}"},
            params={**params, "approve": "true", "org_id": org_id, "state": "admin-review"},
        )
        assert approved.status_code == 302
        assert parse_qs(urlparse(approved.headers["location"]).query)["code"][0].startswith("gkc_")

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
        second_approved = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {second_access}"},
            params={**second_params, "approve": "true", "org_id": second_org_id, "state": "second-admin-review"},
        )
        assert second_approved.status_code == 302

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
        signup = await ac.post(
            "/api/v1/auth/signup",
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

        approved = await ac.get(
            "/oauth/authorize",
            headers={"Authorization": f"Bearer {access}"},
            params={**params, "approve": "true"},
        )
        assert approved.status_code == 302
        code = parse_qs(urlparse(approved.headers["location"]).query)["code"][0]

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
        assert "permissions" not in claims


@pytest.mark.asyncio
async def test_introspection_validates_jwts_and_rejects_invalid_tokens():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
async def test_user_jwt_is_session_bound_and_revocation_updates_introspection():
    async with await client() as ac:
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery",
                "display_name": "Owner User",
            },
        )
        assert owner.status_code == 200
        owner_access = owner.json()["access_token"]
        org_id = owner.json()["orgs"][0]["id"]

        viewer = await ac.post(
            "/api/v1/auth/signup",
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
async def test_api_token_validation_returns_product_metadata_and_policy_checks():
    async with await client() as ac:
        owner = await ac.post(
            "/api/v1/auth/signup",
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
        signup = await ac.post(
            "/api/v1/auth/signup",
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
        owner = await ac.post(
            "/api/v1/auth/signup",
            json={"email": "owner@example.com", "password": "correct horse battery"},
        )
        assert owner.status_code == 200
        owner_payload = owner.json()
        owner_access = owner_payload["access_token"]
        owner_id = owner_payload["user"]["id"]
        org_id = owner_payload["orgs"][0]["id"]

        viewer = await ac.post(
            "/api/v1/auth/signup",
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
