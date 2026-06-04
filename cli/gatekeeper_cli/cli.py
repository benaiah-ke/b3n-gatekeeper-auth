from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import typer
from rich.console import Console
from rich.table import Table

from gatekeeper_cli.auth import (
    clear_credentials,
    credentials_context,
    device_login,
    load_access_token,
    refresh_access_token,
    save_token_response,
)
from gatekeeper_cli.config import normalize_url

app = typer.Typer(help="GateKeeper auth CLI")
org_app = typer.Typer(help="Manage local organization context")
session_app = typer.Typer(help="Manage GateKeeper sessions and devices")
token_app = typer.Typer(help="Manage GateKeeper tokens")
client_app = typer.Typer(help="Manage GateKeeper clients")
mcp_app = typer.Typer(help="Manage MCP auth resources")
app.add_typer(org_app, name="org")
app.add_typer(session_app, name="session")
app.add_typer(token_app, name="token")
app.add_typer(client_app, name="client")
app.add_typer(mcp_app, name="mcp")
console = Console()


class AuthenticatedClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self._client: httpx.Client | None = None

    def __enter__(self) -> "AuthenticatedClient":
        token = load_access_token(self.base_url)
        if not token:
            console.print("[red]Not logged in.[/red]")
            raise typer.Exit(1)
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=20.0,
            headers={"Authorization": f"Bearer {token}"},
        )
        return self

    def __exit__(self, *args: object) -> None:
        if self._client:
            self._client.close()

    @property
    def client(self) -> httpx.Client:
        if not self._client:
            raise RuntimeError("Client is not open")
        return self._client

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        response = self.client.request(method, path, **kwargs)
        if response.status_code == 401:
            token = refresh_access_token(self.base_url)
            if token:
                self.client.headers["Authorization"] = f"Bearer {token}"
                response = self.client.request(method, path, **kwargs)
        return response

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", path, **kwargs)


def api(base_url: str) -> AuthenticatedClient:
    return AuthenticatedClient(base_url)


def origin_from_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return value.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}"


def expand_cli_values(values: list[str] | None, *, fallback: list[str] | None = None) -> list[str]:
    expanded: list[str] = []
    for value in values or []:
        expanded.extend(part for part in value.replace(",", " ").split() if part)
    return expanded or list(fallback or [])


def safe_count(client: AuthenticatedClient, path: str) -> int | None:
    response = client.get(path)
    if response.status_code in {401, 403, 404}:
        return None
    response.raise_for_status()
    payload = response.json()
    return len(payload) if isinstance(payload, list) else None


def response_json(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def add_doctor_row(table: Table, label: str, status: str, detail: str) -> None:
    colors = {"ready": "green", "warning": "yellow", "blocker": "red"}
    table.add_row(label, f"[{colors.get(status, 'white')}]{status}[/{colors.get(status, 'white')}]", detail)


@app.command()
def login(
    url: Optional[str] = typer.Option(None, "--url"),
    client_id: str = typer.Option("gatekeeper-cli", "--client-id"),
    scope: str = typer.Option("auth:read token:* mcp:*", "--scope"),
) -> None:
    device_login(normalize_url(url), client_id, scope)


@app.command()
def logout(url: Optional[str] = typer.Option(None, "--url")) -> None:
    base_url = normalize_url(url)
    token = load_access_token(base_url)
    if token:
        try:
            with httpx.Client(base_url=base_url, timeout=20.0, headers={"Authorization": f"Bearer {token}"}) as client:
                client.post("/api/v1/auth/logout")
        except httpx.HTTPError:
            pass
    clear_credentials(base_url)
    console.print("[green]Logged out[/green]")


@app.command()
def whoami(url: Optional[str] = typer.Option(None, "--url")) -> None:
    base_url = normalize_url(url)
    with api(base_url) as client:
        response = client.get("/api/v1/auth/me")
        response.raise_for_status()
        payload = response.json()
        context = credentials_context(base_url)
        if context.get("current_org_id") and payload.get("org_id") != context["current_org_id"]:
            payload["local_current_org_id"] = context["current_org_id"]
        console.print_json(data=payload)


@app.command()
def doctor(url: Optional[str] = typer.Option(None, "--url")) -> None:
    base_url = normalize_url(url)
    checks = Table(title=f"GateKeeper doctor: {base_url}")
    checks.add_column("Check")
    checks.add_column("Status")
    checks.add_column("Detail")

    discovery_payload: dict[str, Any] = {}
    try:
        with httpx.Client(base_url=base_url, timeout=20.0) as public_client:
            health = public_client.get("/health")
            health_payload = response_json(health)
            health_ok = health.status_code == 200 and health_payload.get("status") == "ok"
            add_doctor_row(
                checks,
                "Health",
                "ready" if health_ok else "blocker",
                "API is reachable" if health_ok else f"/health returned {health.status_code}",
            )

            discovery = public_client.get("/.well-known/openid-configuration")
            discovery_ok = discovery.status_code == 200
            discovery_payload = response_json(discovery) if discovery_ok else {}
            add_doctor_row(
                checks,
                "OIDC discovery",
                "ready" if discovery_ok else "blocker",
                discovery_payload.get("issuer") or f"returned {discovery.status_code}",
            )

            jwks_uri = discovery_payload.get("jwks_uri")
            jwks = public_client.get(jwks_uri.replace(base_url, "") if isinstance(jwks_uri, str) else "/oauth/jwks.json")
            jwks_payload = response_json(jwks)
            jwks_ok = jwks.status_code == 200 and bool(jwks_payload.get("keys"))
            add_doctor_row(
                checks,
                "JWKS",
                "ready" if jwks_ok else "blocker",
                "signing keys are published" if jwks_ok else f"JWKS returned {jwks.status_code}",
            )
    except httpx.HTTPError as exc:
        add_doctor_row(checks, "Health", "blocker", str(exc))
        add_doctor_row(checks, "OIDC discovery", "blocker", "API is not reachable")
        add_doctor_row(checks, "JWKS", "blocker", "API is not reachable")

    if not load_access_token(base_url):
        add_doctor_row(checks, "Authenticated setup", "warning", "login to inspect owner, SMTP, clients, projects, tokens, and sessions")
        console.print(checks)
        return

    try:
        with api(base_url) as client:
            setup = client.get("/api/v1/setup/status")
            setup.raise_for_status()
            status = setup.json()

            add_doctor_row(
                checks,
                "Owner",
                "ready" if status.get("owner_exists") and status.get("can_manage_clients") else "blocker",
                "owner can manage setup" if status.get("can_manage_clients") else "login with an owner account before setup",
            )
            add_doctor_row(
                checks,
                "Issuer",
                "ready" if status.get("issuer") == discovery_payload.get("issuer") else "warning",
                status.get("issuer") or "issuer unavailable",
            )
            add_doctor_row(
                checks,
                "Email delivery",
                "ready" if status.get("smtp_configured") and not status.get("email_dev_mode") else "warning",
                "SMTP configured" if status.get("smtp_configured") else "configure SMTP before relying on reset/invite emails",
            )
            add_doctor_row(
                checks,
                "Client management",
                "ready" if status.get("can_manage_clients") else "warning",
                "can create OAuth clients" if status.get("can_manage_clients") else "token cannot create OAuth clients",
            )
            add_doctor_row(
                checks,
                "Project audiences",
                "ready" if status.get("can_manage_projects") else "warning",
                "can create API audiences" if status.get("can_manage_projects") else "token cannot create project audiences",
            )
            add_doctor_row(
                checks,
                "API credentials",
                "ready" if status.get("can_issue_tokens") else "warning",
                "can issue API tokens" if status.get("can_issue_tokens") else "token cannot issue API credentials",
            )
            add_doctor_row(
                checks,
                "Dynamic registration",
                "warning" if status.get("dynamic_client_registration_enabled") else "ready",
                "enabled; verify registration policy" if status.get("dynamic_client_registration_enabled") else "disabled by default",
            )

            for label, path, empty_detail in [
                ("Registered clients", "/api/v1/clients", "create a web, API, CLI, or MCP client"),
                ("API audiences", "/api/v1/projects", "create a project audience such as example-api"),
                ("API tokens", "/api/v1/tokens", "create scoped personal, service, or project tokens"),
                ("Sessions", "/api/v1/sessions", "no session inventory visible"),
            ]:
                count = safe_count(client, path)
                add_doctor_row(
                    checks,
                    label,
                    "ready" if count else "warning",
                    f"{count} visible" if count is not None and count > 0 else empty_detail,
                )
    except typer.Exit:
        add_doctor_row(checks, "Authenticated setup", "warning", "login to inspect owner, SMTP, clients, projects, tokens, and sessions")
    except httpx.HTTPStatusError as exc:
        add_doctor_row(checks, "Authenticated setup", "warning", f"setup status returned {exc.response.status_code}")
    except httpx.HTTPError as exc:
        add_doctor_row(checks, "Authenticated setup", "warning", str(exc))

    console.print(checks)


@org_app.command("list")
def org_list(url: Optional[str] = typer.Option(None, "--url")) -> None:
    with api(normalize_url(url)) as client:
        response = client.get("/api/v1/orgs")
        response.raise_for_status()
        console.print_json(data=response.json())


@org_app.command("switch")
def org_switch(
    org_id: str,
    url: Optional[str] = typer.Option(None, "--url"),
    client_id: Optional[str] = typer.Option(None, "--client-id"),
    scope: Optional[str] = typer.Option(None, "--scope"),
    audience: Optional[str] = typer.Option(None, "--audience"),
    revoke_current_session: bool = typer.Option(False, "--revoke-current-session"),
) -> None:
    base_url = normalize_url(url)
    with api(base_url) as client:
        response = client.post(
            "/api/v1/auth/session/switch-org",
            json={
                "org_id": org_id,
                "client_id": client_id,
                "scope": scope,
                "audience": audience,
                "revoke_current_session": revoke_current_session,
            },
        )
        response.raise_for_status()
        payload = response.json()
        save_token_response(base_url, payload, current_org_id=org_id)
        console.print_json(data=payload)


@session_app.command("list")
def session_list(url: Optional[str] = typer.Option(None, "--url")) -> None:
    with api(normalize_url(url)) as client:
        response = client.get("/api/v1/sessions")
        response.raise_for_status()
        console.print_json(data=response.json())


@session_app.command("revoke")
def session_revoke(session_id: str, url: Optional[str] = typer.Option(None, "--url")) -> None:
    with api(normalize_url(url)) as client:
        response = client.delete(f"/api/v1/sessions/{session_id}")
        response.raise_for_status()
        console.print_json(data=response.json())


@session_app.command("label")
def session_label(
    session_id: str,
    label: str,
    url: Optional[str] = typer.Option(None, "--url"),
) -> None:
    with api(normalize_url(url)) as client:
        response = client.patch(f"/api/v1/sessions/{session_id}/device", json={"device_label": label})
        response.raise_for_status()
        console.print_json(data=response.json())


@session_app.command("trust")
def session_trust(
    session_id: str,
    url: Optional[str] = typer.Option(None, "--url"),
    trusted_until: Optional[str] = typer.Option(None, "--until"),
) -> None:
    payload: dict[str, Any] = {"trusted": True}
    if trusted_until:
        payload["trusted_until"] = trusted_until
    with api(normalize_url(url)) as client:
        response = client.patch(f"/api/v1/sessions/{session_id}/device", json=payload)
        response.raise_for_status()
        console.print_json(data=response.json())


@session_app.command("untrust")
def session_untrust(session_id: str, url: Optional[str] = typer.Option(None, "--url")) -> None:
    with api(normalize_url(url)) as client:
        response = client.patch(f"/api/v1/sessions/{session_id}/device", json={"trusted": False})
        response.raise_for_status()
        console.print_json(data=response.json())


@session_app.command("revoke-all")
def session_revoke_all(
    url: Optional[str] = typer.Option(None, "--url"),
    include_current: bool = typer.Option(False, "--include-current/--other-only"),
) -> None:
    base_url = normalize_url(url)
    with api(base_url) as client:
        response = client.post("/api/v1/sessions/revoke-all", json={"include_current": include_current})
        response.raise_for_status()
        console.print_json(data=response.json())
    if include_current:
        clear_credentials(base_url)


@token_app.command("list")
def token_list(url: Optional[str] = typer.Option(None, "--url")) -> None:
    with api(normalize_url(url)) as client:
        response = client.get("/api/v1/tokens")
        response.raise_for_status()
        console.print_json(data=response.json())


@token_app.command("create")
def token_create(
    name: str,
    url: Optional[str] = typer.Option(None, "--url"),
    token_type: str = typer.Option("personal", "--type"),
    scope: str = typer.Option("auth:read", "--scope"),
    audience: str = typer.Option("gatekeeper-api", "--audience"),
    org_id: Optional[str] = typer.Option(None, "--org-id"),
) -> None:
    with api(normalize_url(url)) as client:
        response = client.post(
            "/api/v1/tokens",
            json={
                "name": name,
                "token_type": token_type,
                "scopes": scope.split(),
                "audiences": audience.split(),
                "org_id": org_id,
            },
        )
        response.raise_for_status()
        console.print_json(data=response.json())


@token_app.command("revoke")
def token_revoke(token_id: str, url: Optional[str] = typer.Option(None, "--url")) -> None:
    with api(normalize_url(url)) as client:
        response = client.delete(f"/api/v1/tokens/{token_id}")
        response.raise_for_status()
        console.print_json(data=response.json())


@token_app.command("rotate")
def token_rotate(token_id: str, url: Optional[str] = typer.Option(None, "--url")) -> None:
    with api(normalize_url(url)) as client:
        response = client.post(f"/api/v1/tokens/{token_id}/rotate")
        response.raise_for_status()
        console.print_json(data=response.json())


@token_app.command("validate")
def token_validate(
    token: str = typer.Argument(..., help="Opaque GateKeeper API token value to validate"),
    url: Optional[str] = typer.Option(None, "--url"),
    audience: Optional[str] = typer.Option(None, "--audience"),
    scope: str = typer.Option("", "--scope", help="Required scopes separated by spaces"),
    org_id: Optional[str] = typer.Option(None, "--org-id"),
    project_id: Optional[str] = typer.Option(None, "--project-id"),
) -> None:
    with api(normalize_url(url)) as client:
        response = client.post(
            "/api/v1/tokens/validate",
            json={
                "token": token,
                "audience": audience,
                "required_scopes": scope.split() if scope else [],
                "org_id": org_id,
                "project_id": project_id,
            },
        )
        response.raise_for_status()
        console.print_json(data=response.json())


@client_app.command("list")
def client_list(url: Optional[str] = typer.Option(None, "--url")) -> None:
    with api(normalize_url(url)) as client:
        response = client.get("/api/v1/clients")
        response.raise_for_status()
        console.print_json(data=response.json())


@client_app.command("create")
def client_create(
    name: str,
    redirect_uri: Optional[str] = typer.Argument(None, help="Primary redirect URI for browser/OAuth clients"),
    audience: Optional[str] = typer.Argument(None, help="Primary protected API audience"),
    url: Optional[str] = typer.Option(None, "--url"),
    org_id: Optional[str] = typer.Option(None, "--org-id"),
    client_id: Optional[str] = typer.Option(None, "--client-id", help="Stable client_id to register instead of a generated gkc_* id"),
    public: bool = typer.Option(True, "--public/--confidential", help="Create a public client or a confidential client with a copy-once secret"),
    redirect_uris: Optional[list[str]] = typer.Option(None, "--redirect-uri", help="Redirect URI; repeat or use the positional redirect URI"),
    allowed_origins: Optional[list[str]] = typer.Option(None, "--origin", help="Allowed browser origin; defaults to redirect URI origins"),
    audiences: Optional[list[str]] = typer.Option(None, "--audience", help="Allowed audience; repeat or use the positional audience"),
    scopes: Optional[list[str]] = typer.Option(None, "--scope", help="Scope or space-separated scopes; repeatable"),
    require_mfa: bool = typer.Option(False, "--require-mfa", help="Require MFA for user grants to this client"),
    require_org_membership: bool = typer.Option(True, "--require-org-membership/--no-require-org-membership"),
    trusted_device_mfa_bypass: bool = typer.Option(False, "--trusted-device-mfa-bypass/--no-trusted-device-mfa-bypass"),
    session_idle_timeout_minutes: Optional[int] = typer.Option(None, "--idle-timeout-minutes", min=1),
) -> None:
    all_redirect_uris = [redirect_uri] if redirect_uri else []
    all_redirect_uris.extend(redirect_uris or [])
    all_audiences = [audience] if audience else []
    all_audiences.extend(audiences or [])
    payload = {
        "name": name,
        "client_id": client_id,
        "org_id": org_id,
        "public": public,
        "redirect_uris": all_redirect_uris,
        "allowed_origins": allowed_origins or [origin_from_url(uri) for uri in all_redirect_uris],
        "audiences": all_audiences,
        "scopes": expand_cli_values(scopes, fallback=["auth:read"]),
        "require_org_membership": require_org_membership,
        "require_mfa": require_mfa,
        "trusted_device_mfa_bypass": trusted_device_mfa_bypass,
        "session_idle_timeout_minutes": session_idle_timeout_minutes,
    }
    with api(normalize_url(url)) as client:
        response = client.post(
            "/api/v1/clients",
            json=payload,
        )
        response.raise_for_status()
        console.print_json(data=response.json())


@mcp_app.command("register")
def mcp_register(
    name: str,
    resource_uri: str,
    url: Optional[str] = typer.Option(None, "--url"),
    org_id: Optional[str] = typer.Option(None, "--org-id"),
    scope: str = typer.Option("mcp:tools mcp:resources", "--scope"),
) -> None:
    with api(normalize_url(url)) as client:
        response = client.post(
            "/api/v1/mcp/resources",
            json={"name": name, "org_id": org_id, "resource_uri": resource_uri, "scopes": scope.split()},
        )
        response.raise_for_status()
        console.print_json(data=response.json())


if __name__ == "__main__":
    app()
