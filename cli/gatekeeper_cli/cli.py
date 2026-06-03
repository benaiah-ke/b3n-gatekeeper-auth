from __future__ import annotations

from typing import Optional

import httpx
import typer
from rich.console import Console

from gatekeeper_cli.auth import clear_credentials, device_login, load_access_token
from gatekeeper_cli.config import normalize_url

app = typer.Typer(help="GateKeeper auth CLI")
token_app = typer.Typer(help="Manage GateKeeper tokens")
client_app = typer.Typer(help="Manage GateKeeper clients")
mcp_app = typer.Typer(help="Manage MCP auth resources")
app.add_typer(token_app, name="token")
app.add_typer(client_app, name="client")
app.add_typer(mcp_app, name="mcp")
console = Console()


def api(base_url: str) -> httpx.Client:
    token = load_access_token(base_url)
    if not token:
        console.print("[red]Not logged in.[/red]")
        raise typer.Exit(1)
    return httpx.Client(base_url=base_url, timeout=20.0, headers={"Authorization": f"Bearer {token}"})


@app.command()
def login(
    url: Optional[str] = typer.Option(None, "--url"),
    client_id: str = typer.Option("gatekeeper-cli", "--client-id"),
    scope: str = typer.Option("auth:read token:* mcp:*", "--scope"),
) -> None:
    device_login(normalize_url(url), client_id, scope)


@app.command()
def logout(url: Optional[str] = typer.Option(None, "--url")) -> None:
    clear_credentials(normalize_url(url))
    console.print("[green]Logged out[/green]")


@app.command()
def whoami(url: Optional[str] = typer.Option(None, "--url")) -> None:
    base_url = normalize_url(url)
    with api(base_url) as client:
        response = client.get("/api/v1/auth/me")
        response.raise_for_status()
        console.print_json(data=response.json())


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
) -> None:
    with api(normalize_url(url)) as client:
        response = client.post(
            "/api/v1/tokens",
            json={
                "name": name,
                "token_type": token_type,
                "scopes": scope.split(),
                "audiences": ["gatekeeper-api"],
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
    token_revoke(token_id, url)
    console.print("[yellow]Create a replacement token with `gatekeeper token create`.[/yellow]")


@client_app.command("list")
def client_list(url: Optional[str] = typer.Option(None, "--url")) -> None:
    with api(normalize_url(url)) as client:
        response = client.get("/api/v1/clients")
        response.raise_for_status()
        console.print_json(data=response.json())


@client_app.command("create")
def client_create(
    name: str,
    redirect_uri: str,
    audience: str,
    url: Optional[str] = typer.Option(None, "--url"),
) -> None:
    with api(normalize_url(url)) as client:
        response = client.post(
            "/api/v1/clients",
            json={
                "name": name,
                "public": True,
                "redirect_uris": [redirect_uri],
                "allowed_origins": [redirect_uri.split("/callback")[0]],
                "audiences": [audience],
                "scopes": ["auth:read"],
            },
        )
        response.raise_for_status()
        console.print_json(data=response.json())


@mcp_app.command("register")
def mcp_register(
    name: str,
    resource_uri: str,
    url: Optional[str] = typer.Option(None, "--url"),
    scope: str = typer.Option("mcp:tools mcp:resources", "--scope"),
) -> None:
    with api(normalize_url(url)) as client:
        response = client.post(
            "/api/v1/mcp/resources",
            json={"name": name, "resource_uri": resource_uri, "scopes": scope.split()},
        )
        response.raise_for_status()
        console.print_json(data=response.json())


if __name__ == "__main__":
    app()

