from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from pydantic import BaseModel, EmailStr, Field
from pydantic_settings import BaseSettings


class OAuthProviderConfig(BaseModel):
    id: str
    name: str
    client_id: str = ""
    client_secret: str = ""
    authorization_url: str
    token_url: str
    userinfo_url: str
    redirect_uri: str = ""
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    subject_claim: str = "sub"
    email_claim: str = "email"
    name_claim: str = "name"
    email_verified_claim: str = "email_verified"
    allow_email_linking: bool = True
    require_verified_email: bool = True

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)


class Settings(BaseSettings):
    app_env: str = "development"
    app_version: str = "0.1.0"
    gatekeeper_image_tag: str = ""
    git_sha: str = ""
    debug: bool = False
    gatekeeper_url: str = "http://localhost:8000"
    ui_url: str = "http://localhost:5173"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    database_url: str = "sqlite+aiosqlite:///./gatekeeper.db"
    test_database_url: str = "sqlite+aiosqlite:///./test_gatekeeper.db"
    database_pool_size: int = 2
    database_max_overflow: int = 1
    database_pool_timeout_seconds: int = 10
    database_pool_recycle_seconds: int = 300

    secret_key: str = "change-me-in-production"
    jwt_private_key_pem: str = ""
    jwt_public_key_pem: str = ""
    jwt_key_dir: str = ""
    jwt_key_id: str = "local-dev"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_days: int = 30
    device_code_ttl_seconds: int = 600
    email_code_ttl_seconds: int = 900

    bootstrap_admin_email: EmailStr = "admin@example.com"
    bootstrap_org_name: str = "Example Org"
    bootstrap_org_slug: str = "example"

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "GateKeeper <auth@example.com>"
    smtp_use_tls: bool = True
    email_dev_mode: bool = True

    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/api/v1/auth/oauth/google/callback"
    oauth_providers_json: str = ""

    enable_dynamic_client_registration: bool = False
    mcp_default_scopes: str = "mcp:tools,mcp:resources"

    cookie_name: str = "gk_session"
    refresh_cookie_name: str = "gk_refresh"
    device_cookie_name: str = "gk_device"
    cookie_secure: bool = False
    cookie_domain: str = ""

    @property
    def issuer(self) -> str:
        return self.gatekeeper_url.rstrip("/")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def mcp_default_scope_list(self) -> list[str]:
        return [scope.strip() for scope in self.mcp_default_scopes.split(",") if scope.strip()]

    def oauth_provider_configs(self) -> dict[str, OAuthProviderConfig]:
        providers: dict[str, OAuthProviderConfig] = {}
        if self.oauth_providers_json.strip():
            parsed = json.loads(self.oauth_providers_json)
            items: list[Any]
            if isinstance(parsed, dict):
                items = [
                    {"id": provider_id, **value} if isinstance(value, dict) else value
                    for provider_id, value in parsed.items()
                ]
            elif isinstance(parsed, list):
                items = parsed
            else:
                raise ValueError("OAUTH_PROVIDERS_JSON must be a JSON object or array")
            for item in items:
                provider = OAuthProviderConfig.model_validate(item)
                providers[provider.id] = provider

        if self.google_client_id or self.google_client_secret:
            providers.setdefault(
                "google",
                OAuthProviderConfig(
                    id="google",
                    name="Google",
                    client_id=self.google_client_id,
                    client_secret=self.google_client_secret,
                    authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
                    token_url="https://oauth2.googleapis.com/token",
                    userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
                    redirect_uri=self.google_redirect_uri,
                ),
            )
        return providers

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
