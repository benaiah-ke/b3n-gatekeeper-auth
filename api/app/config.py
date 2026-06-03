from __future__ import annotations

from functools import lru_cache

from pydantic import EmailStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_env: str = "development"
    app_version: str = "0.1.0"
    debug: bool = False
    gatekeeper_url: str = "http://localhost:8000"
    ui_url: str = "http://localhost:5173"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    database_url: str = "sqlite+aiosqlite:///./gatekeeper.db"
    test_database_url: str = "sqlite+aiosqlite:///./test_gatekeeper.db"

    secret_key: str = "change-me-in-production"
    jwt_private_key_pem: str = ""
    jwt_public_key_pem: str = ""
    jwt_key_dir: str = ""
    jwt_key_id: str = "local-dev"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_days: int = 30
    device_code_ttl_seconds: int = 600
    email_code_ttl_seconds: int = 900

    bootstrap_admin_email: EmailStr = "admin@b3n.in"
    bootstrap_org_name: str = "B3n"
    bootstrap_org_slug: str = "b3n"

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "GateKeeper <auth@gatekeeper.b3n.in>"
    smtp_use_tls: bool = True
    email_dev_mode: bool = True

    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/api/v1/auth/oauth/google/callback"

    enable_dynamic_client_registration: bool = False
    mcp_default_scopes: str = "mcp:tools,mcp:resources"

    cookie_name: str = "gk_session"
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

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
