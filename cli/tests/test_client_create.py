from __future__ import annotations

import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from gatekeeper_cli.cli import app


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self._payload


class FakeApi:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.posts: list[dict[str, object]] = []

    def __enter__(self) -> "FakeApi":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def post(self, path: str, **kwargs: object) -> FakeResponse:
        self.posts.append({"path": path, **kwargs})
        return FakeResponse({"client_id": kwargs["json"]["client_id"]})  # type: ignore[index]


class ClientCreateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()
        self.calls: list[FakeApi] = []

    def fake_api(self, base_url: str) -> FakeApi:
        client = FakeApi(base_url)
        self.calls.append(client)
        return client

    def test_stable_confidential_client_payload_includes_policy_fields(self) -> None:
        with patch("gatekeeper_cli.cli.api", self.fake_api):
            result = self.runner.invoke(
                app,
                [
                    "client",
                    "create",
                    "Sentinel control plane",
                    "https://sentinel.b3n.in/api/v1/auth/callback",
                    "sentinel-api",
                    "--url",
                    "https://gatekeeper.b3n.in/",
                    "--client-id",
                    "sentinel-control-plane",
                    "--confidential",
                    "--scope",
                    "openid profile",
                    "--scope",
                    "email,auth:read",
                    "--origin",
                    "https://sentinel.b3n.in",
                    "--require-mfa",
                    "--idle-timeout-minutes",
                    "30",
                ],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.calls[0].base_url, "https://gatekeeper.b3n.in")
        post = self.calls[0].posts[0]
        self.assertEqual(post["path"], "/api/v1/clients")
        self.assertEqual(
            post["json"],
            {
                "name": "Sentinel control plane",
                "client_id": "sentinel-control-plane",
                "org_id": None,
                "public": False,
                "redirect_uris": ["https://sentinel.b3n.in/api/v1/auth/callback"],
                "allowed_origins": ["https://sentinel.b3n.in"],
                "audiences": ["sentinel-api"],
                "scopes": ["openid", "profile", "email", "auth:read"],
                "require_org_membership": True,
                "require_mfa": True,
                "trusted_device_mfa_bypass": False,
                "session_idle_timeout_minutes": 30,
            },
        )

    def test_public_device_client_payload_uses_audience_and_no_secret(self) -> None:
        with patch("gatekeeper_cli.cli.api", self.fake_api):
            result = self.runner.invoke(
                app,
                [
                    "client",
                    "create",
                    "Sentinel CLI",
                    "--url",
                    "https://gatekeeper.b3n.in",
                    "--client-id",
                    "sentinel-cli",
                    "--public",
                    "--audience",
                    "sentinel-api",
                    "--scope",
                    "openid profile email auth:read",
                    "--require-mfa",
                ],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        post = self.calls[0].posts[0]
        self.assertEqual(
            post["json"],
            {
                "name": "Sentinel CLI",
                "client_id": "sentinel-cli",
                "org_id": None,
                "public": True,
                "redirect_uris": [],
                "allowed_origins": [],
                "audiences": ["sentinel-api"],
                "scopes": ["openid", "profile", "email", "auth:read"],
                "require_org_membership": True,
                "require_mfa": True,
                "trusted_device_mfa_bypass": False,
                "session_idle_timeout_minutes": None,
            },
        )


if __name__ == "__main__":
    unittest.main()
