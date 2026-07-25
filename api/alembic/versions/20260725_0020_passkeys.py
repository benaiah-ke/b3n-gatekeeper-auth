"""Add passkey credentials and WebAuthn ceremonies.

Revision ID: 20260725_0020
Revises: 20260608_0019
Create Date: 2026-07-25
"""

from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "20260725_0020"
down_revision: str | None = "20260608_0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.JSON:
    return sa.JSON().with_variant(JSONB, "postgresql")


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def _indexes(table_name: str) -> set[str]:
    return {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    table_names = set(sa.inspect(bind).get_table_names())
    if "webauthn_credentials" not in table_names:
        op.create_table(
            "webauthn_credentials",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("credential_id", sa.String(length=1024), nullable=True),
            sa.Column("credential_id_hash", sa.String(length=80), nullable=False),
            sa.Column("public_key", sa.Text(), nullable=False),
            sa.Column("transports", _json_type(), nullable=True),
            sa.Column("sign_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("name", sa.String(length=160), nullable=True),
            sa.Column("aaguid", sa.String(length=36), nullable=True),
            sa.Column(
                "credential_device_type",
                sa.String(length=40),
                server_default="single_device",
                nullable=False,
            ),
            sa.Column("backed_up", sa.Boolean(), server_default=sa.false(), nullable=False),
            sa.Column("last_used_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_webauthn_credentials_credential_id",
            "webauthn_credentials",
            ["credential_id"],
            unique=True,
        )
        op.create_index(
            "ix_webauthn_credentials_credential_id_hash",
            "webauthn_credentials",
            ["credential_id_hash"],
            unique=True,
        )
        op.create_index("ix_webauthn_credentials_user_id", "webauthn_credentials", ["user_id"])
    else:
        columns = _columns("webauthn_credentials")
        additions = (
            ("credential_id", sa.Column("credential_id", sa.String(length=1024), nullable=True)),
            ("name", sa.Column("name", sa.String(length=160), nullable=True)),
            ("aaguid", sa.Column("aaguid", sa.String(length=36), nullable=True)),
            (
                "credential_device_type",
                sa.Column(
                    "credential_device_type",
                    sa.String(length=40),
                    server_default="single_device",
                    nullable=False,
                ),
            ),
            (
                "backed_up",
                sa.Column("backed_up", sa.Boolean(), server_default=sa.false(), nullable=False),
            ),
            ("revoked_at", sa.Column("revoked_at", sa.DateTime(), nullable=True)),
        )
        for name, column in additions:
            if name not in columns:
                op.add_column("webauthn_credentials", column)
        if "ix_webauthn_credentials_credential_id" not in _indexes("webauthn_credentials"):
            op.create_index(
                "ix_webauthn_credentials_credential_id",
                "webauthn_credentials",
                ["credential_id"],
                unique=True,
            )

    if "webauthn_challenges" not in table_names:
        op.create_table(
            "webauthn_challenges",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("purpose", sa.String(length=40), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=True),
            sa.Column("session_id", sa.String(length=36), nullable=True),
            sa.Column("challenge_encrypted", sa.Text(), nullable=False),
            sa.Column("context", _json_type(), nullable=True),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("used_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
            sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_webauthn_challenges_purpose", "webauthn_challenges", ["purpose"])
        op.create_index("ix_webauthn_challenges_session_id", "webauthn_challenges", ["session_id"])
        op.create_index("ix_webauthn_challenges_user_id", "webauthn_challenges", ["user_id"])
        op.create_index(
            "ix_webauthn_challenges_purpose_user_used",
            "webauthn_challenges",
            ["purpose", "user_id", "used_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    table_names = set(sa.inspect(bind).get_table_names())
    if "webauthn_challenges" in table_names:
        op.drop_table("webauthn_challenges")

    if "webauthn_credentials" not in table_names:
        return
    indexes = _indexes("webauthn_credentials")
    if "ix_webauthn_credentials_credential_id" in indexes:
        op.drop_index("ix_webauthn_credentials_credential_id", table_name="webauthn_credentials")
    columns = _columns("webauthn_credentials")
    for name in (
        "revoked_at",
        "backed_up",
        "credential_device_type",
        "aaguid",
        "name",
        "credential_id",
    ):
        if name in columns:
            op.drop_column("webauthn_credentials", name)
