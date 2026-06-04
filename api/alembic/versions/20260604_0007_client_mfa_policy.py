"""add client mfa policy and amr persistence

Revision ID: 20260604_0007
Revises: 20260604_0006
Create Date: 2026-06-04
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "20260604_0007"
down_revision = "20260604_0006"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def _json_type():
    return sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    client_columns = _columns("auth_clients")
    if "require_mfa" not in client_columns:
        op.add_column(
            "auth_clients",
            sa.Column("require_mfa", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        with op.batch_alter_table("auth_clients") as batch_op:
            batch_op.alter_column(
                "require_mfa",
                server_default=None,
                existing_type=sa.Boolean(),
                existing_nullable=False,
            )

    session_columns = _columns("sessions")
    if "amr" not in session_columns:
        op.add_column("sessions", sa.Column("amr", _json_type(), nullable=True))

    code_columns = _columns("oauth_authorization_codes")
    if "amr" not in code_columns:
        op.add_column("oauth_authorization_codes", sa.Column("amr", _json_type(), nullable=True))

    device_columns = _columns("device_grants")
    if "amr" not in device_columns:
        op.add_column("device_grants", sa.Column("amr", _json_type(), nullable=True))


def downgrade() -> None:
    if "amr" in _columns("device_grants"):
        op.drop_column("device_grants", "amr")
    if "amr" in _columns("oauth_authorization_codes"):
        op.drop_column("oauth_authorization_codes", "amr")
    if "amr" in _columns("sessions"):
        op.drop_column("sessions", "amr")
    if "require_mfa" in _columns("auth_clients"):
        op.drop_column("auth_clients", "require_mfa")
