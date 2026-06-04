"""add trusted device mfa policy

Revision ID: 20260604_0012
Revises: 20260604_0011
Create Date: 2026-06-04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0012"
down_revision = "20260604_0011"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    org_columns = _columns("organizations")
    if "trusted_device_mfa_bypass" not in org_columns:
        op.add_column(
            "organizations",
            sa.Column("trusted_device_mfa_bypass", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        with op.batch_alter_table("organizations") as batch_op:
            batch_op.alter_column(
                "trusted_device_mfa_bypass",
                server_default=None,
                existing_type=sa.Boolean(),
                existing_nullable=False,
            )

    client_columns = _columns("auth_clients")
    if "trusted_device_mfa_bypass" not in client_columns:
        op.add_column(
            "auth_clients",
            sa.Column("trusted_device_mfa_bypass", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        with op.batch_alter_table("auth_clients") as batch_op:
            batch_op.alter_column(
                "trusted_device_mfa_bypass",
                server_default=None,
                existing_type=sa.Boolean(),
                existing_nullable=False,
            )

    session_columns = _columns("sessions")
    if "device_id_hash" not in session_columns:
        op.add_column("sessions", sa.Column("device_id_hash", sa.String(length=80), nullable=True))
        op.create_index("ix_sessions_device_id_hash", "sessions", ["device_id_hash"], unique=False)


def downgrade() -> None:
    session_columns = _columns("sessions")
    if "device_id_hash" in session_columns:
        op.drop_index("ix_sessions_device_id_hash", table_name="sessions")
        op.drop_column("sessions", "device_id_hash")

    client_columns = _columns("auth_clients")
    if "trusted_device_mfa_bypass" in client_columns:
        op.drop_column("auth_clients", "trusted_device_mfa_bypass")

    org_columns = _columns("organizations")
    if "trusted_device_mfa_bypass" in org_columns:
        op.drop_column("organizations", "trusted_device_mfa_bypass")
