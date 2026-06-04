"""add user totp mfa fields

Revision ID: 20260604_0004
Revises: 20260604_0003
Create Date: 2026-06-04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0004"
down_revision = "20260604_0003"
branch_labels = None
depends_on = None


def _user_columns() -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns("users")}


def upgrade() -> None:
    columns = _user_columns()
    if "mfa_totp_secret_encrypted" not in columns:
        op.add_column("users", sa.Column("mfa_totp_secret_encrypted", sa.Text(), nullable=True))
    if "mfa_totp_enabled_at" not in columns:
        op.add_column("users", sa.Column("mfa_totp_enabled_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    columns = _user_columns()
    if "mfa_totp_enabled_at" in columns:
        op.drop_column("users", "mfa_totp_enabled_at")
    if "mfa_totp_secret_encrypted" in columns:
        op.drop_column("users", "mfa_totp_secret_encrypted")
