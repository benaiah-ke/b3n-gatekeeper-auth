"""add organization mfa policy

Revision ID: 20260604_0008
Revises: 20260604_0007
Create Date: 2026-06-04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0008"
down_revision = "20260604_0007"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    if "require_mfa" not in _columns("organizations"):
        op.add_column(
            "organizations",
            sa.Column("require_mfa", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        with op.batch_alter_table("organizations") as batch_op:
            batch_op.alter_column(
                "require_mfa",
                server_default=None,
                existing_type=sa.Boolean(),
                existing_nullable=False,
            )


def downgrade() -> None:
    if "require_mfa" in _columns("organizations"):
        op.drop_column("organizations", "require_mfa")
