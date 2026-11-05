"""add install claims guarding the first-owner signup

Revision ID: 20261105_0022
Revises: 20261105_0021
Create Date: 2026-11-05
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20261105_0022"
down_revision = "20261105_0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "install_claims" not in set(sa.inspect(op.get_bind()).get_table_names()):
        op.create_table(
            "install_claims",
            sa.Column("name", sa.String(length=40), primary_key=True),
            sa.Column("user_id", sa.String(length=36), nullable=True),
            sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        )


def downgrade() -> None:
    if "install_claims" in set(sa.inspect(op.get_bind()).get_table_names()):
        op.drop_table("install_claims")
