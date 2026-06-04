"""Add durable OAuth grants.

Revision ID: 20260604_0002
Revises: 20260603_0001
Create Date: 2026-06-04
"""

from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa

from alembic import op
from app.models import json_type

revision: str = "20260604_0002"
down_revision: str | None = "20260603_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    if "oauth_grants" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "oauth_grants",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("client_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=True),
        sa.Column("audience", sa.String(length=300), nullable=True),
        sa.Column("scopes", json_type(), nullable=False),
        sa.Column("last_authorized_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(["client_id"], ["auth_clients.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_oauth_grants_client_id", "oauth_grants", ["client_id"])
    op.create_index("ix_oauth_grants_user_id", "oauth_grants", ["user_id"])
    op.create_index("ix_oauth_grants_user_client", "oauth_grants", ["user_id", "client_id"])


def downgrade() -> None:
    bind = op.get_bind()
    if "oauth_grants" not in sa.inspect(bind).get_table_names():
        return
    op.drop_index("ix_oauth_grants_user_client", table_name="oauth_grants")
    op.drop_index("ix_oauth_grants_user_id", table_name="oauth_grants")
    op.drop_index("ix_oauth_grants_client_id", table_name="oauth_grants")
    op.drop_table("oauth_grants")
