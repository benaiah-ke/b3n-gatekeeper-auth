"""add oauth provider management

Revision ID: 20260604_0011
Revises: 20260604_0010
Create Date: 2026-06-04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0011"
down_revision = "20260604_0010"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if "oauth_providers" in _tables():
        return
    op.create_table(
        "oauth_providers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("provider_id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("client_id", sa.String(length=240), nullable=False),
        sa.Column("client_secret_encrypted", sa.Text(), nullable=True),
        sa.Column("authorization_url", sa.String(length=500), nullable=False),
        sa.Column("token_url", sa.String(length=500), nullable=False),
        sa.Column("userinfo_url", sa.String(length=500), nullable=False),
        sa.Column("redirect_uri", sa.String(length=500), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("subject_claim", sa.String(length=120), nullable=False),
        sa.Column("email_claim", sa.String(length=120), nullable=False),
        sa.Column("name_claim", sa.String(length=120), nullable=False),
        sa.Column("email_verified_claim", sa.String(length=120), nullable=False),
        sa.Column("allow_email_linking", sa.Boolean(), nullable=False),
        sa.Column("require_verified_email", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider_id"),
    )
    op.create_index("ix_oauth_providers_provider_id", "oauth_providers", ["provider_id"], unique=True)


def downgrade() -> None:
    if "oauth_providers" not in _tables():
        return
    op.drop_index("ix_oauth_providers_provider_id", table_name="oauth_providers")
    op.drop_table("oauth_providers")
