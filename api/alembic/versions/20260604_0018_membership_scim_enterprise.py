"""Add membership SCIM enterprise profile."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0018"
down_revision = "20260604_0017"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    columns = _columns("memberships")
    if "scim_external_id" not in columns:
        op.add_column("memberships", sa.Column("scim_external_id", sa.String(length=240), nullable=True))
    if "scim_enterprise_profile" not in columns:
        op.add_column("memberships", sa.Column("scim_enterprise_profile", sa.JSON(), nullable=True))


def downgrade() -> None:
    columns = _columns("memberships")
    if "scim_enterprise_profile" in columns:
        op.drop_column("memberships", "scim_enterprise_profile")
    if "scim_external_id" in columns:
        op.drop_column("memberships", "scim_external_id")
