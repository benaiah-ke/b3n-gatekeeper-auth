"""Add organization audit retention policy."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0015"
down_revision = "20260604_0014"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    columns = _columns("organizations")
    if "audit_retention_days" not in columns:
        op.add_column("organizations", sa.Column("audit_retention_days", sa.Integer(), nullable=True))


def downgrade() -> None:
    columns = _columns("organizations")
    if "audit_retention_days" in columns:
        op.drop_column("organizations", "audit_retention_days")
