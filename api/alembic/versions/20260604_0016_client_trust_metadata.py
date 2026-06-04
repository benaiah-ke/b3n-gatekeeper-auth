"""Add client trust metadata."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0016"
down_revision = "20260604_0015"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    columns = _columns("auth_clients")
    if "publisher_name" not in columns:
        op.add_column("auth_clients", sa.Column("publisher_name", sa.String(length=160), nullable=True))
    if "verified_at" not in columns:
        op.add_column("auth_clients", sa.Column("verified_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    columns = _columns("auth_clients")
    if "verified_at" in columns:
        op.drop_column("auth_clients", "verified_at")
    if "publisher_name" in columns:
        op.drop_column("auth_clients", "publisher_name")
