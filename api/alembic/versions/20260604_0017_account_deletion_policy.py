"""Add account deletion policy."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0017"
down_revision = "20260604_0016"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    columns = _columns("organizations")
    if "allow_user_hard_delete" not in columns:
        op.add_column(
            "organizations",
            sa.Column("allow_user_hard_delete", sa.Boolean(), nullable=False, server_default=sa.false()),
        )


def downgrade() -> None:
    columns = _columns("organizations")
    if "allow_user_hard_delete" in columns:
        op.drop_column("organizations", "allow_user_hard_delete")
