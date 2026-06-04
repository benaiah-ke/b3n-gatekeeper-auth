"""Add client app metadata."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0014"
down_revision = "20260604_0013"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    columns = _columns("auth_clients")
    if "description" not in columns:
        op.add_column("auth_clients", sa.Column("description", sa.Text(), nullable=True))
    if "logo_url" not in columns:
        op.add_column("auth_clients", sa.Column("logo_url", sa.String(length=500), nullable=True))
    if "homepage_url" not in columns:
        op.add_column("auth_clients", sa.Column("homepage_url", sa.String(length=500), nullable=True))
    if "privacy_policy_url" not in columns:
        op.add_column("auth_clients", sa.Column("privacy_policy_url", sa.String(length=500), nullable=True))
    if "terms_url" not in columns:
        op.add_column("auth_clients", sa.Column("terms_url", sa.String(length=500), nullable=True))


def downgrade() -> None:
    columns = _columns("auth_clients")
    for column in ["terms_url", "privacy_policy_url", "homepage_url", "logo_url", "description"]:
        if column in columns:
            op.drop_column("auth_clients", column)
