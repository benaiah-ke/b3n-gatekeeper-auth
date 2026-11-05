"""store the scopes and audience granted at login on sessions

Revision ID: 20261105_0021
Revises: 20260725_0020
Create Date: 2026-11-05
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "20261105_0021"
down_revision = "20260725_0020"
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    return sa.JSON().with_variant(JSONB, "postgresql")


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    columns = _columns("sessions")
    if "scopes" not in columns:
        op.add_column("sessions", sa.Column("scopes", _json_type(), nullable=True))
    if "audience" not in columns:
        op.add_column("sessions", sa.Column("audience", _json_type(), nullable=True))


def downgrade() -> None:
    columns = _columns("sessions")
    if "audience" in columns:
        op.drop_column("sessions", "audience")
    if "scopes" in columns:
        op.drop_column("sessions", "scopes")
