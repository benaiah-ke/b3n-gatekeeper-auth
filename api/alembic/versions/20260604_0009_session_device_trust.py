"""add session device trust metadata

Revision ID: 20260604_0009
Revises: 20260604_0008
Create Date: 2026-06-04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0009"
down_revision = "20260604_0008"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    columns = _columns("sessions")
    if "device_label" not in columns:
        op.add_column("sessions", sa.Column("device_label", sa.String(length=120), nullable=True))
    if "trusted_at" not in columns:
        op.add_column("sessions", sa.Column("trusted_at", sa.DateTime(), nullable=True))
    if "trusted_until" not in columns:
        op.add_column("sessions", sa.Column("trusted_until", sa.DateTime(), nullable=True))


def downgrade() -> None:
    columns = _columns("sessions")
    if "trusted_until" in columns:
        op.drop_column("sessions", "trusted_until")
    if "trusted_at" in columns:
        op.drop_column("sessions", "trusted_at")
    if "device_label" in columns:
        op.drop_column("sessions", "device_label")
