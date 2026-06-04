"""Link sessions to auth clients.

Revision ID: 20260604_0003
Revises: 20260604_0002
Create Date: 2026-06-04
"""

from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260604_0003"
down_revision: str | None = "20260604_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _session_columns() -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns("sessions")}


def upgrade() -> None:
    if "client_id" in _session_columns():
        return
    op.add_column("sessions", sa.Column("client_id", sa.String(length=36), nullable=True))
    op.create_index("ix_sessions_client_id", "sessions", ["client_id"])


def downgrade() -> None:
    if "client_id" not in _session_columns():
        return
    op.drop_index("ix_sessions_client_id", table_name="sessions")
    op.drop_column("sessions", "client_id")
