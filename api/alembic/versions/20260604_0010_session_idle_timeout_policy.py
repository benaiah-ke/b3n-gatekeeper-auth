"""add session idle timeout policy

Revision ID: 20260604_0010
Revises: 20260604_0009
Create Date: 2026-06-04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0010"
down_revision = "20260604_0009"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    org_columns = _columns("organizations")
    if "session_idle_timeout_minutes" not in org_columns:
        op.add_column("organizations", sa.Column("session_idle_timeout_minutes", sa.Integer(), nullable=True))

    client_columns = _columns("auth_clients")
    if "session_idle_timeout_minutes" not in client_columns:
        op.add_column("auth_clients", sa.Column("session_idle_timeout_minutes", sa.Integer(), nullable=True))

    session_columns = _columns("sessions")
    if "last_seen_at" not in session_columns:
        op.add_column("sessions", sa.Column("last_seen_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    session_columns = _columns("sessions")
    if "last_seen_at" in session_columns:
        op.drop_column("sessions", "last_seen_at")

    client_columns = _columns("auth_clients")
    if "session_idle_timeout_minutes" in client_columns:
        op.drop_column("auth_clients", "session_idle_timeout_minutes")

    org_columns = _columns("organizations")
    if "session_idle_timeout_minutes" in org_columns:
        op.drop_column("organizations", "session_idle_timeout_minutes")
