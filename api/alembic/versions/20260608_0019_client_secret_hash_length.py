"""widen client secret hash column

Revision ID: 20260608_0019
Revises: 20260604_0018
Create Date: 2026-06-08
"""

from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260608_0019"
down_revision: str | None = "20260604_0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("auth_clients") as batch_op:
        batch_op.alter_column(
            "client_secret_hash",
            existing_type=sa.String(length=80),
            type_=sa.String(length=255),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("auth_clients") as batch_op:
        batch_op.alter_column(
            "client_secret_hash",
            existing_type=sa.String(length=255),
            type_=sa.String(length=80),
            existing_nullable=True,
        )
