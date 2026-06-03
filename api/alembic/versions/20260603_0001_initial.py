"""Initial GateKeeper schema.

Revision ID: 20260603_0001
Revises:
Create Date: 2026-06-03
"""

from __future__ import annotations

from typing import Sequence

from alembic import op

from app.database import Base
from app import models  # noqa: F401

revision: str = "20260603_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())

