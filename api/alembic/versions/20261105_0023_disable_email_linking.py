"""turn off email linking on existing OAuth providers

Data only. Downgrade is a no-op: the previous values are not recorded, and
turning email linking back on for a provider is an operator decision.

Revision ID: 20261105_0023
Revises: 20261105_0022
Create Date: 2026-11-05
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20261105_0023"
down_revision = "20261105_0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "oauth_providers" in set(sa.inspect(op.get_bind()).get_table_names()):
        op.execute(sa.text("UPDATE oauth_providers SET allow_email_linking = :off").bindparams(off=False))


def downgrade() -> None:
    pass
