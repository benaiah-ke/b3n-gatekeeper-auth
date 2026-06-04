"""Add admin step-up MFA policy."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260604_0013"
down_revision = "20260604_0012"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    org_columns = _columns("organizations")
    if "admin_step_up_mfa_required" not in org_columns:
        op.add_column(
            "organizations",
            sa.Column("admin_step_up_mfa_required", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        with op.batch_alter_table("organizations") as batch_op:
            batch_op.alter_column(
                "admin_step_up_mfa_required",
                server_default=None,
                existing_type=sa.Boolean(),
                existing_nullable=False,
            )


def downgrade() -> None:
    org_columns = _columns("organizations")
    if "admin_step_up_mfa_required" in org_columns:
        op.drop_column("organizations", "admin_step_up_mfa_required")
