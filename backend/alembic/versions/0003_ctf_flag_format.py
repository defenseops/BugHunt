"""add ctf_flag_format to scans

Revision ID: 0003_ctf_flag_format
Revises: 0002_report_status
Create Date: 2026-05-06
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("ctf_flag_format", sa.String(200), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "ctf_flag_format")
