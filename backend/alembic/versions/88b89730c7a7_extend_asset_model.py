"""extend asset model

Revision ID: 88b89730c7a7
Revises: 1449178d5497
Create Date: 2026-07-05
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "88b89730c7a7"
down_revision: Union[str, None] = "1449178d5497"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("name", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("hostname", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("fqdn", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("ip_address", sa.String(length=64), nullable=True))
    op.add_column(
        "assets",
        sa.Column("environment", sa.String(length=50), nullable=False, server_default="production"),
    )
    op.add_column(
        "assets",
        sa.Column("criticality", sa.String(length=50), nullable=False, server_default="medium"),
    )
    op.add_column("assets", sa.Column("owner", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("assets", sa.Column("tags", sa.String(length=1024), nullable=True))
    op.add_column(
        "assets",
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "updated_at")
    op.drop_column("assets", "tags")
    op.drop_column("assets", "description")
    op.drop_column("assets", "owner")
    op.drop_column("assets", "criticality")
    op.drop_column("assets", "environment")
    op.drop_column("assets", "ip_address")
    op.drop_column("assets", "fqdn")
    op.drop_column("assets", "hostname")
    op.drop_column("assets", "name")
