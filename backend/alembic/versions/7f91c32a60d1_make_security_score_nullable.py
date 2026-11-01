"""make security score nullable

Revision ID: 7f91c32a60d1
Revises: 2d1a72872070
Create Date: 2026-07-24
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "7f91c32a60d1"
down_revision: Union[str, None] = "2d1a72872070"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "url_security",
        "security_score",
        existing_type=sa.Integer(),
        nullable=True,
        server_default=None,
    )


def downgrade() -> None:
    op.execute("""
        UPDATE url_security
        SET security_score = 0
        WHERE security_score IS NULL
        """)

    op.alter_column(
        "url_security",
        "security_score",
        existing_type=sa.Integer(),
        nullable=False,
        server_default=sa.text("0"),
    )
