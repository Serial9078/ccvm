"""Preserve complete finding URLs without a VARCHAR length limit.

Revision ID: d91e6a2f4c80
Revises: bc64c6f0e217
Create Date: 2026-11-01
"""

import sqlalchemy as sa

from alembic import op

revision = "d91e6a2f4c80"
down_revision = "bc64c6f0e217"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute("SET LOCAL statement_timeout = '120s'")
    op.alter_column("findings", "matched_at", existing_type=sa.String(1024), type_=sa.Text())


def downgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute("SET LOCAL statement_timeout = '120s'")
    # ALTER TYPE may silently truncate when narrowing TEXT to VARCHAR. Hold
    # the same lock as the alteration and explicitly reject any lossy downgrade.
    op.execute("LOCK TABLE findings IN ACCESS EXCLUSIVE MODE")
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM findings WHERE char_length(matched_at) > 1024) THEN
                RAISE EXCEPTION 'Cannot restore VARCHAR(1024): finding URLs exceed 1024 characters';
            END IF;
        END $$
        """)
    op.alter_column("findings", "matched_at", existing_type=sa.Text(), type_=sa.String(1024))
