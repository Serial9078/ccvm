"""Use a bounded SHA-256 identity index for long discovered URLs.

Revision ID: bc64c6f0e217
Revises: 7f91c32a60d1
Create Date: 2026-11-01
"""

import sqlalchemy as sa

from alembic import op

revision = "bc64c6f0e217"
down_revision = "7f91c32a60d1"
branch_labels = None
depends_on = None

# Core immutable functions only. Escaping backslashes before bytea conversion
# preserves the entire URL literally without requiring a pgcrypto extension.
URL_DIGEST = "sha256(CAST(replace(url, chr(92), chr(92) || chr(92)) AS bytea))"


def upgrade() -> None:
    # PostgreSQL transactional DDL retains the old constraint if building the
    # replacement fails. No URL rows, IDs or dependent records are changed.
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute("SET LOCAL statement_timeout = '120s'")
    op.create_index(
        "uq_urls_domain_url_sha256", "urls", ["domain_id", sa.text(URL_DIGEST)], unique=True
    )
    op.drop_constraint("uq_urls_domain_url", "urls", type_="unique")


def downgrade() -> None:
    # Restore the old constraint first. If long values prevent it, the whole
    # transaction fails and the SHA-256 index and data remain intact.
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute("SET LOCAL statement_timeout = '120s'")
    op.create_unique_constraint("uq_urls_domain_url", "urls", ["domain_id", "url"])
    op.drop_index("uq_urls_domain_url_sha256", table_name="urls")
