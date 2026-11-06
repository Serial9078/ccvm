"""Retain an explicit WinRM transport on each immutable inventory run.

Revision ID: b7e2c9d1a630
Revises: a4c1d8e7f209
"""

import sqlalchemy as sa

from alembic import op

revision = "b7e2c9d1a630"
down_revision = "a4c1d8e7f209"
branch_labels = None
depends_on = None


def upgrade():
    # Every retained run predates HTTP support. No credentials, evidence,
    # ciphertext or frozen scope hash are rewritten by this additive migration.
    op.add_column(
        "host_audits",
        sa.Column("winrm_transport", sa.String(20), nullable=False, server_default="https"),
    )


def downgrade():
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("LOCK TABLE host_audits IN ACCESS EXCLUSIVE MODE")
    if connection.scalar(
        sa.text("SELECT count(*) FROM host_audits WHERE winrm_transport <> 'https'")
    ):
        raise RuntimeError("HTTP WinRM history exists; downgrade would discard its transport")
    op.drop_column("host_audits", "winrm_transport")
