"""Add encrypted, scoped credentials and authenticated inventory history.

Revision ID: a4c1d8e7f209
Revises: f93b70a4e628
"""

import sqlalchemy as sa

from alembic import op

revision = "a4c1d8e7f209"
down_revision = "f93b70a4e628"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("customer_id", sa.Integer(), sa.ForeignKey("customers.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("allowed_cidrs", sa.JSON(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_credentials_customer_id", "audit_credentials", ["customer_id"])
    op.create_table(
        "host_audits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("customer_id", sa.Integer(), sa.ForeignKey("customers.id"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column(
            "credential_id",
            sa.Integer(),
            sa.ForeignKey("audit_credentials.id"),
            nullable=False,
        ),
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey("jobs.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("target", sa.String(64), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("ssh_fingerprint", sa.String(60), nullable=True),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("scope_sha256", sa.String(64), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("inventory", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_host_audits_customer_id", "host_audits", ["customer_id"])


def downgrade():
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE host_audits, audit_credentials IN ACCESS EXCLUSIVE MODE"
        )
    if connection.scalar(sa.text("SELECT count(*) FROM host_audits")) or connection.scalar(
        sa.text("SELECT count(*) FROM audit_credentials")
    ):
        raise RuntimeError("Credential/inventory history exists; downgrade would discard it")
    op.drop_table("host_audits")
    op.drop_table("audit_credentials")
