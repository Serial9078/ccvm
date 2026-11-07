"""Retain official catalog snapshots and private Windows patch assessments.

Revision ID: c8f3a0e2b741
Revises: b7e2c9d1a630
"""

import sqlalchemy as sa

from alembic import op

revision = "c8f3a0e2b741"
down_revision = "b7e2c9d1a630"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "windows_patch_catalogs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_table(
        "host_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("customer_id", sa.Integer(), sa.ForeignKey("customers.id"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("host_audit_id", sa.Integer(), sa.ForeignKey("host_audits.id"), nullable=False),
        sa.Column("catalog_id", sa.Integer(), sa.ForeignKey("windows_patch_catalogs.id")),
        sa.Column("engine_version", sa.String(40), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "host_audit_id",
            "catalog_id",
            "engine_version",
            "evidence_sha256",
            name="uq_host_assessment_evidence_catalog_engine",
        ),
    )
    op.create_index("ix_host_assessments_customer_id", "host_assessments", ["customer_id"])
    op.create_index("ix_host_assessments_host_audit_id", "host_assessments", ["host_audit_id"])


def downgrade():
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE host_assessments, windows_patch_catalogs IN ACCESS EXCLUSIVE MODE"
        )
    if connection.scalar(sa.text("SELECT count(*) FROM host_assessments")) or connection.scalar(
        sa.text("SELECT count(*) FROM windows_patch_catalogs")
    ):
        raise RuntimeError("Patch catalog/assessment history exists; downgrade would discard it")
    op.drop_index("ix_host_assessments_host_audit_id", table_name="host_assessments")
    op.drop_index("ix_host_assessments_customer_id", table_name="host_assessments")
    op.drop_table("host_assessments")
    op.drop_table("windows_patch_catalogs")
