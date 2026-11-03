"""Add scoped network scans, observations and structured service inventory.

Revision ID: f93b70a4e628
Revises: d91e6a2f4c80
"""

import sqlalchemy as sa

from alembic import op

revision = "f93b70a4e628"
down_revision = "d91e6a2f4c80"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ports", sa.Column("state", sa.String(30), nullable=False, server_default="open"))
    for name, kind in (
        ("product", sa.Text()),
        ("version", sa.Text()),
        ("tunnel", sa.String(30)),
        ("cpe", sa.JSON()),
    ):
        op.add_column("ports", sa.Column(name, kind, nullable=True))
    op.create_table(
        "network_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("customer_id", sa.Integer(), sa.ForeignKey("customers.id"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("pipeline_id", sa.String(36), nullable=False, unique=True),
        sa.Column(
            "discovery_job_id", sa.Integer(), sa.ForeignKey("jobs.id"), nullable=False, unique=True
        ),
        sa.Column(
            "audit_job_id", sa.Integer(), sa.ForeignKey("jobs.id"), nullable=False, unique=True
        ),
        sa.Column("target", sa.String(100), nullable=False),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("exclusions", sa.JSON(), nullable=False),
        sa.Column("profile", sa.String(20), nullable=False),
        sa.Column("ports", sa.String(2000), nullable=True),
        sa.Column("rate", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("scope_sha256", sa.String(64), nullable=False),
        sa.Column("scanned_ports", sa.JSON(), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("hosts_checked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_services", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("scanner_version", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_network_scans_customer_id", "network_scans", ["customer_id"])
    op.create_table(
        "network_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("network_scans.id"), nullable=False),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("ip_address", sa.String(64), nullable=False),
        sa.Column("services", sa.JSON(), nullable=False),
        sa.UniqueConstraint("scan_id", "ip_address", name="uq_network_scan_ip"),
    )
    op.create_index("ix_network_observations_scan_id", "network_observations", ["scan_id"])


def downgrade():
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE network_scans, network_observations, ports IN ACCESS EXCLUSIVE MODE"
        )
    # This is data retention, not an automatic destructive cleanup.
    if connection.scalar(sa.text("SELECT count(*) FROM network_scans")) or connection.scalar(
        sa.text(
            "SELECT count(*) FROM ports WHERE product IS NOT NULL OR version IS NOT NULL "
            "OR tunnel IS NOT NULL OR cpe IS NOT NULL OR state <> 'open'"
        )
    ):
        raise RuntimeError("Network scan/service evidence exists; downgrade would discard it")
    op.drop_table("network_observations")
    op.drop_table("network_scans")
    for name in ("cpe", "tunnel", "version", "product", "state"):
        op.drop_column("ports", name)
