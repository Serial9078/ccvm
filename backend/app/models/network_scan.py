from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database.session import Base


class NetworkScan(Base):
    __tablename__ = "network_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), nullable=False, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    pipeline_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    discovery_job_id: Mapped[int] = mapped_column(
        ForeignKey("jobs.id"), unique=True, nullable=False
    )
    audit_job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), unique=True, nullable=False)
    target: Mapped[str] = mapped_column(String(100), nullable=False)
    targets: Mapped[list] = mapped_column(JSON, nullable=False)
    exclusions: Mapped[list] = mapped_column(JSON, nullable=False)
    profile: Mapped[str] = mapped_column(String(20), nullable=False)
    ports: Mapped[str | None] = mapped_column(String(2000))
    rate: Mapped[int] = mapped_column(Integer, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    scope_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    scanned_ports: Mapped[list | None] = mapped_column(JSON(none_as_null=True))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    hosts_checked: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    open_services: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    findings_created: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    findings_updated: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    scanner_version: Mapped[str | None] = mapped_column(String(100))
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())

    discovery_job = relationship("Job", foreign_keys=[discovery_job_id])
    audit_job = relationship("Job", foreign_keys=[audit_job_id])
    observations = relationship(
        "NetworkObservation", back_populates="scan", order_by="NetworkObservation.id"
    )


class NetworkObservation(Base):
    __tablename__ = "network_observations"
    __table_args__ = (UniqueConstraint("scan_id", "ip_address", name="uq_network_scan_ip"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("network_scans.id"), nullable=False, index=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    services: Mapped[list] = mapped_column(JSON, nullable=False)
    scan = relationship("NetworkScan", back_populates="observations")
