"""Immutable, operator-only Windows patch catalog and inventory assessments."""

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database.session import Base


class WindowsPatchCatalog(Base):
    __tablename__ = "windows_patch_catalogs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    retrieved_at = mapped_column(DateTime(timezone=True), nullable=False)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class HostAssessment(Base):
    __tablename__ = "host_assessments"
    __table_args__ = (
        UniqueConstraint(
            "host_audit_id",
            "catalog_id",
            "engine_version",
            "evidence_sha256",
            name="uq_host_assessment_evidence_catalog_engine",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    host_audit_id: Mapped[int] = mapped_column(ForeignKey("host_audits.id"), index=True)
    catalog_id: Mapped[int | None] = mapped_column(ForeignKey("windows_patch_catalogs.id"))
    engine_version: Mapped[str] = mapped_column(String(40), nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    result: Mapped[dict] = mapped_column(JSON, nullable=False)
    evaluated_at = mapped_column(DateTime(timezone=True), nullable=False)
