"""Operator-only credentials and immutable, customer-bound host inventory runs."""

import uuid

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database.session import Base


class AuditCredential(Base):
    __tablename__ = "audit_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(20))
    username: Mapped[str] = mapped_column(String(255))
    allowed_cidrs: Mapped[list] = mapped_column(JSON)
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class HostAudit(Base):
    __tablename__ = "host_audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    credential_id: Mapped[int] = mapped_column(ForeignKey("audit_credentials.id"))
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), unique=True)
    target: Mapped[str] = mapped_column(String(64))
    port: Mapped[int] = mapped_column(Integer)
    ssh_fingerprint: Mapped[str | None] = mapped_column(String(60))
    winrm_transport: Mapped[str] = mapped_column(
        String(20), default="https", server_default="https"
    )
    mode: Mapped[str] = mapped_column(String(20))
    scope_sha256: Mapped[str] = mapped_column(String(64))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    inventory: Mapped[dict | None] = mapped_column(JSON(none_as_null=True))
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at = mapped_column(DateTime(timezone=True))

    credential = relationship("AuditCredential")
    job = relationship("Job")
