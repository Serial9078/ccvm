from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database.session import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("jobs.id"), nullable=True)

    scanner: Mapped[str] = mapped_column(String(100), default="nuclei")
    template_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="info")

    host: Mapped[str | None] = mapped_column(String(512), nullable=True)
    matched_at: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    reference: Mapped[str | None] = mapped_column(Text, nullable=True)

    cve: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_score: Mapped[str | None] = mapped_column(String(50), nullable=True)

    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(50), default="open")

    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
