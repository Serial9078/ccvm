import uuid
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database.session import Base


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))

    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)

    plugin: Mapped[str] = mapped_column(String(100), default="dummy")
    status: Mapped[str] = mapped_column(String(50), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)

    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at = mapped_column(DateTime(timezone=True), nullable=True)
