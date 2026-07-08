import uuid

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    uuid: Mapped[str] = mapped_column(String(64), default=lambda: str(uuid.uuid4()), unique=True)

    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    domain_id: Mapped[int | None] = mapped_column(ForeignKey("domains.id"), nullable=True)

    plugin: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    worker: Mapped[str | None] = mapped_column(String(100), nullable=True)

    asset = relationship("Asset")
    domain = relationship("Domain")
