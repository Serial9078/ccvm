from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), nullable=False)

    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), default="tcp")
    service: Mapped[str | None] = mapped_column(String(100), nullable=True)
    banner: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)

    host = relationship("Host")
