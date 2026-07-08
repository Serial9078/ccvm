from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Technology(Base):
    __tablename__ = "technologies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)

    host = relationship("Host")
