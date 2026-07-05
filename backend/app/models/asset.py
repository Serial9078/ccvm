from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from app.database.session import Base

class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), nullable=False)
    target: Mapped[str] = mapped_column(String(1024), nullable=False)
    type: Mapped[str] = mapped_column(String(50), default="url")
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())

    customer = relationship("Customer", back_populates="assets")
