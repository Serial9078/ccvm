import uuid

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database.session import Base


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String, unique=True, index=True, default=lambda: str(uuid.uuid4()))

    name = Column(String, nullable=False)
    company = Column(String, nullable=True)
    street = Column(String, nullable=True)
    zip = Column(String, nullable=True)
    city = Column(String, nullable=True)
    country = Column(String, nullable=True, default="Germany")

    contact_name = Column(String, nullable=True)
    contact_email = Column(String, nullable=True)
    contact_phone = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    assets = relationship("Asset", back_populates="customer", cascade="all, delete-orphan")

    domains = relationship(
        "Domain",
        back_populates="customer",
        cascade="all, delete-orphan",
    )

