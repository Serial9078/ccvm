from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Subdomain(Base):
    __tablename__ = "subdomains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), nullable=False)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)

    domain = relationship("Domain")
    customer = relationship("Customer")
