from sqlalchemy import ForeignKey, Integer, String, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), nullable=False)
    domain_id: Mapped[int | None] = mapped_column(ForeignKey("domains.id"), nullable=True)
    subdomain_id: Mapped[int | None] = mapped_column(ForeignKey("subdomains.id"), nullable=True)

    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(100), nullable=True)
    alive: Mapped[bool] = mapped_column(Boolean, default=False)

    source: Mapped[str | None] = mapped_column(String(100), nullable=True)

    customer = relationship("Customer")
    domain = relationship("Domain")
    subdomain = relationship("Subdomain")
