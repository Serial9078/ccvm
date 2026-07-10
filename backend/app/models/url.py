from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Url(Base):
    __tablename__ = "urls"
    __table_args__ = (
        UniqueConstraint(
            "domain_id",
            "url",
            name="uq_urls_domain_url",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    customer_id: Mapped[int] = mapped_column(
        ForeignKey("customers.id"),
        nullable=False,
        index=True,
    )

    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domains.id"),
        nullable=False,
        index=True,
    )

    host_id: Mapped[int | None] = mapped_column(
        ForeignKey("hosts.id"),
        nullable=True,
        index=True,
    )

    url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    method: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="GET",
    )

    status_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    content_type: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="katana",
    )

    customer = relationship("Customer")
    domain = relationship("Domain")
    host = relationship("Host")
