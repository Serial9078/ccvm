from sqlalchemy import (
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from app.database.session import Base
from app.database.url_identity import url_digest


class Url(Base):
    __tablename__ = "urls"

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

    __table_args__ = (
        Index("uq_urls_domain_url_sha256", "domain_id", url_digest(url), unique=True),
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

    detail = relationship(
        "UrlDetail",
        back_populates="url",
        uselist=False,
        cascade="all, delete-orphan",
    )

    security = relationship(
        "UrlSecurity",
        back_populates="url",
        uselist=False,
        cascade="all, delete-orphan",
    )

    screenshot = relationship(
        "UrlScreenshot",
        back_populates="url",
        uselist=False,
        cascade="all, delete-orphan",
    )
