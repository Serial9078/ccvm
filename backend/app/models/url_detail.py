from sqlalchemy import (
    Float,
    ForeignKey,
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


class UrlDetail(Base):
    __tablename__ = "url_details"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    url_id: Mapped[int] = mapped_column(
        ForeignKey(
            "urls.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        unique=True,
        index=True,
    )

    status_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    title: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    content_type: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    content_length: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    webserver: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    final_url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    response_time_seconds: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    method: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="GET",
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="httpx",
    )

    url = relationship(
        "Url",
        back_populates="detail",
    )
