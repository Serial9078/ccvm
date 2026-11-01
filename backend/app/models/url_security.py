from sqlalchemy import (
    Boolean,
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


class UrlSecurity(Base):
    __tablename__ = "url_security"

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

    checked_url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    status_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    server: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    powered_by: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    strict_transport_security: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    content_security_policy: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    x_frame_options: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    x_content_type_options: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    referrer_policy: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    permissions_policy: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    cache_control: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    etag: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    last_modified: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    hsts_present: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    csp_present: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    xfo_present: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    xcto_present: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    referrer_policy_present: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    permissions_policy_present: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    missing_headers: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    security_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="headerprobe",
    )

    url = relationship(
        "Url",
        back_populates="security",
    )
