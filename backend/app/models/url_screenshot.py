from sqlalchemy import (
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


class UrlScreenshot(Base):
    __tablename__ = "url_screenshots"

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

    screenshot_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    filename: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    title: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    final_url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    status_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    viewport_width: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1440,
    )

    viewport_height: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=900,
    )

    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="playwright",
    )

    url = relationship(
        "Url",
        back_populates="screenshot",
    )
