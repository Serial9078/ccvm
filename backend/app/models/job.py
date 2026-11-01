import uuid

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    uuid: Mapped[str] = mapped_column(
        String(64),
        default=lambda: str(uuid.uuid4()),
        unique=True,
        nullable=False,
    )

    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id"),
        nullable=True,
    )

    domain_id: Mapped[int | None] = mapped_column(
        ForeignKey("domains.id"),
        nullable=True,
    )

    parent_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("jobs.id"),
        nullable=True,
        index=True,
    )

    pipeline_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True,
    )

    plugin: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="queued",
        nullable=False,
    )

    progress: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    message: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )

    worker: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    asset = relationship("Asset")
    domain = relationship("Domain")

    parent_job: Mapped["Job | None"] = relationship(
        "Job",
        remote_side=[id],
        foreign_keys=[parent_job_id],
        back_populates="child_jobs",
    )

    child_jobs: Mapped[list["Job"]] = relationship(
        "Job",
        foreign_keys=[parent_job_id],
        back_populates="parent_job",
    )
