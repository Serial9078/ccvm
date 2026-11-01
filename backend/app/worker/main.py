import time
import traceback

from sqlalchemy import or_
from sqlalchemy.orm import Session, aliased

from app.database.session import SessionLocal
from app.models.job import Job
from app.plugins.registry import (
    get_plugin,
    list_plugins,
)

WORKER_NAME = "ccvm-worker-01"
POLL_INTERVAL_SECONDS = 2

TERMINAL_SUCCESS_STATES = {
    "finished",
}

TERMINAL_FAILURE_STATES = {
    "failed",
    "skipped",
    "cancelled",
}


def mark_job_failed(
    db: Session,
    job_id: int,
    message: str,
) -> None:
    db.rollback()

    job = db.get(Job, job_id)

    if not job:
        return

    job.status = "failed"
    job.progress = 100
    job.message = message[:1000]
    job.worker = WORKER_NAME

    db.commit()


def skip_blocked_jobs(
    db: Session,
) -> int:
    queued_jobs = (
        db.query(Job)
        .filter(
            Job.status == "queued",
            Job.parent_job_id.is_not(None),
        )
        .order_by(Job.id.asc())
        .all()
    )

    skipped = 0

    for job in queued_jobs:
        parent = db.get(
            Job,
            job.parent_job_id,
        )

        if not parent:
            job.status = "skipped"
            job.progress = 100
            job.message = "Skipped because parent job " "does not exist"
            skipped += 1
            continue

        if parent.status in TERMINAL_FAILURE_STATES:
            job.status = "skipped"
            job.progress = 100
            job.message = (
                f"Skipped because parent job "
                f"{parent.id} ended with "
                f"status '{parent.status}'"
            )
            skipped += 1

    if skipped:
        db.commit()

    return skipped


def claim_next_job(
    db: Session,
) -> Job | None:
    parent = aliased(Job)

    job = (
        db.query(Job)
        .outerjoin(
            parent,
            Job.parent_job_id == parent.id,
        )
        .filter(
            Job.status == "queued",
            or_(
                Job.parent_job_id.is_(None),
                parent.status.in_(TERMINAL_SUCCESS_STATES),
            ),
        )
        .order_by(Job.id.asc())
        .with_for_update(
            skip_locked=True,
            of=Job,
        )
        .first()
    )

    if not job:
        return None

    job.status = "running"
    job.worker = WORKER_NAME
    job.message = f"Starting plugin: {job.plugin}"

    db.commit()
    db.refresh(job)

    return job


def process_job(
    db: Session,
    job: Job,
) -> None:
    plugin_name = job.plugin.strip().lower()
    handler = get_plugin(plugin_name)

    if not handler:
        available = ", ".join(list_plugins())

        mark_job_failed(
            db,
            job.id,
            (f"Unknown plugin '{plugin_name}'. " f"Available plugins: {available}"),
        )
        return

    print(
        (
            f"Processing job {job.id} "
            f"with plugin {plugin_name} "
            f"in pipeline "
            f"{job.pipeline_id or '-'}"
        ),
        flush=True,
    )

    try:
        handler(db, job)

    except Exception as exc:
        traceback.print_exc()

        mark_job_failed(
            db,
            job.id,
            (f"Plugin '{plugin_name}' failed: " f"{type(exc).__name__}: {exc}"),
        )


def worker() -> None:
    print(
        (
            f"CCVM plugin worker started "
            f"as {WORKER_NAME}. Plugins: "
            f"{', '.join(list_plugins())}"
        ),
        flush=True,
    )

    while True:
        db = SessionLocal()

        try:
            skip_blocked_jobs(db)

            job = claim_next_job(db)

            if job:
                process_job(db, job)

        except Exception as exc:
            db.rollback()
            traceback.print_exc()

            print(
                ("Worker loop error: " f"{type(exc).__name__}: " f"{exc}"),
                flush=True,
            )

        finally:
            db.close()

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    worker()
