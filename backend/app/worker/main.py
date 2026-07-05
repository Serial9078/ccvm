import time

from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.models.job import Job


def process_job(db: Session, job: Job):
    print(f"Starting job {job.id}")

    job.status = "running"
    job.progress = 5
    db.commit()

    time.sleep(2)

    job.progress = 25
    db.commit()

    time.sleep(2)

    job.progress = 50
    db.commit()

    time.sleep(2)

    job.progress = 75
    db.commit()

    time.sleep(2)

    job.progress = 100
    job.status = "finished"
    job.message = "Dummy scan finished successfully"

    db.commit()

    print(f"Finished job {job.id}")


def worker():
    while True:

        db = SessionLocal()

        job = (
            db.query(Job)
            .filter(Job.status == "queued")
            .order_by(Job.id.asc())
            .first()
        )

        if job:
            process_job(db, job)

        db.close()

        time.sleep(2)


if __name__ == "__main__":
    worker()
