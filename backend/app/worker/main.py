import subprocess
import time

from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.models.asset import Asset
from app.models.job import Job


def run_dummy(db: Session, job: Job):
    for progress in [5, 25, 50, 75, 100]:
        job.status = "running"
        job.progress = progress
        job.message = f"Dummy job progress {progress}%"
        db.commit()
        time.sleep(2)

    job.status = "finished"
    job.message = "Dummy scan finished successfully"
    db.commit()


def run_nuclei(db: Session, job: Job):
    asset = db.query(Asset).filter(Asset.id == job.asset_id).first()

    if not asset:
        job.status = "failed"
        job.message = "Asset not found"
        db.commit()
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Starting Nuclei scan for {asset.target}"
    db.commit()

    cmd = [
        "docker",
        "exec",
        "ccvm-nuclei",
        "nuclei",
        "-u",
        asset.target,
        "-severity",
        "critical,high,medium",
        "-jsonl",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    job.progress = 100

    if result.returncode == 0:
        job.status = "finished"
        output = result.stdout.strip()
        job.message = output[-3000:] if output else "Nuclei scan finished. No findings."
    else:
        job.status = "failed"
        job.message = result.stderr.strip()[-3000:] or "Nuclei scan failed"

    db.commit()


def process_job(db: Session, job: Job):
    job.worker = "ccvm-worker-01"
    db.commit()

    if job.plugin == "nuclei":
        run_nuclei(db, job)
    else:
        run_dummy(db, job)


def worker():
    print("CCVM worker started")

    while True:
        db = SessionLocal()

        job = (
            db.query(Job)
            .filter(Job.status == "queued")
            .order_by(Job.id.asc())
            .first()
        )

        if job:
            print(f"Processing job {job.id} with plugin {job.plugin}")
            process_job(db, job)

        db.close()
        time.sleep(2)


if __name__ == "__main__":
    worker()
