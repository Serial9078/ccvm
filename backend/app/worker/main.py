import json
import subprocess
import time

from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.job import Job


def normalize_nuclei_finding(item: dict, asset_id: int, job_id: int) -> Finding:
    info = item.get("info", {}) or {}
    classification = info.get("classification", {}) or {}

    references = info.get("reference") or []
    if isinstance(references, list):
        references = "\n".join(str(r) for r in references)

    cve = classification.get("cve-id")
    if isinstance(cve, list):
        cve = ",".join(cve)

    return Finding(
        asset_id=asset_id,
        job_id=job_id,
        scanner="nuclei",
        template_id=item.get("template-id"),
        name=info.get("name") or item.get("template-id") or "Nuclei Finding",
        severity=info.get("severity", "info"),
        host=item.get("host"),
        matched_at=item.get("matched-at") or item.get("matched"),
        description=info.get("description"),
        remediation=info.get("remediation"),
        reference=references,
        cve=cve,
        cvss_score=str(classification.get("cvss-score")) if classification.get("cvss-score") else None,
        raw_json=json.dumps(item),
        status="open",
    )


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
        "critical,high,medium,low,info",
        "-jsonl",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    findings_created = 0

    if result.stdout.strip():
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            finding = normalize_nuclei_finding(item, asset.id, job.id)
            db.add(finding)
            findings_created += 1

    job.progress = 100

    if result.returncode == 0:
        job.status = "finished"
        job.message = f"Nuclei scan finished. Findings created: {findings_created}"
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
