from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.job import Job
from app.schemas.job import JobCreate, JobOut

router = APIRouter(prefix="/jobs", tags=["Jobs"])


DISCOVERY_PLUGINS = ["subfinder", "dnsx", "httpx"]


@router.get("", response_model=list[JobOut])
def list_jobs(db: Session = Depends(get_db)):
    return db.query(Job).order_by(Job.id.desc()).all()


@router.post("", response_model=JobOut)
def create_job(payload: JobCreate, db: Session = Depends(get_db)):
    if payload.plugin in DISCOVERY_PLUGINS and not payload.domain_id:
        raise HTTPException(status_code=400, detail="domain_id is required for discovery jobs")

    if payload.plugin not in DISCOVERY_PLUGINS and not payload.asset_id:
        raise HTTPException(status_code=400, detail="asset_id is required for scanner jobs")

    job = Job(
        asset_id=payload.asset_id,
        domain_id=payload.domain_id,
        plugin=payload.plugin,
        status="queued",
        progress=0,
        message="Job queued",
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    return job
