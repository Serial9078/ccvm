from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.job import Job
from app.schemas.job import (
    JobCreate,
    JobOut,
)

router = APIRouter(
    prefix="/jobs",
    tags=["Jobs"],
)


DISCOVERY_PLUGINS = [
    "subfinder",
    "dnsx",
    "httpx",
    "naabu",
    "katana",
    "urlprobe",
    "headerprobe",
    "headerfindings",
    "screenshot",
    "nucleiurl",
]


@router.get(
    "",
    response_model=list[JobOut],
)
def list_jobs(
    pipeline_id: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Job)

    if pipeline_id:
        query = query.filter(
            Job.pipeline_id == pipeline_id,
        )

    return query.order_by(Job.id.desc()).all()


@router.get(
    "/{job_id}",
    response_model=JobOut,
)
def get_job(
    job_id: int,
    db: Session = Depends(get_db),
):
    job = db.get(
        Job,
        job_id,
    )

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Job not found",
        )

    return job


@router.post(
    "",
    response_model=JobOut,
)
def create_job(
    payload: JobCreate,
    db: Session = Depends(get_db),
):
    plugin = payload.plugin.strip().lower()

    if plugin in DISCOVERY_PLUGINS and not payload.domain_id:
        raise HTTPException(
            status_code=400,
            detail=("domain_id is required " "for discovery jobs"),
        )

    if plugin not in DISCOVERY_PLUGINS and plugin != "dummy" and not payload.asset_id:
        raise HTTPException(
            status_code=400,
            detail=("asset_id is required " "for scanner jobs"),
        )

    if payload.parent_job_id is not None:
        parent_job = db.get(
            Job,
            payload.parent_job_id,
        )

        if not parent_job:
            raise HTTPException(
                status_code=404,
                detail=("Parent job not found"),
            )

        if (
            payload.pipeline_id
            and parent_job.pipeline_id
            and payload.pipeline_id != parent_job.pipeline_id
        ):
            raise HTTPException(
                status_code=400,
                detail=("Parent job belongs " "to another pipeline"),
            )

    job = Job(
        asset_id=payload.asset_id,
        domain_id=payload.domain_id,
        parent_job_id=(payload.parent_job_id),
        pipeline_id=(payload.pipeline_id),
        plugin=plugin,
        status="queued",
        progress=0,
        message="Job queued",
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    return job
