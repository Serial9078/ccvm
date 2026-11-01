import uuid

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.domain import Domain
from app.models.job import Job
from app.schemas.discovery import (
    DiscoveryCreate,
    DiscoveryOut,
)

router = APIRouter(
    prefix="/discover",
    tags=["Discovery"],
)


DISCOVERY_STAGES = [
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


@router.post(
    "",
    response_model=DiscoveryOut,
)
def start_discovery(
    payload: DiscoveryCreate,
    db: Session = Depends(get_db),
):
    domain = db.get(
        Domain,
        payload.domain_id,
    )

    if not domain:
        raise HTTPException(
            status_code=404,
            detail="Domain not found",
        )

    pipeline_id = str(uuid.uuid4())

    jobs: list[Job] = []
    parent_job: Job | None = None

    for stage in DISCOVERY_STAGES:
        job = Job(
            domain_id=domain.id,
            parent_job_id=(parent_job.id if parent_job else None),
            pipeline_id=pipeline_id,
            plugin=stage,
            status="queued",
            progress=0,
            message=(
                (f"Waiting for " f"{parent_job.plugin}")
                if parent_job
                else ("Discovery queued: " f"{stage}")
            ),
        )

        db.add(job)
        db.flush()

        jobs.append(job)
        parent_job = job

    db.commit()

    for job in jobs:
        db.refresh(job)

    return {
        "pipeline_id": pipeline_id,
        "domain_id": domain.id,
        "jobs": jobs,
    }
