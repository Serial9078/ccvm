from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.asset import Asset
from app.models.domain import Domain
from app.models.job import Job
from app.schemas.pipeline import PipelineOut

router = APIRouter(
    prefix="/pipelines",
    tags=["Pipelines"],
)


def calculate_pipeline_status(
    jobs: list[Job],
) -> str:
    statuses = {job.status for job in jobs}

    if "running" in statuses:
        return "running"

    if "failed" in statuses:
        return "failed"

    if "cancelled" in statuses:
        return "cancelled"

    if "queued" in statuses:
        return "queued"

    if "skipped" in statuses:
        return "partial"

    if statuses == {"finished"}:
        return "finished"

    return "unknown"


def calculate_pipeline_progress(
    jobs: list[Job],
) -> int:
    if not jobs:
        return 0

    total_progress = sum(job.progress or 0 for job in jobs)

    return int(total_progress / len(jobs))


def serialize_pipeline(
    db: Session,
    pipeline_id: str,
    jobs: list[Job],
) -> dict:
    ordered_jobs = sorted(
        jobs,
        key=lambda job: job.id,
    )

    domain_id = next(
        (job.domain_id for job in ordered_jobs if job.domain_id is not None),
        None,
    )

    domain_name = None
    asset_id = next((job.asset_id for job in ordered_jobs if job.asset_id is not None), None)
    asset = db.get(Asset, asset_id) if asset_id is not None else None

    if domain_id is not None:
        domain = db.get(
            Domain,
            domain_id,
        )

        if domain:
            domain_name = domain.name

    return {
        "pipeline_id": pipeline_id,
        "domain_id": domain_id,
        "domain_name": domain_name,
        "asset_id": asset_id,
        "asset_name": asset.name if asset else None,
        "asset_target": asset.target if asset else None,
        "status": calculate_pipeline_status(ordered_jobs),
        "progress": calculate_pipeline_progress(ordered_jobs),
        "total_jobs": len(ordered_jobs),
        "finished_jobs": sum(1 for job in ordered_jobs if job.status == "finished"),
        "failed_jobs": sum(1 for job in ordered_jobs if job.status == "failed"),
        "skipped_jobs": sum(1 for job in ordered_jobs if job.status == "skipped"),
        "running_jobs": sum(1 for job in ordered_jobs if job.status == "running"),
        "queued_jobs": sum(1 for job in ordered_jobs if job.status == "queued"),
        "jobs": ordered_jobs,
    }


@router.get(
    "",
    response_model=list[PipelineOut],
)
def list_pipelines(
    limit: int = 25,
    db: Session = Depends(get_db),
):
    pipeline_jobs = (
        db.query(Job)
        .filter(
            Job.pipeline_id.is_not(None),
        )
        .order_by(Job.id.desc())
        .all()
    )

    grouped_jobs: dict[str, list[Job]] = defaultdict(list)

    latest_job_id: dict[str, int] = {}

    for job in pipeline_jobs:
        if not job.pipeline_id:
            continue

        grouped_jobs[job.pipeline_id].append(job)

        latest_job_id[job.pipeline_id] = max(
            latest_job_id.get(
                job.pipeline_id,
                0,
            ),
            job.id,
        )

    sorted_pipeline_ids = sorted(
        grouped_jobs.keys(),
        key=lambda current_pipeline_id: (latest_job_id[current_pipeline_id]),
        reverse=True,
    )

    return [
        serialize_pipeline(
            db,
            pipeline_id,
            grouped_jobs[pipeline_id],
        )
        for pipeline_id in sorted_pipeline_ids[: max(1, min(limit, 100))]
    ]


@router.get(
    "/{pipeline_id}",
    response_model=PipelineOut,
)
def get_pipeline(
    pipeline_id: str,
    db: Session = Depends(get_db),
):
    jobs = (
        db.query(Job)
        .filter(
            Job.pipeline_id == pipeline_id,
        )
        .order_by(Job.id.asc())
        .all()
    )

    if not jobs:
        raise HTTPException(
            status_code=404,
            detail="Pipeline not found",
        )

    return serialize_pipeline(
        db,
        pipeline_id,
        jobs,
    )
