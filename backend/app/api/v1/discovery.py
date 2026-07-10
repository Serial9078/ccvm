from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.domain import Domain
from app.models.job import Job
from app.schemas.discovery import DiscoveryCreate, DiscoveryOut

router = APIRouter(
    prefix="/discover",
    tags=["Discovery"],
)


@router.post("", response_model=DiscoveryOut)
def start_discovery(
    payload: DiscoveryCreate,
    db: Session = Depends(get_db),
):
    domain = (
        db.query(Domain)
        .filter(Domain.id == payload.domain_id)
        .first()
    )

    if not domain:
        raise HTTPException(
            status_code=404,
            detail="Domain not found",
        )

    stages = [
        "subfinder",
        "dnsx",
        "httpx",
        "naabu",
        "katana",
    ]

    jobs = [
        Job(
            domain_id=domain.id,
            plugin=stage,
            status="queued",
            progress=0,
            message=f"Discovery queued: {stage}",
        )
        for stage in stages
    ]

    db.add_all(jobs)
    db.commit()

    for job in jobs:
        db.refresh(job)

    return {
        "domain_id": domain.id,
        "jobs": jobs,
    }
