from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.domain import Domain
from app.models.job import Job
from app.schemas.discovery import DiscoveryCreate, DiscoveryOut

router = APIRouter(prefix="/discover", tags=["Discovery"])


@router.post("", response_model=DiscoveryOut)
def start_discovery(payload: DiscoveryCreate, db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == payload.domain_id).first()

    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    jobs = [
        Job(domain_id=domain.id, plugin="subfinder", status="queued", progress=0, message="Discovery queued: subfinder"),
        Job(domain_id=domain.id, plugin="dnsx", status="queued", progress=0, message="Discovery queued: dnsx"),
        Job(domain_id=domain.id, plugin="httpx", status="queued", progress=0, message="Discovery queued: httpx"),
        Job(domain_id=domain.id, plugin="naabu", status="queued", progress=0, message="Discovery queued: naabu"),
    ]

    for job in jobs:
        db.add(job)

    db.commit()

    for job in jobs:
        db.refresh(job)

    return {"domain_id": domain.id, "jobs": jobs}
