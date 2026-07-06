from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.domain import Domain
from app.schemas.domain import DomainCreate, DomainOut

router = APIRouter(prefix="/domains", tags=["Domains"])


@router.get("", response_model=list[DomainOut])
def list_domains(db: Session = Depends(get_db)):
    return db.query(Domain).order_by(Domain.id.desc()).all()


@router.post("", response_model=DomainOut)
def create_domain(payload: DomainCreate, db: Session = Depends(get_db)):
    domain = Domain(**payload.model_dump())
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain
