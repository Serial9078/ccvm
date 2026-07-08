from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.subdomain import Subdomain
from app.schemas.subdomain import SubdomainCreate, SubdomainOut

router = APIRouter(prefix="/subdomains", tags=["Subdomains"])


@router.get("", response_model=list[SubdomainOut])
def list_subdomains(db: Session = Depends(get_db)):
    return db.query(Subdomain).order_by(Subdomain.id.desc()).all()


@router.post("", response_model=SubdomainOut)
def create_subdomain(payload: SubdomainCreate, db: Session = Depends(get_db)):
    subdomain = Subdomain(**payload.model_dump())
    db.add(subdomain)
    db.commit()
    db.refresh(subdomain)
    return subdomain
