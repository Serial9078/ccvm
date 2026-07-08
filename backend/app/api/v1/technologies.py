from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.technology import Technology
from app.schemas.technology import TechnologyCreate, TechnologyOut

router = APIRouter(prefix="/technologies", tags=["Technologies"])


@router.get("", response_model=list[TechnologyOut])
def list_technologies(db: Session = Depends(get_db)):
    return db.query(Technology).order_by(Technology.id.desc()).all()


@router.post("", response_model=TechnologyOut)
def create_technology(payload: TechnologyCreate, db: Session = Depends(get_db)):
    technology = Technology(**payload.model_dump())
    db.add(technology)
    db.commit()
    db.refresh(technology)
    return technology
