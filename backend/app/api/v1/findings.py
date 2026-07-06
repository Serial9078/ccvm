from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingOut

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(db: Session = Depends(get_db)):
    return db.query(Finding).order_by(Finding.id.desc()).all()
