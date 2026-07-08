from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingOut

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(db: Session = Depends(get_db)):
    return db.query(Finding).order_by(Finding.id.desc()).all()


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding
