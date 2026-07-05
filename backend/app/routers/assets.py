from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.deps import get_db
from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetOut

router = APIRouter(prefix="/assets", tags=["Assets"])

@router.get("", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.id.desc()).all()

@router.post("", response_model=AssetOut)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    asset = Asset(customer_id=payload.customer_id, target=payload.target, type=payload.type)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset
