from sqlalchemy.orm import Session

from app.models.asset import Asset


class AssetRepository:
    def __init__(self, db: Session):
        self.db = db

    def list(self) -> list[Asset]:
        return self.db.query(Asset).order_by(Asset.id.desc()).all()

    def create(self, customer_id: int, target: str, type: str, exposure: str) -> Asset:
        asset = Asset(customer_id=customer_id, target=target, type=type, exposure=exposure)
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return asset
