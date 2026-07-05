from sqlalchemy.orm import Session

from app.repositories.asset_repository import AssetRepository
from app.schemas.asset import AssetCreate


class AssetService:
    def __init__(self, db: Session):
        self.repo = AssetRepository(db)

    def list_assets(self):
        return self.repo.list()

    def create_asset(self, payload: AssetCreate):
        return self.repo.create(payload.customer_id, payload.target, payload.type, payload.exposure)
