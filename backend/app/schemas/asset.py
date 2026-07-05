from pydantic import BaseModel

class AssetCreate(BaseModel):
    customer_id: int
    target: str
    type: str = "url"

class AssetOut(AssetCreate):
    id: int

    class Config:
        from_attributes = True
