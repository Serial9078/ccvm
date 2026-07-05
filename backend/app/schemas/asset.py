from pydantic import BaseModel


class AssetCreate(BaseModel):
    customer_id: int
    target: str
    type: str = "url"
    exposure: str = "external"


class AssetOut(BaseModel):
    id: int
    customer_id: int
    target: str
    type: str
    exposure: str

    model_config = {"from_attributes": True}
