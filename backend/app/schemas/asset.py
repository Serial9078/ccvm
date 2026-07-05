from pydantic import BaseModel


class AssetCreate(BaseModel):
    customer_id: int
    target: str
    name: str | None = None
    hostname: str | None = None
    fqdn: str | None = None
    ip_address: str | None = None
    type: str = "url"
    exposure: str = "external"
    environment: str = "production"
    criticality: str = "medium"
    owner: str | None = None
    description: str | None = None
    tags: str | None = None


class AssetOut(AssetCreate):
    id: int

    model_config = {"from_attributes": True}
