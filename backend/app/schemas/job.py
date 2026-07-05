from pydantic import BaseModel


class JobCreate(BaseModel):
    asset_id: int
    plugin: str = "dummy"


class JobOut(BaseModel):
    id: int
    uuid: str
    asset_id: int
    plugin: str
    status: str
    progress: int
    message: str | None = None
    worker: str | None = None

    model_config = {"from_attributes": True}
