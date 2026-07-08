from pydantic import BaseModel


class TechnologyCreate(BaseModel):
    host_id: int
    name: str
    version: str | None = None
    category: str | None = None
    source: str | None = None


class TechnologyOut(TechnologyCreate):
    id: int

    model_config = {"from_attributes": True}
