from pydantic import BaseModel


class DomainCreate(BaseModel):
    customer_id: int
    name: str
    description: str | None = None


class DomainOut(DomainCreate):
    id: int

    model_config = {"from_attributes": True}
