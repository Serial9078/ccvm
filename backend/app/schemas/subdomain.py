from pydantic import BaseModel


class SubdomainCreate(BaseModel):
    customer_id: int
    domain_id: int
    name: str
    source: str | None = None


class SubdomainOut(SubdomainCreate):
    id: int

    model_config = {"from_attributes": True}
