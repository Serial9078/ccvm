from pydantic import BaseModel

class CustomerCreate(BaseModel):
    name: str
    email: str | None = None

class CustomerOut(CustomerCreate):
    id: int

    model_config = {"from_attributes": True}
