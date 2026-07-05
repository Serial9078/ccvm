from pydantic import BaseModel

class CustomerCreate(BaseModel):
    name: str
    email: str | None = None

class CustomerOut(CustomerCreate):
    id: int

    class Config:
        from_attributes = True
