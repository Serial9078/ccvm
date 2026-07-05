from pydantic import BaseModel

class CustomerBase(BaseModel):
    name: str
    company: str | None = None
    street: str | None = None
    zip: str | None = None
    city: str | None = None
    country: str | None = "Germany"
    contact_name: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None

class CustomerCreate(CustomerBase):
    pass

class CustomerUpdate(CustomerBase):
    name: str | None = None

class CustomerOut(CustomerBase):
    id: int
    uuid: str

    class Config:
        from_attributes = True
