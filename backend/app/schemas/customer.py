from pydantic import BaseModel, EmailStr


class CustomerCreate(BaseModel):
    name: str
    email: EmailStr | None = None


class CustomerOut(BaseModel):
    id: int
    name: str
    email: str | None = None

    model_config = {"from_attributes": True}
