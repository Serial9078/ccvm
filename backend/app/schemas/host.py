from pydantic import BaseModel


class HostCreate(BaseModel):
    customer_id: int
    domain_id: int | None = None
    subdomain_id: int | None = None
    hostname: str
    ip_address: str | None = None
    alive: bool = False
    source: str | None = None


class HostOut(HostCreate):
    id: int

    model_config = {"from_attributes": True}
