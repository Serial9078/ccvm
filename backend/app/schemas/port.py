from pydantic import BaseModel


class PortCreate(BaseModel):
    host_id: int
    port: int
    protocol: str = "tcp"
    service: str | None = None
    banner: str | None = None
    source: str | None = None


class PortOut(PortCreate):
    id: int

    model_config = {"from_attributes": True}
