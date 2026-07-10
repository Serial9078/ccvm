from pydantic import BaseModel


class UrlCreate(BaseModel):
    customer_id: int
    domain_id: int
    host_id: int | None = None
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None
    source: str = "katana"


class UrlOut(UrlCreate):
    id: int

    model_config = {
        "from_attributes": True,
    }
