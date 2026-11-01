from pydantic import BaseModel


class UrlDetailOut(BaseModel):
    id: int
    url_id: int

    status_code: int | None = None
    title: str | None = None
    content_type: str | None = None
    content_length: int | None = None

    webserver: str | None = None
    ip_address: str | None = None
    final_url: str | None = None

    response_time_seconds: float | None = None

    method: str
    source: str

    model_config = {
        "from_attributes": True,
    }
