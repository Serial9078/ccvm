from pydantic import BaseModel


class UrlSecurityOut(BaseModel):
    id: int
    url_id: int

    checked_url: str | None = None
    status_code: int | None = None

    server: str | None = None
    powered_by: str | None = None

    strict_transport_security: str | None = None
    content_security_policy: str | None = None
    x_frame_options: str | None = None
    x_content_type_options: str | None = None
    referrer_policy: str | None = None
    permissions_policy: str | None = None

    cache_control: str | None = None
    etag: str | None = None
    last_modified: str | None = None

    hsts_present: bool
    csp_present: bool
    xfo_present: bool
    xcto_present: bool
    referrer_policy_present: bool
    permissions_policy_present: bool

    missing_headers: str | None = None
    security_score: int | None = None

    error: str | None = None
    source: str

    model_config = {
        "from_attributes": True,
    }
