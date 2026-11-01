from pydantic import BaseModel


class UrlScreenshotOut(BaseModel):
    id: int
    url_id: int

    screenshot_path: str | None = None
    filename: str | None = None
    title: str | None = None
    final_url: str | None = None

    status_code: int | None = None
    duration_ms: int | None = None

    viewport_width: int
    viewport_height: int

    error: str | None = None
    source: str

    model_config = {
        "from_attributes": True,
    }
