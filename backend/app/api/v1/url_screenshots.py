from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.url_screenshot import UrlScreenshot
from app.schemas.url_screenshot import UrlScreenshotOut

router = APIRouter(
    tags=["URL Screenshots"],
)

SCREENSHOT_DIRECTORY = Path("/data/screenshots")


@router.get(
    "/url-screenshots",
    response_model=list[UrlScreenshotOut],
)
def list_url_screenshots(
    url_id: int | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(UrlScreenshot)

    if url_id is not None:
        query = query.filter(
            UrlScreenshot.url_id == url_id,
        )

    return query.order_by(UrlScreenshot.id.desc()).all()


def resolve_screenshot_path(
    filename: str,
) -> tuple[str, Path]:
    safe_filename = Path(filename).name

    if not safe_filename.lower().endswith(".png"):
        raise HTTPException(
            status_code=400,
            detail="Invalid screenshot filename",
        )

    screenshot_path = SCREENSHOT_DIRECTORY / safe_filename

    try:
        screenshot_path.resolve().relative_to(SCREENSHOT_DIRECTORY.resolve())
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid screenshot path",
        ) from exc

    if not screenshot_path.exists() or not screenshot_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Screenshot not found",
        )

    return (
        safe_filename,
        screenshot_path,
    )


@router.api_route(
    "/screenshots/{filename}",
    methods=[
        "GET",
        "HEAD",
    ],
)
def read_screenshot(
    filename: str,
):
    (
        safe_filename,
        screenshot_path,
    ) = resolve_screenshot_path(filename)

    return FileResponse(
        path=screenshot_path,
        media_type="image/png",
        filename=safe_filename,
        content_disposition_type="inline",
        headers={
            "Cache-Control": ("public, max-age=3600"),
            "X-Content-Type-Options": ("nosniff"),
        },
    )
