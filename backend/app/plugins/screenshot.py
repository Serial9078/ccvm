import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.job import Job
from app.models.url import Url
from app.models.url_detail import UrlDetail
from app.models.url_screenshot import UrlScreenshot

SCREENSHOT_SERVICE_URL = os.getenv(
    "SCREENSHOT_SERVICE_URL",
    "http://screenshot-service:3001",
)

REQUEST_TIMEOUT_SECONDS = 50
MAX_SCREENSHOTS_PER_DOMAIN = 25


def fail_job(
    db: Session,
    job: Job,
    message: str,
) -> None:
    db.rollback()

    current_job = db.get(
        Job,
        job.id,
    )

    if not current_job:
        return

    current_job.status = "failed"
    current_job.progress = 100
    current_job.message = message[:1000]

    db.commit()


def finish_job(
    db: Session,
    job: Job,
    message: str,
) -> None:
    current_job = db.get(
        Job,
        job.id,
    )

    if not current_job:
        return

    current_job.status = "finished"
    current_job.progress = 100
    current_job.message = message[:1000]

    db.commit()


def normalized_page_key(
    value: str,
) -> str:
    parsed = urlparse(value)

    return f"{parsed.scheme}://" f"{parsed.netloc}" f"{parsed.path.rstrip('/') or '/'}"


def request_screenshot(
    target_url: str,
) -> dict:
    payload = json.dumps(
        {
            "url": target_url,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        (f"{SCREENSHOT_SERVICE_URL}" "/screenshot"),
        data=payload,
        method="POST",
        headers={
            "Content-Type": ("application/json"),
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ) as response:
            return json.loads(response.read().decode("utf-8"))

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        raise RuntimeError(
            ("Screenshot service returned " f"HTTP {exc.code}: " f"{error_body[:500]}")
        ) from exc


def upsert_screenshot(
    db: Session,
    row: dict,
) -> None:
    statement = insert(UrlScreenshot).values(row)

    excluded = statement.excluded

    statement = statement.on_conflict_do_update(
        index_elements=[
            "url_id",
        ],
        set_={
            "screenshot_path": (excluded.screenshot_path),
            "filename": excluded.filename,
            "title": excluded.title,
            "final_url": (excluded.final_url),
            "status_code": (excluded.status_code),
            "duration_ms": (excluded.duration_ms),
            "viewport_width": (excluded.viewport_width),
            "viewport_height": (excluded.viewport_height),
            "error": excluded.error,
            "source": excluded.source,
        },
    )

    db.execute(statement)
    db.commit()


def run_screenshot(
    db: Session,
    job: Job,
) -> None:
    domain = db.get(
        Domain,
        job.domain_id,
    )

    if not domain:
        fail_job(
            db,
            job,
            "Domain not found",
        )
        return

    rows = (
        db.query(
            Url,
            UrlDetail,
        )
        .join(
            UrlDetail,
            UrlDetail.url_id == Url.id,
        )
        .filter(
            Url.domain_id == domain.id,
            UrlDetail.content_type.ilike("%text/html%"),
            UrlDetail.status_code.between(
                200,
                399,
            ),
        )
        .order_by(Url.id.asc())
        .all()
    )

    selected: list[tuple[Url, UrlDetail]] = []

    seen_pages: set[str] = set()

    for url_record, detail in rows:
        target_url = detail.final_url or url_record.url

        page_key = normalized_page_key(target_url)

        if page_key in seen_pages:
            continue

        seen_pages.add(page_key)

        selected.append(
            (
                url_record,
                detail,
            )
        )

        if len(selected) >= MAX_SCREENSHOTS_PER_DOMAIN:
            break

    if not selected:
        fail_job(
            db,
            job,
            ("No reachable HTML URLs found " "for screenshots"),
        )
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Starting screenshots for " f"{len(selected)} HTML pages"
    db.commit()

    completed = 0
    created_or_updated = 0
    failures = 0

    for url_record, detail in selected:
        target_url = detail.final_url or url_record.url

        current_job = db.get(
            Job,
            job.id,
        )

        if current_job:
            current_job.message = (
                f"Screenshot " f"{completed + 1}/" f"{len(selected)}: " f"{target_url[:180]}"
            )
            db.commit()

        try:
            result = request_screenshot(target_url)

            row = {
                "url_id": url_record.id,
                "screenshot_path": (result.get("path")),
                "filename": (result.get("filename")),
                "title": (result.get("title")),
                "final_url": (result.get("final_url")),
                "status_code": (result.get("status_code")),
                "duration_ms": (result.get("duration_ms")),
                "viewport_width": (
                    result.get(
                        "viewport_width",
                        1440,
                    )
                ),
                "viewport_height": (
                    result.get(
                        "viewport_height",
                        900,
                    )
                ),
                "error": None,
                "source": "playwright",
            }

            created_or_updated += 1

        except Exception as exc:
            failures += 1

            row = {
                "url_id": url_record.id,
                "screenshot_path": None,
                "filename": None,
                "title": None,
                "final_url": target_url,
                "status_code": None,
                "duration_ms": None,
                "viewport_width": 1440,
                "viewport_height": 900,
                "error": (f"{type(exc).__name__}: " f"{exc}")[:1000],
                "source": "playwright",
            }

        upsert_screenshot(
            db,
            row,
        )

        completed += 1

        current_job = db.get(
            Job,
            job.id,
        )

        if current_job:
            current_job.progress = min(
                95,
                10
                + int(
                    completed
                    / max(
                        len(selected),
                        1,
                    )
                    * 85
                ),
            )

            current_job.message = (
                f"Screenshots processed "
                f"{completed}/{len(selected)}. "
                f"Successful: "
                f"{created_or_updated}. "
                f"Failures: {failures}"
            )

            db.commit()

    finish_job(
        db,
        job,
        (
            "Screenshot stage finished. "
            f"Pages selected: {len(selected)}. "
            f"Successful: {created_or_updated}. "
            f"Failures: {failures}"
        ),
    )
