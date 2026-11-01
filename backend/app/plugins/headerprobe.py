import ssl
import urllib.error
import urllib.request
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.job import Job
from app.models.url import Url
from app.models.url_security import UrlSecurity

REQUEST_TIMEOUT_SECONDS = 15
MAX_WORKERS = 20

USER_AGENT = "Mozilla/5.0 " "(compatible; CCVM-HeaderProbe/1.0; " "+https://cloudcollab.de)"

SECURITY_HEADERS = {
    "strict-transport-security": (
        "Strict-Transport-Security",
        20,
    ),
    "content-security-policy": (
        "Content-Security-Policy",
        25,
    ),
    "x-frame-options": (
        "X-Frame-Options",
        15,
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        15,
    ),
    "referrer-policy": (
        "Referrer-Policy",
        10,
    ),
    "permissions-policy": (
        "Permissions-Policy",
        10,
    ),
}


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


def calculate_security_score(
    headers: dict[str, str],
    checked_url: str,
) -> tuple[int, list[str]]:
    score = 0
    missing: list[str] = []

    if checked_url.lower().startswith("https://"):
        score += 5

    for header_name, (
        display_name,
        points,
    ) in SECURITY_HEADERS.items():
        if headers.get(header_name):
            score += points
        else:
            missing.append(display_name)

    return min(100, max(0, score)), missing


def normalize_headers(
    header_items: list[tuple[str, str]],
) -> dict[str, str]:
    normalized: dict[str, str] = {}

    for key, value in header_items:
        normalized[key.lower()] = value

    return normalized


def build_result(
    url_id: int,
    checked_url: str,
    status_code: int | None,
    headers: dict[str, str],
    error: str | None,
) -> dict:
    if error is None:
        score, missing = calculate_security_score(
            headers,
            checked_url,
        )
    else:
        score = None
        missing = []

    return {
        "url_id": url_id,
        "checked_url": checked_url,
        "status_code": status_code,
        "server": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "strict_transport_security": headers.get("strict-transport-security"),
        "content_security_policy": headers.get("content-security-policy"),
        "x_frame_options": headers.get("x-frame-options"),
        "x_content_type_options": headers.get("x-content-type-options"),
        "referrer_policy": headers.get("referrer-policy"),
        "permissions_policy": headers.get("permissions-policy"),
        "cache_control": headers.get("cache-control"),
        "etag": headers.get("etag"),
        "last_modified": headers.get("last-modified"),
        "hsts_present": bool(headers.get("strict-transport-security")),
        "csp_present": bool(headers.get("content-security-policy")),
        "xfo_present": bool(headers.get("x-frame-options")),
        "xcto_present": bool(headers.get("x-content-type-options")),
        "referrer_policy_present": bool(headers.get("referrer-policy")),
        "permissions_policy_present": bool(headers.get("permissions-policy")),
        "missing_headers": (", ".join(missing) if error is None and missing else None),
        "security_score": score,
        "error": error,
        "source": "headerprobe",
    }


def probe_url(
    url_id: int,
    target_url: str,
) -> dict:
    ssl_context = ssl._create_unverified_context()

    request = urllib.request.Request(
        target_url,
        method="HEAD",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT_SECONDS,
            context=ssl_context,
        ) as response:
            headers = normalize_headers(list(response.headers.items()))

            return build_result(
                url_id=url_id,
                checked_url=response.geturl(),
                status_code=response.status,
                headers=headers,
                error=None,
            )

    except urllib.error.HTTPError as exc:
        headers = normalize_headers(list(exc.headers.items()) if exc.headers else [])

        if exc.code not in {
            405,
            501,
        }:
            return build_result(
                url_id=url_id,
                checked_url=exc.geturl(),
                status_code=exc.code,
                headers=headers,
                error=None,
            )

    except Exception:
        pass

    fallback_request = urllib.request.Request(
        target_url,
        method="GET",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Range": "bytes=0-1024",
        },
    )

    try:
        with urllib.request.urlopen(
            fallback_request,
            timeout=REQUEST_TIMEOUT_SECONDS,
            context=ssl_context,
        ) as response:
            headers = normalize_headers(list(response.headers.items()))

            return build_result(
                url_id=url_id,
                checked_url=response.geturl(),
                status_code=response.status,
                headers=headers,
                error=None,
            )

    except urllib.error.HTTPError as exc:
        headers = normalize_headers(list(exc.headers.items()) if exc.headers else [])

        return build_result(
            url_id=url_id,
            checked_url=exc.geturl(),
            status_code=exc.code,
            headers=headers,
            error=None,
        )

    except Exception as exc:
        return build_result(
            url_id=url_id,
            checked_url=target_url,
            status_code=None,
            headers={},
            error=(f"{type(exc).__name__}: " f"{exc}")[:1000],
        )


def bulk_upsert_security(
    db: Session,
    rows: list[dict],
) -> int:
    if not rows:
        return 0

    statement = insert(UrlSecurity).values(rows)

    excluded = statement.excluded

    statement = statement.on_conflict_do_update(
        index_elements=[
            "url_id",
        ],
        set_={
            "checked_url": excluded.checked_url,
            "status_code": excluded.status_code,
            "server": excluded.server,
            "powered_by": excluded.powered_by,
            "strict_transport_security": (excluded.strict_transport_security),
            "content_security_policy": (excluded.content_security_policy),
            "x_frame_options": (excluded.x_frame_options),
            "x_content_type_options": (excluded.x_content_type_options),
            "referrer_policy": (excluded.referrer_policy),
            "permissions_policy": (excluded.permissions_policy),
            "cache_control": excluded.cache_control,
            "etag": excluded.etag,
            "last_modified": (excluded.last_modified),
            "hsts_present": excluded.hsts_present,
            "csp_present": excluded.csp_present,
            "xfo_present": excluded.xfo_present,
            "xcto_present": excluded.xcto_present,
            "referrer_policy_present": (excluded.referrer_policy_present),
            "permissions_policy_present": (excluded.permissions_policy_present),
            "missing_headers": (excluded.missing_headers),
            "security_score": (excluded.security_score),
            "error": excluded.error,
            "source": excluded.source,
        },
    )

    result = db.execute(statement)
    db.commit()

    return int(result.rowcount or 0)


def run_headerprobe(
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

    urls = (
        db.query(Url)
        .filter(
            Url.domain_id == domain.id,
        )
        .order_by(Url.id.asc())
        .all()
    )

    if not urls:
        fail_job(
            db,
            job,
            "No URLs found for HeaderProbe",
        )
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Starting HTTP security analysis " f"for {len(urls)} URLs"
    db.commit()

    targets = [
        (
            url_record.id,
            url_record.url,
        )
        for url_record in urls
    ]

    results: list[dict] = []
    completed = 0
    failures = 0

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS,
    ) as executor:
        futures = {
            executor.submit(
                probe_url,
                url_id,
                target_url,
            ): (
                url_id,
                target_url,
            )
            for url_id, target_url in targets
        }

        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)

                if result.get("error"):
                    failures += 1

            except Exception as exc:
                url_id, target_url = futures[future]

                results.append(
                    build_result(
                        url_id=url_id,
                        checked_url=target_url,
                        status_code=None,
                        headers={},
                        error=(f"{type(exc).__name__}: " f"{exc}")[:1000],
                    )
                )

                failures += 1

            completed += 1

            if completed % 10 == 0 or completed == len(targets):
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
                                len(targets),
                                1,
                            )
                            * 85
                        ),
                    )

                    current_job.message = (
                        f"HeaderProbe processed "
                        f"{completed}/"
                        f"{len(targets)} URLs. "
                        f"Failures: {failures}"
                    )

                    db.commit()

    try:
        stored = bulk_upsert_security(
            db,
            results,
        )

    except Exception as exc:
        fail_job(
            db,
            job,
            ("HeaderProbe import failed: " f"{type(exc).__name__}: {exc}"),
        )
        return

    finish_job(
        db,
        job,
        (
            f"HeaderProbe finished. "
            f"URLs processed: {completed}. "
            f"Records stored: {stored}. "
            f"Failures: {failures}"
        ),
    )
