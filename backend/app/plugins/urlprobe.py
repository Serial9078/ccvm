import json
import math
import re
import subprocess
from urllib.parse import urlsplit

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.job import Job
from app.models.url import Url
from app.models.url_detail import UrlDetail

HTTPX_TIMEOUT_SECONDS = 1800


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


def parse_integer(
    value: object,
) -> int | None:
    try:
        if value is None:
            return None

        return int(value)

    except (
        TypeError,
        ValueError,
        OverflowError,
    ):
        return None


def parse_float(
    value: object,
) -> float | None:
    try:
        if value is None:
            return None

        if isinstance(value, (int, float)):
            number = float(value)
            return number if math.isfinite(number) and number >= 0 else None

        # httpx uses Go duration strings, e.g. 120ms or 150µs, not only seconds.
        match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ns|us|µs|μs|ms|s|m|h)?", str(value).strip())
        if not match:
            return None
        multiplier = {
            None: 1,
            "ns": 1e-9,
            "us": 1e-6,
            "µs": 1e-6,
            "μs": 1e-6,
            "ms": 1e-3,
            "s": 1,
            "m": 60,
            "h": 3600,
        }[match[2]]
        result = float(match[1]) * multiplier
        return result if math.isfinite(result) else None

    except (
        TypeError,
        ValueError,
    ):
        return None


def extract_ip(
    item: dict,
) -> str | None:
    ip_value = item.get("host") or item.get("ip") or item.get("a")

    if isinstance(ip_value, list):
        return str(ip_value[0]) if ip_value else None

    return str(ip_value) if ip_value else None


def extract_final_url(
    item: dict,
) -> str | None:
    # Location describes a next hop, which may be relative or never visited.
    # Only retain an absolute URL actually reported as probed/effective by httpx.
    for key in ("final-url", "final_url", "url", "input"):
        value = item.get(key)
        if not isinstance(value, str):
            continue
        try:
            parsed = urlsplit(value)
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                return value
        except ValueError:
            continue
    return None


def run_urlprobe(
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
            "No URLs found for URLProbe",
        )
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Starting URL intelligence for " f"{len(urls)} URLs"
    db.commit()

    input_data = "\n".join(url.url for url in urls) + "\n"

    command = [
        "httpx",
        "-silent",
        "-json",
        "-title",
        "-status-code",
        "-content-type",
        "-content-length",
        "-web-server",
        "-ip",
        "-location",
        "-response-time",
        "-follow-redirects",
        "-timeout",
        "15",
        "-retries",
        "1",
        "-threads",
        "25",
    ]

    try:
        result = subprocess.run(
            command,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=HTTPX_TIMEOUT_SECONDS,
            check=False,
        )

    except subprocess.TimeoutExpired:
        fail_job(
            db,
            job,
            "URLProbe timed out",
        )
        return

    except Exception as exc:
        fail_job(
            db,
            job,
            ("URLProbe execution failed: " f"{type(exc).__name__}: {exc}"),
        )
        return

    url_by_value = {url.url: url for url in urls}

    rows_by_url_id: dict[int, dict] = {}
    parsed_results = 0

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line.startswith("{"):
            continue

        try:
            item = json.loads(line)

        except json.JSONDecodeError:
            continue

        if not isinstance(item, dict):
            continue

        input_url = str(item.get("input") or item.get("url") or "").strip()

        url_record = url_by_value.get(input_url)

        if not url_record:
            continue

        status_code = parse_integer(item.get("status-code") or item.get("status_code"))

        content_length = parse_integer(item.get("content-length", item.get("content_length")))

        content_type = item.get("content-type") or item.get("content_type")

        webserver = item.get("webserver") or item.get("web-server") or item.get("server")

        response_time = parse_float(
            item.get("time") or item.get("response-time") or item.get("response_time")
        )

        rows_by_url_id[url_record.id] = {
            "url_id": url_record.id,
            "status_code": status_code,
            "title": item.get("title"),
            "content_type": (str(content_type) if content_type else None),
            "content_length": content_length,
            "webserver": (str(webserver) if webserver else None),
            "ip_address": extract_ip(item),
            "final_url": extract_final_url(item),
            "response_time_seconds": response_time,
            "method": "GET",
            "source": "httpx",
        }

        url_record.status_code = status_code
        url_record.content_type = str(content_type) if content_type else None

        parsed_results += 1

    if result.returncode == 0:
        # A completed probe that no longer reports a URL must not leave its old
        # successful response eligible for the downstream active scanner.
        unobserved_ids = []
        for url_record in urls:
            if url_record.id not in rows_by_url_id:
                unobserved_ids.append(url_record.id)
                url_record.status_code = None
        if unobserved_ids:
            # Retain previous titles, response metadata and URL records. Only
            # invalidate reachability after a completed observation pass.
            db.query(UrlDetail).filter(UrlDetail.url_id.in_(unobserved_ids)).update(
                {UrlDetail.status_code: None}, synchronize_session=False
            )

    if rows_by_url_id:
        statement = (
            insert(UrlDetail)
            .values(list(rows_by_url_id.values()))
            .on_conflict_do_update(
                index_elements=[
                    "url_id",
                ],
                set_={
                    "status_code": insert(UrlDetail).excluded.status_code,
                    "title": insert(UrlDetail).excluded.title,
                    "content_type": insert(UrlDetail).excluded.content_type,
                    "content_length": insert(UrlDetail).excluded.content_length,
                    "webserver": insert(UrlDetail).excluded.webserver,
                    "ip_address": insert(UrlDetail).excluded.ip_address,
                    "final_url": insert(UrlDetail).excluded.final_url,
                    "response_time_seconds": insert(UrlDetail).excluded.response_time_seconds,
                    "method": insert(UrlDetail).excluded.method,
                    "source": insert(UrlDetail).excluded.source,
                },
            )
        )

        db.execute(statement)

    db.commit()

    if result.returncode != 0:
        fail_job(
            db,
            job,
            (
                "URLProbe failed. "
                f"Parsed results: {parsed_results}. "
                f"Output: {result.stderr[-800:]}"
            ),
        )
        return

    finish_job(
        db,
        job,
        (
            "URLProbe finished. "
            f"URLs submitted: {len(urls)}. "
            f"Results parsed: {parsed_results}. "
            f"Details stored: "
            f"{len(rows_by_url_id)}"
        ),
    )
