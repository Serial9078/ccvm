import json
import re
import subprocess
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.database.url_identity import url_digest
from app.models.domain import Domain
from app.models.host import Host
from app.models.job import Job
from app.models.url import Url

KATANA_TIMEOUT_SECONDS = 45
KATANA_DEPTH = 2
KATANA_CRAWL_DURATION = "30s"


BLOCKED_EXTENSIONS = {
    ".7z",
    ".aac",
    ".avi",
    ".avif",
    ".bmp",
    ".css",
    ".csv",
    ".doc",
    ".docx",
    ".eot",
    ".flac",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".map",
    ".mjs",
    ".mov",
    ".mp3",
    ".mp4",
    ".mpeg",
    ".mpg",
    ".ogg",
    ".otf",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".tgz",
    ".tif",
    ".tiff",
    ".ts",
    ".ttf",
    ".txt",
    ".wav",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".xml",
    ".zip",
}


BLOCKED_PATH_PREFIXES = (
    "/assets/",
    "/cdn-cgi/",
    "/css/",
    "/fonts/",
    "/font/",
    "/images/",
    "/image/",
    "/img/",
    "/js/",
    "/scripts/",
    "/static/",
    "/vendor/",
    "/webfonts/",
)


BLOCKED_EXACT_PATHS = {
    "/apple-touch-icon.png",
    "/browserconfig.xml",
    "/favicon.ico",
    "/manifest.json",
    "/robots.txt",
    "/sitemap",
    "/sitemap.xml",
}


BLOCKED_CONTENT_TYPES = (
    "application/font",
    "application/javascript",
    "application/octet-stream",
    "application/pdf",
    "application/vnd.ms-fontobject",
    "application/wasm",
    "application/x-font",
    "application/x-javascript",
    "audio/",
    "font/",
    "image/",
    "text/css",
    "text/javascript",
    "video/",
)


INDEX_FILENAMES = {
    "default.htm",
    "default.html",
    "index.htm",
    "index.html",
}


def get_domain(
    db: Session,
    job: Job,
) -> Domain | None:
    return db.query(Domain).filter(Domain.id == job.domain_id).first()


def fail_job(
    db: Session,
    job: Job,
    message: str,
) -> None:
    db.rollback()

    current_job = db.get(Job, job.id)

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
    current_job = db.get(Job, job.id)

    if not current_job:
        return

    current_job.status = "finished"
    current_job.progress = 100
    current_job.message = message[:1000]

    db.commit()


def extract_katana_url(
    item: dict,
) -> tuple[str | None, str, int | None, str | None]:
    if not isinstance(item, dict):
        return None, "GET", None, None
    request_data = item.get("request")
    response_data = item.get("response")
    if not isinstance(request_data, dict):
        request_data = {}
    if not isinstance(response_data, dict):
        response_data = {}

    discovered_url = (
        item.get("url")
        or item.get("endpoint")
        or request_data.get("endpoint")
        or request_data.get("url")
    )

    method = item.get("method") or request_data.get("method") or "GET"

    status_code = (
        item.get("status-code")
        or item.get("status_code")
        or response_data.get("status-code")
        or response_data.get("status_code")
        or response_data.get("status")
    )

    content_type = (
        item.get("content-type")
        or item.get("content_type")
        or response_data.get("content-type")
        or response_data.get("content_type")
    )

    try:
        normalized_status_code = int(status_code) if status_code is not None else None
    except (TypeError, ValueError):
        normalized_status_code = None

    return (
        str(discovered_url).strip() if discovered_url else None,
        str(method).upper(),
        normalized_status_code,
        str(content_type).strip() if content_type else None,
    )


def normalize_path(
    path: str,
) -> str:
    normalized_path = path or "/"

    normalized_path = re.sub(
        r"/{2,}",
        "/",
        normalized_path,
    )

    path_parts = normalized_path.rstrip("/").split("/")

    if path_parts and path_parts[-1].lower() in INDEX_FILENAMES:
        path_parts = path_parts[:-1]
        normalized_path = "/".join(path_parts) or "/"

    if not normalized_path.startswith("/"):
        normalized_path = f"/{normalized_path}"

    if normalized_path != "/":
        normalized_path = normalized_path.rstrip("/")

    return normalized_path


def normalize_url(
    value: str,
) -> str | None:
    raw_value = value.strip()

    if not raw_value:
        return None

    try:
        parsed = urlsplit(raw_value)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        return None

    hostname = (parsed.hostname or "").lower().rstrip(".")

    if not hostname:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    if ":" in hostname and not hostname.startswith("["):
        normalized_hostname = f"[{hostname}]"
    else:
        normalized_hostname = hostname

    if (
        port is not None
        and not (scheme == "http" and port == 80)
        and not (scheme == "https" and port == 443)
    ):
        netloc = f"{normalized_hostname}:{port}"
    else:
        netloc = normalized_hostname

    normalized_path = normalize_path(parsed.path)

    return urlunsplit(
        (
            scheme,
            netloc,
            normalized_path,
            parsed.query,
            "",
        )
    )


def is_domain_url(
    discovered_url: str,
    domain_name: str,
) -> bool:
    try:
        parsed = urlsplit(discovered_url)
    except ValueError:
        return False

    hostname = (parsed.hostname or "").lower().rstrip(".")
    normalized_domain = domain_name.lower().rstrip(".")

    return hostname == normalized_domain or hostname.endswith(f".{normalized_domain}")


def has_blocked_extension(
    path: str,
) -> bool:
    lowered_path = path.lower()

    return any(lowered_path.endswith(extension) for extension in BLOCKED_EXTENSIONS)


def has_blocked_content_type(
    content_type: str | None,
) -> bool:
    if not content_type:
        return False

    normalized_content_type = content_type.split(";", 1)[0].strip().lower()

    return any(
        normalized_content_type.startswith(blocked_type) for blocked_type in BLOCKED_CONTENT_TYPES
    )


def should_collect_url(
    discovered_url: str,
    content_type: str | None = None,
) -> bool:
    try:
        parsed = urlsplit(discovered_url)
    except ValueError:
        return False

    path = (parsed.path or "/").lower()

    if path in BLOCKED_EXACT_PATHS:
        return False

    if path.startswith(BLOCKED_PATH_PREFIXES):
        return False

    if has_blocked_extension(path):
        return False

    if has_blocked_content_type(content_type):
        return False

    return True


def collect_host_urls(
    host: Host,
    domain: Domain,
) -> tuple[list[dict], int, int]:
    collected: dict[str, dict] = {}
    execution_failures = 0
    filtered_urls = 0

    targets = [
        f"https://{host.hostname}",
        f"http://{host.hostname}",
    ]

    for target in targets:
        try:
            result = subprocess.run(
                [
                    "katana",
                    "-u",
                    target,
                    "-silent",
                    "-jsonl",
                    "-d",
                    str(KATANA_DEPTH),
                    "-jc",
                    "-kf",
                    "all",
                    "-timeout",
                    "10",
                    "-crawl-duration",
                    KATANA_CRAWL_DURATION,
                ],
                capture_output=True,
                text=True,
                timeout=KATANA_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            execution_failures += 1
            continue
        except Exception:
            execution_failures += 1
            continue

        target_had_results = False

        for line in result.stdout.splitlines():
            line = line.strip()

            if not line.startswith("{"):
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            (
                discovered_url,
                method,
                status_code,
                content_type,
            ) = extract_katana_url(item)

            if not discovered_url:
                continue

            normalized_url = normalize_url(discovered_url)

            if not normalized_url:
                filtered_urls += 1
                continue

            if not is_domain_url(
                normalized_url,
                domain.name,
            ):
                filtered_urls += 1
                continue

            if not should_collect_url(
                normalized_url,
                content_type,
            ):
                filtered_urls += 1
                continue

            parsed = urlsplit(normalized_url)
            hostname = (parsed.hostname or "").lower()

            collected[normalized_url] = {
                "hostname": hostname,
                "url": normalized_url,
                "method": method,
                "status_code": status_code,
                "content_type": content_type,
            }

            target_had_results = True

        if target_had_results:
            break

    return (
        list(collected.values()),
        execution_failures,
        filtered_urls,
    )


def bulk_insert_urls(
    db: Session,
    rows: list[dict],
) -> int:
    if not rows:
        return 0

    statement = (
        insert(Url)
        .values(rows)
        .on_conflict_do_nothing(
            index_elements=[
                Url.domain_id,
                url_digest(Url.url),
            ],
        )
    )

    result = db.execute(statement)
    db.commit()

    return int(result.rowcount or 0)


def run_katana(
    db: Session,
    job: Job,
) -> None:
    domain = get_domain(db, job)

    if not domain:
        fail_job(
            db,
            job,
            "Domain not found",
        )
        return

    hosts = (
        db.query(Host)
        .filter(
            Host.domain_id == domain.id,
            Host.alive.is_(True),
        )
        .order_by(Host.id.asc())
        .all()
    )

    if not hosts:
        fail_job(
            db,
            job,
            "No alive hosts found for Katana",
        )
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Starting Katana crawl for " f"{domain.name}"
    db.commit()

    host_by_hostname = {host.hostname.lower(): host for host in hosts if host.hostname}

    collected_rows_by_url: dict[str, dict] = {}
    processed_hosts = 0
    execution_failures = 0
    filtered_urls = 0

    for host in hosts:
        if not host.hostname:
            processed_hosts += 1
            continue

        current_job = db.get(Job, job.id)

        if current_job:
            current_job.message = (
                f"Katana starting host "
                f"{processed_hosts + 1}/"
                f"{len(hosts)}: "
                f"{host.hostname}"
            )
            db.commit()

        (
            host_urls,
            host_failures,
            host_filtered_urls,
        ) = collect_host_urls(
            host,
            domain,
        )

        execution_failures += host_failures
        filtered_urls += host_filtered_urls

        for discovered in host_urls:
            hostname = discovered["hostname"]

            target_host = host_by_hostname.get(
                hostname,
                host,
            )

            collected_rows_by_url[discovered["url"]] = {
                "customer_id": domain.customer_id,
                "domain_id": domain.id,
                "host_id": target_host.id,
                "url": discovered["url"],
                "method": discovered["method"],
                "status_code": discovered["status_code"],
                "content_type": discovered["content_type"],
                "source": "katana",
            }

        processed_hosts += 1

        current_job = db.get(Job, job.id)

        if current_job:
            current_job.progress = min(
                95,
                10 + int(processed_hosts / max(len(hosts), 1) * 85),
            )

            current_job.message = (
                f"Katana crawling "
                f"{processed_hosts}/"
                f"{len(hosts)} hosts. "
                f"Unique URLs collected: "
                f"{len(collected_rows_by_url)}. "
                f"Filtered URLs: "
                f"{filtered_urls}. "
                f"Failures: "
                f"{execution_failures}"
            )

            db.commit()

    try:
        created = bulk_insert_urls(
            db,
            list(collected_rows_by_url.values()),
        )
    except Exception as exc:
        fail_job(
            db,
            job,
            ("Katana URL bulk import failed: " f"{type(exc).__name__}: {exc}"),
        )
        return

    finish_job(
        db,
        job,
        (
            f"Katana finished. "
            f"Hosts processed: {processed_hosts}. "
            f"Unique URLs collected: "
            f"{len(collected_rows_by_url)}. "
            f"New URLs created: {created}. "
            f"Filtered URLs: {filtered_urls}. "
            f"Execution failures: "
            f"{execution_failures}"
        ),
    )
