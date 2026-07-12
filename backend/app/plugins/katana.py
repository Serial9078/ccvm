import json
import subprocess
from urllib.parse import urlparse

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.host import Host
from app.models.job import Job
from app.models.url import Url


KATANA_TIMEOUT_SECONDS = 45
KATANA_DEPTH = 2
KATANA_CRAWL_DURATION = "30s"


def get_domain(
    db: Session,
    job: Job,
) -> Domain | None:
    return (
        db.query(Domain)
        .filter(Domain.id == job.domain_id)
        .first()
    )


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
    request_data = item.get("request") or {}
    response_data = item.get("response") or {}

    discovered_url = (
        item.get("url")
        or item.get("endpoint")
        or request_data.get("endpoint")
        or request_data.get("url")
    )

    method = (
        item.get("method")
        or request_data.get("method")
        or "GET"
    )

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
        normalized_status_code = (
            int(status_code)
            if status_code is not None
            else None
        )
    except (TypeError, ValueError):
        normalized_status_code = None

    return (
        str(discovered_url).strip()
        if discovered_url
        else None,
        str(method).upper(),
        normalized_status_code,
        str(content_type)
        if content_type
        else None,
    )


def normalize_url(
    value: str,
) -> str:
    return value.strip()


def is_domain_url(
    discovered_url: str,
    domain_name: str,
) -> bool:
    parsed = urlparse(discovered_url)

    if not parsed.scheme or not parsed.netloc:
        return False

    hostname = (parsed.hostname or "").lower()
    normalized_domain = domain_name.lower()

    return (
        hostname == normalized_domain
        or hostname.endswith(
            f".{normalized_domain}"
        )
    )


def collect_host_urls(
    host: Host,
    domain: Domain,
) -> tuple[list[dict], int]:
    collected: dict[str, dict] = {}
    execution_failures = 0

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

            discovered_url = normalize_url(
                discovered_url
            )

            if not is_domain_url(
                discovered_url,
                domain.name,
            ):
                continue

            parsed = urlparse(discovered_url)
            hostname = (
                parsed.hostname
                or ""
            ).lower()

            collected[discovered_url] = {
                "hostname": hostname,
                "url": discovered_url,
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
                "domain_id",
                "url",
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
    job.message = (
        f"Starting Katana crawl for "
        f"{domain.name}"
    )
    db.commit()

    host_by_hostname = {
        host.hostname.lower(): host
        for host in hosts
        if host.hostname
    }

    collected_rows_by_url: dict[str, dict] = {}
    processed_hosts = 0
    execution_failures = 0

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

        host_urls, host_failures = collect_host_urls(
            host,
            domain,
        )

        execution_failures += host_failures

        for discovered in host_urls:
            hostname = discovered["hostname"]

            target_host = host_by_hostname.get(
                hostname,
                host,
            )

            collected_rows_by_url[
                discovered["url"]
            ] = {
                "customer_id": domain.customer_id,
                "domain_id": domain.id,
                "host_id": target_host.id,
                "url": discovered["url"],
                "method": discovered["method"],
                "status_code": discovered[
                    "status_code"
                ],
                "content_type": discovered[
                    "content_type"
                ],
                "source": "katana",
            }

        processed_hosts += 1

        current_job = db.get(Job, job.id)

        if current_job:
            current_job.progress = min(
                95,
                10
                + int(
                    processed_hosts
                    / max(len(hosts), 1)
                    * 85
                ),
            )

            current_job.message = (
                f"Katana crawling "
                f"{processed_hosts}/"
                f"{len(hosts)} hosts. "
                f"Unique URLs collected: "
                f"{len(collected_rows_by_url)}. "
                f"Failures: "
                f"{execution_failures}"
            )

            db.commit()

    try:
        created = bulk_insert_urls(
            db,
            list(
                collected_rows_by_url.values()
            ),
        )
    except Exception as exc:
        fail_job(
            db,
            job,
            (
                "Katana URL bulk import failed: "
                f"{type(exc).__name__}: {exc}"
            ),
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
            f"Execution failures: "
            f"{execution_failures}"
        ),
    )
