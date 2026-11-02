import json
import math
import os
import subprocess
import tempfile
import time
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.domain import Domain
from app.models.finding import Finding
from app.models.job import Job
from app.models.url import Url
from app.models.url_detail import UrlDetail
from app.plugins.nuclei_templates import DEFAULT_DIRECTORY, error_summary, prepare_templates

NUCLEI_TIMEOUT_SECONDS = 28800
NUCLEI_STALL_SECONDS = 300
MAX_URLS_PER_DOMAIN = 40
MAX_URLS_PER_ORIGIN = 12
PROGRESS_POLL_SECONDS = 5

NUCLEI_SEVERITIES = "info,low,medium,high,critical"

NUCLEI_TAGS = "http,ssl,misconfig,exposure," "panel,tech,default-login,cve"

STATIC_SUFFIXES = {
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".svg",
    ".ttf",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".xml",
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


def get_default_asset(
    db: Session,
    domain: Domain,
) -> Asset | None:
    return (
        db.query(Asset)
        .filter(
            Asset.customer_id == domain.customer_id,
        )
        .order_by(
            Asset.id.asc(),
        )
        .first()
    )


def normalize_severity(
    value: object,
) -> str:
    normalized = str(value or "info").strip().lower()

    if normalized not in {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }:
        return "info"

    return normalized


def parse_float(
    value: object,
) -> float | None:
    try:
        if value is None:
            return None

        return float(value)

    except (
        TypeError,
        ValueError,
    ):
        return None


def extract_cve(
    info: dict[str, Any],
) -> str | None:
    classification = info.get("classification") or {}

    cve_ids = classification.get("cve-id") or classification.get("cve_id") or []

    if isinstance(
        cve_ids,
        str,
    ):
        return cve_ids

    if isinstance(
        cve_ids,
        list,
    ):
        normalized = [str(value) for value in cve_ids if value]

        return ", ".join(normalized) if normalized else None

    return None


def extract_cvss_score(
    info: dict[str, Any],
) -> float | None:
    classification = info.get("classification") or {}

    return parse_float(classification.get("cvss-score") or classification.get("cvss_score"))


def extract_reference(
    info: dict[str, Any],
) -> str | None:
    references = info.get("reference") or info.get("references") or []

    if isinstance(
        references,
        str,
    ):
        return references

    if isinstance(
        references,
        list,
    ):
        normalized = [str(value) for value in references if value]

        return "\n".join(normalized) if normalized else None

    return None


def extract_remediation(
    info: dict[str, Any],
) -> str | None:
    remediation = info.get("remediation") or info.get("solution")

    return str(remediation) if remediation else None


def extract_template_id(
    item: dict[str, Any],
) -> str:
    return str(
        item.get("template-id")
        or item.get("template_id")
        or item.get("template")
        or "unknown-template"
    )


def extract_matched_url(
    item: dict[str, Any],
) -> str:
    return str(
        item.get("matched-at")
        or item.get("matched_at")
        or item.get("url")
        or item.get("host")
        or ""
    ).strip()


def extract_host(
    item: dict[str, Any],
    matched_url: str,
) -> str:
    value = str(item.get("host") or matched_url).strip()
    # Scanner records may omit host or put the complete request URL there.
    # Keep paths/queries in matched_at and raw_json, not the bounded host field.
    return origin_from_url(value) or value


def origin_from_url(
    value: str,
) -> str | None:
    try:
        parsed = urlparse(value)

        if (
            parsed.scheme
            not in {
                "http",
                "https",
            }
            or not parsed.hostname
        ):
            return None

        default_port = (parsed.scheme == "https" and parsed.port == 443) or (
            parsed.scheme == "http" and parsed.port == 80
        )

        if parsed.port and not default_port:
            return f"{parsed.scheme}://" f"{parsed.hostname.lower()}:" f"{parsed.port}"

        return f"{parsed.scheme}://" f"{parsed.hostname.lower()}"

    except ValueError:
        return None


def is_domain_scan_url(value: str, domain_name: str) -> bool:
    domain_name = domain_name.strip().lower().rstrip(".")
    # Targets are written one per line. Reject control characters before urlparse
    # can silently discard them, as well as credentials and malformed authorities.
    if not domain_name or any(ord(character) <= 32 or ord(character) == 127 for character in value):
        return False

    try:
        parsed = urlparse(value)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if (
            not origin_from_url(value)
            or parsed.username is not None
            or parsed.password is not None
            or "\\" in parsed.netloc
        ):
            return False
    except ValueError:
        return False

    return hostname == domain_name or hostname.endswith(f".{domain_name}")


def is_static_resource(
    value: str,
    content_type: str | None,
) -> bool:
    parsed = urlparse(value)
    path = parsed.path.lower()

    if any(path.endswith(suffix) for suffix in STATIC_SUFFIXES):
        return True

    normalized_content_type = (content_type or "").lower()

    blocked_types = (
        "application/javascript",
        "application/pdf",
        "application/xml",
        "audio/",
        "font/",
        "image/",
        "text/css",
        "text/javascript",
        "video/",
    )

    return normalized_content_type.startswith(blocked_types)


def url_priority(
    target: str,
    status_code: int | None,
    content_type: str | None,
) -> tuple[int, int, int, str]:
    parsed = urlparse(target)
    path = parsed.path or "/"
    normalized_path = path.lower()

    keywords = {
        "admin",
        "api",
        "auth",
        "dashboard",
        "graphql",
        "login",
        "manager",
        "oauth",
        "portal",
        "signin",
        "swagger",
        "upload",
        "wp-admin",
    }

    keyword_score = sum(1 for keyword in keywords if keyword in normalized_path)

    html_score = 1 if (content_type and "text/html" in content_type.lower()) else 0

    status_score = (
        2
        if (status_code and 200 <= status_code < 300)
        else (1 if (status_code and 300 <= status_code < 500) else 0)
    )

    root_score = (
        1
        if path
        in {
            "",
            "/",
        }
        else 0
    )

    return (
        -keyword_score,
        -root_score,
        -html_score,
        -status_score,
        len(path),
        target,
    )


def select_scan_urls(
    db: Session,
    domain: Domain,
) -> list[str]:
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
            UrlDetail.status_code.between(
                200,
                499,
            ),
        )
        .order_by(
            Url.id.asc(),
        )
        .all()
    )

    candidates: list[
        tuple[
            str,
            int | None,
            str | None,
            str,
        ]
    ] = []

    seen_targets: set[str] = set()

    for url_record, detail in rows:
        target = str(detail.final_url or url_record.url).strip()

        if (
            target in seen_targets
            or not is_domain_scan_url(url_record.url, domain.name)
            or not is_domain_scan_url(target, domain.name)
        ):
            continue

        if is_static_resource(
            target,
            detail.content_type,
        ):
            continue

        origin = origin_from_url(target)

        if not origin:
            continue

        seen_targets.add(target)

        candidates.append(
            (
                target,
                detail.status_code,
                detail.content_type,
                origin,
            )
        )

    candidates.sort(
        key=lambda item: url_priority(
            item[0],
            item[1],
            item[2],
        )
    )

    selected: list[str] = []
    origin_counts: defaultdict[
        str,
        int,
    ] = defaultdict(int)

    for (
        target,
        _status_code,
        _content_type,
        origin,
    ) in candidates:
        if origin_counts[origin] >= MAX_URLS_PER_ORIGIN:
            continue

        origin_counts[origin] += 1
        selected.append(target)

        if len(selected) >= MAX_URLS_PER_DOMAIN:
            break

    return selected


def existing_finding(
    db: Session,
    asset_id: int,
    template_id: str,
    matched_at: str,
) -> Finding | None:
    return (
        db.query(Finding)
        .filter(
            Finding.asset_id == asset_id,
            Finding.scanner == "nuclei-url",
            Finding.template_id == template_id,
            Finding.matched_at == matched_at,
        )
        .order_by(
            Finding.id.desc(),
        )
        .first()
    )


def import_nuclei_result(
    db: Session,
    job: Job,
    asset: Asset,
    item: dict[str, Any],
) -> tuple[bool, bool]:
    info = item.get("info") or {}

    template_id = extract_template_id(item)

    matched_at = extract_matched_url(item)

    if not matched_at:
        return False, False

    host = extract_host(
        item,
        matched_at,
    )

    name = str(info.get("name") or template_id)

    description = info.get("description")

    severity = normalize_severity(info.get("severity") or item.get("severity"))

    existing = existing_finding(
        db,
        asset.id,
        template_id,
        matched_at,
    )

    raw_json = json.dumps(
        item,
        ensure_ascii=False,
    )

    if existing:
        was_fixed = existing.status == "fixed"

        existing.asset_id = asset.id
        existing.job_id = job.id
        existing.scanner = "nuclei-url"
        existing.template_id = template_id
        existing.name = name
        existing.severity = severity
        existing.host = host
        existing.matched_at = matched_at
        existing.description = str(description) if description else None
        existing.remediation = extract_remediation(info)
        existing.reference = extract_reference(info)
        existing.cve = extract_cve(info)
        existing.cvss_score = extract_cvss_score(info)
        existing.raw_json = raw_json
        existing.status = "open"

        return False, was_fixed

    db.add(
        Finding(
            asset_id=asset.id,
            job_id=job.id,
            scanner="nuclei-url",
            template_id=template_id,
            name=name,
            severity=severity,
            host=host,
            matched_at=matched_at,
            description=(str(description) if description else None),
            remediation=(extract_remediation(info)),
            reference=(extract_reference(info)),
            cve=extract_cve(info),
            cvss_score=(extract_cvss_score(info)),
            raw_json=raw_json,
            status="open",
        )
    )

    # SessionLocal disables autoflush. Make this insert visible to the next
    # result's deduplication query without committing the whole import batch.
    db.flush()

    return True, False


def read_scan_stats(path: Path) -> dict | None:
    """Read a bounded log tail; findings and incomplete/noisy lines are not stats."""
    if not path.exists():
        return None
    with path.open("rb") as handle:
        handle.seek(0, 2)
        handle.seek(max(0, handle.tell() - 16384))
        lines = handle.read().decode("utf-8", errors="replace").splitlines()
    for line in reversed(lines):
        try:
            item = json.loads(line)
            if not isinstance(item, dict) or not {"percent", "requests", "total"} <= item.keys():
                continue
            percent = float(item["percent"])
            if not math.isfinite(percent) or not 0 <= percent <= 100:
                continue
            counts = {key: int(item.get(key, 0)) for key in ("requests", "total", "matched")}
            if any(value < 0 for value in counts.values()):
                continue
            return {"percent": percent, **counts}
        except (ValueError, TypeError, OverflowError):
            continue
    return None


def valid_result(item: object) -> bool:
    if not isinstance(item, dict):
        return False
    info = item.get("info", {})
    if not isinstance(info, dict):
        return False
    classification = info.get("classification", {})
    return isinstance(classification, dict) and bool(extract_matched_url(item))


@contextmanager
def retained_scan_directory(job: Job):
    root = Path(
        os.environ.get("CCVM_NUCLEI_LOG_DIR", str(DEFAULT_DIRECTORY.parent / "nuclei-runs"))
    )
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = Path(tempfile.mkdtemp(prefix=f"job-{job.id}-", dir=root))
    write_diagnostic(directory / "identity.json", {"job_id": job.id, "uuid": job.uuid})
    yield str(directory)  # Retain every attempt, including failures and partial results.


def write_diagnostic(path: Path, value: dict) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(value, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def execution_limits() -> tuple[int, int]:
    maximum = int(os.environ.get("CCVM_NUCLEI_TIMEOUT_SECONDS", NUCLEI_TIMEOUT_SECONDS))
    stall = int(os.environ.get("CCVM_NUCLEI_STALL_SECONDS", NUCLEI_STALL_SECONDS))
    if maximum <= 0 or stall <= 0:
        raise ValueError("Nuclei execution limits must be positive seconds")
    return maximum, stall


def run_nucleiurl(
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

    asset = get_default_asset(
        db,
        domain,
    )

    if not asset:
        fail_job(
            db,
            job,
            ("No customer asset found " "for Nuclei URL scan"),
        )
        return

    targets = select_scan_urls(
        db,
        domain,
    )

    if not targets:
        fail_job(
            db,
            job,
            ("No relevant reachable URLs " "found for Nuclei URL scan"),
        )
        return

    job.status = "running"
    job.progress = 5
    job.message = "Preparing Nuclei scan templates"
    db.commit()
    try:
        templates = prepare_templates()
        timeout_seconds, stall_seconds = execution_limits()
    except Exception as exc:
        fail_job(db, job, f"Nuclei template preparation failed: {type(exc).__name__}: {exc}")
        return

    job.progress = 10
    job.message = f"Starting prioritized Nuclei URL scan " f"for {len(targets)} targets"
    db.commit()

    with retained_scan_directory(job) as temporary_directory:
        working_directory = Path(temporary_directory)

        target_file = working_directory / "targets.txt"

        result_file = working_directory / "results.jsonl"

        target_file.write_text(
            "\n".join(targets) + "\n",
            encoding="utf-8",
        )

        command = [
            "nuclei",
            "-t",
            str(templates),
            "-update-template-dir",
            str(templates),
            "-l",
            str(target_file),
            "-jsonl",
            "-o",
            str(result_file),
            "-no-color",
            "-no-stdin",
            "-severity",
            NUCLEI_SEVERITIES,
            "-tags",
            NUCLEI_TAGS,
            "-scan-strategy",
            "host-spray",
            "-timeout",
            "10",
            "-retries",
            "0",
            "-rate-limit",
            "30",
            "-bulk-size",
            "10",
            "-concurrency",
            "5",
            "-headless-concurrency",
            "1",
            "-no-interactsh",
            "-disable-redirects",
            "-disable-update-check",
            "-stats",
            "-stats-json",
            "-stats-interval",
            str(PROGRESS_POLL_SECONDS),
        ]

        process: subprocess.Popen | None = None
        execution_started = time.monotonic()
        hard_timeout_reached = False
        stall_reached = False
        last_activity = 0
        last_counts = (-1, -1)
        last_stats = None

        stdout_file = working_directory / "nuclei.stdout.log"

        stderr_file = working_directory / "nuclei.stderr.log"

        try:
            with (
                stdout_file.open(
                    "w",
                    encoding="utf-8",
                ) as stdout_handle,
                stderr_file.open(
                    "w",
                    encoding="utf-8",
                ) as stderr_handle,
            ):
                process = subprocess.Popen(
                    command,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    stdin=subprocess.DEVNULL,
                    text=True,
                )

                while process.poll() is None:
                    elapsed_seconds = int(time.monotonic() - execution_started)
                    stats = read_scan_stats(stderr_file) or read_scan_stats(stdout_file)
                    if stats:
                        last_stats = stats
                        counts = (stats["requests"], stats["matched"])
                        if counts != last_counts:
                            last_counts, last_activity = counts, elapsed_seconds
                    write_diagnostic(
                        working_directory / "progress.json",
                        {
                            "elapsed_seconds": elapsed_seconds,
                            "last_stats": last_stats,
                            "last_activity_seconds": last_activity,
                            "timeout_seconds": timeout_seconds,
                            "stall_seconds": stall_seconds,
                        },
                    )

                    if (
                        elapsed_seconds >= timeout_seconds
                        or elapsed_seconds - last_activity >= stall_seconds
                    ):
                        hard_timeout_reached = elapsed_seconds >= timeout_seconds
                        stall_reached = not hard_timeout_reached

                        process.terminate()

                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()

                        break

                    current_job = db.get(
                        Job,
                        job.id,
                    )

                    if current_job:
                        if stats:
                            current_job.progress = max(
                                current_job.progress,
                                10 + int(stats["percent"] * 0.65),
                            )
                        statistics = (
                            f"Requests: {stats['requests']}/{stats['total']}. "
                            f"Results: {stats['matched']}"
                            if stats
                            else "Waiting for scanner statistics"
                        )
                        current_job.message = (
                            "Nuclei URL scan running. "
                            f"Targets: {len(targets)}. "
                            f"Elapsed: {elapsed_seconds}s. "
                            f"Limit: {timeout_seconds}s. "
                            f"{statistics}"
                        )
                        db.commit()

                    time.sleep(PROGRESS_POLL_SECONDS)

            stdout = (
                stdout_file.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                if stdout_file.exists()
                else ""
            )

            stderr = (
                stderr_file.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                if stderr_file.exists()
                else ""
            )

            return_code = (
                124
                if hard_timeout_reached or stall_reached
                else (process.returncode if process is not None else 1)
            )
            last_stats = read_scan_stats(stderr_file) or read_scan_stats(stdout_file) or last_stats
            write_diagnostic(
                working_directory / "execution.json",
                {
                    "return_code": return_code,
                    "hard_timeout": hard_timeout_reached,
                    "stalled": stall_reached,
                    "last_stats": last_stats,
                    "timeout_seconds": timeout_seconds,
                    "stall_seconds": stall_seconds,
                },
            )

            result = subprocess.CompletedProcess(
                args=command,
                returncode=return_code,
                stdout=stdout,
                stderr=stderr,
            )

        except Exception as exc:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()

            write_diagnostic(
                working_directory / "execution.json",
                {
                    "exception": f"{type(exc).__name__}: {exc}",
                    "last_stats": last_stats,
                    "timeout_seconds": timeout_seconds,
                    "stall_seconds": stall_seconds,
                },
            )
            fail_job(
                db,
                job,
                (
                    "Nuclei URL execution failed: "
                    f"{type(exc).__name__}: "
                    f"{exc}. "
                    f"Diagnostics: {working_directory}"
                ),
            )
            return

        current_job = db.get(
            Job,
            job.id,
        )

        if current_job:
            current_job.progress = 80
            current_job.message = "Nuclei execution ended. " "Importing URL findings"
            db.commit()

        created = 0
        updated = 0
        reopened = 0
        malformed = 0

        if result_file.exists():
            with result_file.open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:
                for line in handle:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        item = json.loads(line)

                    except json.JSONDecodeError:
                        malformed += 1
                        continue

                    if not valid_result(item):
                        malformed += 1
                        continue

                    (
                        was_created,
                        was_reopened,
                    ) = import_nuclei_result(
                        db,
                        job,
                        asset,
                        item,
                    )

                    if was_created:
                        created += 1

                    elif was_reopened:
                        reopened += 1

                    else:
                        updated += 1

                    if (created + updated + reopened) % 25 == 0:
                        db.commit()

        db.commit()

        summary = (
            f"Targets: {len(targets)}. Created: {created}. Updated: {updated}. "
            f"Reopened: {reopened}. Malformed results: {malformed}"
        )
        statistics = (
            f" Requests: {last_stats['requests']}/{last_stats['total']}. "
            f"Results: {last_stats['matched']}."
            if last_stats
            else " No scanner statistics received."
        )
        if result.returncode != 0 or malformed:
            reason = (
                f"hard timeout after {timeout_seconds}s"
                if hard_timeout_reached
                else (
                    f"no scanner progress for {stall_seconds}s"
                    if stall_reached
                    else (
                        f"exit code {result.returncode}"
                        if result.returncode != 0
                        else "malformed scanner output"
                    )
                )
            )
            fail_job(
                db,
                job,
                (
                    f"Nuclei URL scan incomplete: {reason}. "
                    f"Partial findings retained. {summary}.{statistics} "
                    f"Diagnostics: {working_directory}. "
                    f"Error: {error_summary(result.stdout, result.stderr, limit=250)}"
                ),
            )
            return

    finish_job(
        db,
        job,
        f"Nuclei URL scan finished. {summary}.{statistics}",
    )
