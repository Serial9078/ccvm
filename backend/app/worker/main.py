import json
import re
import subprocess
import time
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.models.asset import Asset
from app.models.domain import Domain
from app.models.finding import Finding
from app.models.host import Host
from app.models.job import Job
from app.models.port import Port
from app.models.subdomain import Subdomain
from app.models.technology import Technology
from app.models.url import Url


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
):
    job.status = "failed"
    job.progress = 100
    job.message = message
    db.commit()


def finish_job(
    db: Session,
    job: Job,
    message: str,
):
    job.status = "finished"
    job.progress = 100
    job.message = message
    db.commit()


def normalize_nuclei_finding(
    item: dict,
    asset_id: int,
    job_id: int,
) -> Finding:
    info = item.get("info", {}) or {}
    classification = info.get("classification", {}) or {}

    references = info.get("reference") or []

    if isinstance(references, list):
        references = "\n".join(
            str(reference)
            for reference in references
        )

    cve = classification.get("cve-id")

    if isinstance(cve, list):
        cve = ",".join(cve)

    cvss_score = classification.get("cvss-score")

    return Finding(
        asset_id=asset_id,
        job_id=job_id,
        scanner="nuclei",
        template_id=item.get("template-id"),
        name=(
            info.get("name")
            or item.get("template-id")
            or "Nuclei Finding"
        ),
        severity=info.get("severity", "info"),
        host=item.get("host"),
        matched_at=(
            item.get("matched-at")
            or item.get("matched")
        ),
        description=info.get("description"),
        remediation=info.get("remediation"),
        reference=references,
        cve=cve,
        cvss_score=(
            str(cvss_score)
            if cvss_score is not None
            else None
        ),
        raw_json=json.dumps(item),
        status="open",
    )


def run_subfinder(
    db: Session,
    job: Job,
):
    domain = get_domain(db, job)

    if not domain:
        fail_job(db, job, "Domain not found")
        return

    job.status = "running"
    job.progress = 10
    job.message = (
        f"Starting Subfinder discovery for {domain.name}"
    )
    db.commit()

    try:
        result = subprocess.run(
            [
                "subfinder",
                "-d",
                domain.name,
                "-silent",
            ],
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
    except Exception as exc:
        fail_job(
            db,
            job,
            f"Subfinder execution failed: {exc}",
        )
        return

    discovered = 0

    for line in result.stdout.splitlines():
        name = line.strip().lower()

        if not name or " " in name:
            continue

        existing = (
            db.query(Subdomain)
            .filter(
                Subdomain.domain_id == domain.id,
                Subdomain.name == name,
            )
            .first()
        )

        if existing:
            continue

        db.add(
            Subdomain(
                customer_id=domain.customer_id,
                domain_id=domain.id,
                name=name,
                source="subfinder",
            )
        )
        discovered += 1

    if result.returncode != 0:
        fail_job(
            db,
            job,
            (
                f"Subfinder failed. New subdomains: "
                f"{discovered}. Output: "
                f"{result.stderr[-1000:]}"
            ),
        )
        return

    finish_job(
        db,
        job,
        (
            f"Subfinder finished. "
            f"New subdomains: {discovered}"
        ),
    )


def run_dnsx(
    db: Session,
    job: Job,
):
    domain = get_domain(db, job)

    if not domain:
        fail_job(db, job, "Domain not found")
        return

    subdomains = (
        db.query(Subdomain)
        .filter(Subdomain.domain_id == domain.id)
        .order_by(Subdomain.id.asc())
        .all()
    )

    if not subdomains:
        fail_job(
            db,
            job,
            "No subdomains found for DNSX",
        )
        return

    job.status = "running"
    job.progress = 10
    job.message = (
        f"Starting DNSX resolve for {domain.name}"
    )
    db.commit()

    input_data = (
        "\n".join(
            subdomain.name
            for subdomain in subdomains
        )
        + "\n"
    )

    try:
        result = subprocess.run(
            [
                "dnsx",
                "-silent",
                "-a",
                "-resp",
            ],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
    except Exception as exc:
        fail_job(
            db,
            job,
            f"DNSX execution failed: {exc}",
        )
        return

    created = 0

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        hostname = line.split()[0].strip().lower()

        ip_match = re.search(
            r"(\d{1,3}(?:\.\d{1,3}){3})",
            line,
        )

        ip_address = (
            ip_match.group(1)
            if ip_match
            else None
        )

        subdomain = (
            db.query(Subdomain)
            .filter(
                Subdomain.domain_id == domain.id,
                Subdomain.name == hostname,
            )
            .first()
        )

        existing = (
            db.query(Host)
            .filter(
                Host.customer_id == domain.customer_id,
                Host.hostname == hostname,
                Host.ip_address == ip_address,
            )
            .first()
        )

        if existing:
            continue

        db.add(
            Host(
                customer_id=domain.customer_id,
                domain_id=domain.id,
                subdomain_id=(
                    subdomain.id
                    if subdomain
                    else None
                ),
                hostname=hostname,
                ip_address=ip_address,
                alive=True,
                source="dnsx",
            )
        )
        created += 1

    if result.returncode != 0:
        fail_job(
            db,
            job,
            (
                f"DNSX failed. Hosts created: "
                f"{created}. Output: "
                f"{result.stderr[-1000:]}"
            ),
        )
        return

    finish_job(
        db,
        job,
        f"DNSX finished. Hosts created: {created}",
    )


def run_httpx(
    db: Session,
    job: Job,
):
    domain = get_domain(db, job)

    if not domain:
        fail_job(db, job, "Domain not found")
        return

    hosts = (
        db.query(Host)
        .filter(Host.domain_id == domain.id)
        .order_by(Host.id.asc())
        .all()
    )

    if not hosts:
        fail_job(
            db,
            job,
            "No hosts found for HTTPX",
        )
        return

    job.status = "running"
    job.progress = 10
    job.message = (
        f"Starting HTTPX probing for {domain.name}"
    )
    db.commit()

    input_data = (
        "\n".join(
            sorted(
                {
                    host.hostname
                    for host in hosts
                    if host.hostname
                }
            )
        )
        + "\n"
    )

    try:
        result = subprocess.run(
            [
                "httpx",
                "-silent",
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-ip",
                "-cdn",
                "-follow-redirects",
            ],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=1200,
            check=False,
        )
    except Exception as exc:
        fail_job(
            db,
            job,
            f"HTTPX execution failed: {exc}",
        )
        return

    hosts_updated = 0
    technologies_created = 0

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line.startswith("{"):
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        input_host = (
            item.get("input")
            or item.get("host")
            or ""
        )

        hostname = (
            str(input_host)
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .split(":")[0]
            .strip()
            .lower()
        )

        if not hostname:
            continue

        host = (
            db.query(Host)
            .filter(
                Host.domain_id == domain.id,
                Host.hostname == hostname,
            )
            .first()
        )

        if not host:
            continue

        host.alive = True
        hosts_updated += 1

        tech_values = (
            item.get("tech")
            or item.get("technologies")
            or []
        )

        if isinstance(tech_values, str):
            tech_values = [tech_values]

        for technology_name in tech_values:
            technology_name = str(
                technology_name
            ).strip()

            if not technology_name:
                continue

            existing = (
                db.query(Technology)
                .filter(
                    Technology.host_id == host.id,
                    Technology.name == technology_name,
                )
                .first()
            )

            if existing:
                continue

            db.add(
                Technology(
                    host_id=host.id,
                    name=technology_name,
                    category="web",
                    source="httpx",
                )
            )
            technologies_created += 1

    if result.returncode != 0:
        fail_job(
            db,
            job,
            (
                f"HTTPX failed. Output: "
                f"{result.stderr[-1000:]}"
            ),
        )
        return

    finish_job(
        db,
        job,
        (
            f"HTTPX finished. Hosts updated: "
            f"{hosts_updated}. Technologies created: "
            f"{technologies_created}"
        ),
    )


def run_naabu(
    db: Session,
    job: Job,
):
    domain = get_domain(db, job)

    if not domain:
        fail_job(db, job, "Domain not found")
        return

    hosts = (
        db.query(Host)
        .filter(Host.domain_id == domain.id)
        .order_by(Host.id.asc())
        .all()
    )

    if not hosts:
        fail_job(
            db,
            job,
            "No hosts found for Naabu",
        )
        return

    job.status = "running"
    job.progress = 10
    job.message = (
        f"Starting Naabu port discovery for "
        f"{domain.name}"
    )
    db.commit()

    input_data = (
        "\n".join(
            sorted(
                {
                    host.hostname
                    for host in hosts
                    if host.hostname
                }
            )
        )
        + "\n"
    )

    try:
        result = subprocess.run(
            [
                "naabu",
                "-silent",
                "-json",
                "-top-ports",
                "100",
            ],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
    except Exception as exc:
        fail_job(
            db,
            job,
            f"Naabu execution failed: {exc}",
        )
        return

    created = 0
    seen: set[tuple[int, int, str]] = set()

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line.startswith("{"):
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        target = str(
            item.get("host")
            or item.get("ip")
            or ""
        ).strip().lower()

        port_number = item.get("port")

        if not target or not port_number:
            continue

        host = (
            db.query(Host)
            .filter(
                Host.domain_id == domain.id,
                Host.hostname == target,
            )
            .first()
        )

        if not host:
            host = (
                db.query(Host)
                .filter(
                    Host.domain_id == domain.id,
                    Host.ip_address == target,
                )
                .first()
            )

        if not host:
            continue

        key = (
            host.id,
            int(port_number),
            "tcp",
        )

        if key in seen:
            continue

        seen.add(key)

        existing = (
            db.query(Port)
            .filter(
                Port.host_id == host.id,
                Port.port == int(port_number),
                Port.protocol == "tcp",
            )
            .first()
        )

        if existing:
            continue

        db.add(
            Port(
                host_id=host.id,
                port=int(port_number),
                protocol="tcp",
                service=item.get("service"),
                banner=None,
                source="naabu",
            )
        )
        created += 1

    if result.returncode != 0:
        fail_job(
            db,
            job,
            (
                f"Naabu failed. Ports created: "
                f"{created}. Output: "
                f"{result.stderr[-1000:]}"
            ),
        )
        return

    finish_job(
        db,
        job,
        f"Naabu finished. Ports created: {created}",
    )


def extract_katana_url(
    item: dict,
) -> tuple[str | None, str, int | None, str | None]:
    request_data = item.get("request") or {}
    response_data = item.get("response") or {}

    url = (
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
        status_code = (
            int(status_code)
            if status_code is not None
            else None
        )
    except (TypeError, ValueError):
        status_code = None

    return (
        str(url).strip()
        if url
        else None,
        str(method).upper(),
        status_code,
        str(content_type)
        if content_type
        else None,
    )


def run_katana(
    db: Session,
    job: Job,
):
    domain = get_domain(db, job)

    if not domain:
        fail_job(db, job, "Domain not found")
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
        f"Starting Katana crawl for {domain.name}"
    )
    db.commit()

    created = 0
    processed_hosts = 0
    failures = 0

    for index, host in enumerate(hosts, start=1):
        if not host.hostname:
            continue

        targets = [
            f"https://{host.hostname}",
            f"http://{host.hostname}",
        ]

        host_had_output = False

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
                        "2",
                        "-jc",
                        "-kf",
                        "all",
                        "-timeout",
                        "10",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=900,
                    check=False,
                )
            except Exception:
                failures += 1
                continue

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

                parsed = urlparse(discovered_url)

                if not parsed.scheme or not parsed.netloc:
                    continue

                hostname = (
                    parsed.hostname
                    or ""
                ).lower()

                if not (
                    hostname == domain.name
                    or hostname.endswith(
                        f".{domain.name}"
                    )
                ):
                    continue

                target_host = (
                    db.query(Host)
                    .filter(
                        Host.domain_id == domain.id,
                        Host.hostname == hostname,
                    )
                    .first()
                )

                existing = (
                    db.query(Url)
                    .filter(
                        Url.domain_id == domain.id,
                        Url.url == discovered_url,
                    )
                    .first()
                )

                if existing:
                    continue

                db.add(
                    Url(
                        customer_id=domain.customer_id,
                        domain_id=domain.id,
                        host_id=(
                            target_host.id
                            if target_host
                            else host.id
                        ),
                        url=discovered_url,
                        method=method,
                        status_code=status_code,
                        content_type=content_type,
                        source="katana",
                    )
                )

                created += 1
                host_had_output = True

            if host_had_output:
                break

        processed_hosts += 1

        job.progress = min(
            95,
            10 + int(
                processed_hosts
                / max(len(hosts), 1)
                * 85
            ),
        )

        job.message = (
            f"Katana crawling {processed_hosts}/"
            f"{len(hosts)} hosts. URLs found: "
            f"{created}"
        )
        db.commit()

    finish_job(
        db,
        job,
        (
            f"Katana finished. Hosts processed: "
            f"{processed_hosts}. URLs created: "
            f"{created}. Execution failures: "
            f"{failures}"
        ),
    )


def run_nuclei(
    db: Session,
    job: Job,
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == job.asset_id)
        .first()
    )

    if not asset:
        fail_job(db, job, "Asset not found")
        return

    job.status = "running"
    job.progress = 10
    job.message = (
        f"Starting Nuclei scan for {asset.target}"
    )
    db.commit()

    try:
        result = subprocess.run(
            [
                "nuclei",
                "-u",
                asset.target,
                "-severity",
                "critical,high,medium,low,info",
                "-jsonl",
                "-silent",
            ],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
    except Exception as exc:
        fail_job(
            db,
            job,
            f"Nuclei execution failed: {exc}",
        )
        return

    findings_created = 0

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line.startswith("{"):
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        db.add(
            normalize_nuclei_finding(
                item,
                asset.id,
                job.id,
            )
        )
        findings_created += 1

    if result.returncode != 0:
        fail_job(
            db,
            job,
            (
                f"Nuclei failed. Findings created: "
                f"{findings_created}. Output: "
                f"{result.stderr[-1000:]}"
            ),
        )
        return

    finish_job(
        db,
        job,
        (
            f"Nuclei scan finished. "
            f"Findings created: {findings_created}"
        ),
    )


def run_dummy(
    db: Session,
    job: Job,
):
    for progress in [5, 25, 50, 75, 100]:
        job.status = "running"
        job.progress = progress
        job.message = (
            f"Dummy job progress {progress}%"
        )
        db.commit()
        time.sleep(2)

    finish_job(
        db,
        job,
        "Dummy scan finished successfully",
    )


def process_job(
    db: Session,
    job: Job,
):
    job.worker = "ccvm-worker-01"
    db.commit()

    if job.plugin == "subfinder":
        run_subfinder(db, job)

    elif job.plugin == "dnsx":
        run_dnsx(db, job)

    elif job.plugin == "httpx":
        run_httpx(db, job)

    elif job.plugin == "naabu":
        run_naabu(db, job)

    elif job.plugin == "katana":
        run_katana(db, job)

    elif job.plugin == "nuclei":
        run_nuclei(db, job)

    else:
        run_dummy(db, job)


def worker():
    print(
        "CCVM worker started",
        flush=True,
    )

    while True:
        db = SessionLocal()

        try:
            job = (
                db.query(Job)
                .filter(Job.status == "queued")
                .order_by(Job.id.asc())
                .first()
            )

            if job:
                print(
                    (
                        f"Processing job {job.id} "
                        f"with plugin {job.plugin}"
                    ),
                    flush=True,
                )

                process_job(db, job)

        except Exception as exc:
            db.rollback()

            print(
                f"Worker loop error: {exc}",
                flush=True,
            )

        finally:
            db.close()

        time.sleep(2)


if __name__ == "__main__":
    worker()
