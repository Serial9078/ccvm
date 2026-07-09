import json
import re
import subprocess
import time

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


def normalize_nuclei_finding(item: dict, asset_id: int, job_id: int) -> Finding:
    info = item.get("info", {}) or {}
    classification = info.get("classification", {}) or {}

    references = info.get("reference") or []
    if isinstance(references, list):
        references = "\n".join(str(r) for r in references)

    cve = classification.get("cve-id")
    if isinstance(cve, list):
        cve = ",".join(cve)

    return Finding(
        asset_id=asset_id,
        job_id=job_id,
        scanner="nuclei",
        template_id=item.get("template-id"),
        name=info.get("name") or item.get("template-id") or "Nuclei Finding",
        severity=info.get("severity", "info"),
        host=item.get("host"),
        matched_at=item.get("matched-at") or item.get("matched"),
        description=info.get("description"),
        remediation=info.get("remediation"),
        reference=references,
        cve=cve,
        cvss_score=str(classification.get("cvss-score")) if classification.get("cvss-score") else None,
        raw_json=json.dumps(item),
        status="open",
    )


def get_domain(db: Session, job: Job) -> Domain | None:
    return db.query(Domain).filter(Domain.id == job.domain_id).first()


def fail_job(db: Session, job: Job, message: str):
    job.status = "failed"
    job.progress = 100
    job.message = message
    db.commit()


def run_subfinder(db: Session, job: Job):
    domain = get_domain(db, job)
    if not domain:
        fail_job(db, job, "Domain not found")
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Starting Subfinder discovery for {domain.name}"
    db.commit()

    result = subprocess.run(["subfinder", "-d", domain.name, "-silent"], capture_output=True, text=True, timeout=900)
    output = "\n".join([result.stdout or "", result.stderr or ""])
    discovered = 0

    for line in output.splitlines():
        name = line.strip().lower()
        if not name or " " in name:
            continue

        exists = db.query(Subdomain).filter(Subdomain.domain_id == domain.id, Subdomain.name == name).first()
        if exists:
            continue

        db.add(Subdomain(customer_id=domain.customer_id, domain_id=domain.id, name=name, source="subfinder"))
        discovered += 1

    job.progress = 100
    job.status = "finished" if result.returncode == 0 else "failed"
    job.message = f"Subfinder finished. New subdomains: {discovered}" if result.returncode == 0 else f"Subfinder failed. Output: {output[-1000:]}"
    db.commit()


def run_dnsx(db: Session, job: Job):
    domain = get_domain(db, job)
    if not domain:
        fail_job(db, job, "Domain not found")
        return

    subdomains = db.query(Subdomain).filter(Subdomain.domain_id == domain.id).order_by(Subdomain.id.asc()).all()
    if not subdomains:
        fail_job(db, job, "No subdomains found for DNSX")
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Starting DNSX resolve for {domain.name}"
    db.commit()

    input_data = "\n".join([s.name for s in subdomains]) + "\n"
    result = subprocess.run(["dnsx", "-silent", "-a", "-resp"], input=input_data, capture_output=True, text=True, timeout=900)
    output = "\n".join([result.stdout or "", result.stderr or ""])
    created = 0

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        hostname = line.split()[0].strip().lower()
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        ip_address = ip_match.group(1) if ip_match else None

        subdomain = db.query(Subdomain).filter(Subdomain.domain_id == domain.id, Subdomain.name == hostname).first()
        exists = db.query(Host).filter(
            Host.customer_id == domain.customer_id,
            Host.hostname == hostname,
            Host.ip_address == ip_address,
        ).first()

        if exists:
            continue

        db.add(Host(
            customer_id=domain.customer_id,
            domain_id=domain.id,
            subdomain_id=subdomain.id if subdomain else None,
            hostname=hostname,
            ip_address=ip_address,
            alive=True,
            source="dnsx",
        ))
        created += 1

    job.progress = 100
    job.status = "finished" if result.returncode == 0 else "failed"
    job.message = f"DNSX finished. Hosts created: {created}" if result.returncode == 0 else f"DNSX failed. Output: {output[-1000:]}"
    db.commit()


def run_httpx(db: Session, job: Job):
    domain = get_domain(db, job)
    if not domain:
        fail_job(db, job, "Domain not found")
        return

    hosts = db.query(Host).filter(Host.domain_id == domain.id).order_by(Host.id.asc()).all()
    if not hosts:
        fail_job(db, job, "No hosts found for HTTPX")
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Starting HTTPX probing for {domain.name}"
    db.commit()

    input_data = "\n".join(sorted({h.hostname for h in hosts if h.hostname})) + "\n"
    cmd = ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code", "-ip", "-cdn", "-follow-redirects"]

    result = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=1200)
    output = "\n".join([result.stdout or "", result.stderr or ""])
    technologies_created = 0
    hosts_updated = 0

    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        input_host = item.get("input") or item.get("host") or item.get("url", "").replace("https://", "").replace("http://", "").split("/")[0]
        hostname = str(input_host).strip().lower()
        if not hostname:
            continue

        host = db.query(Host).filter(Host.domain_id == domain.id, Host.hostname == hostname).first()
        if not host:
            host = Host(customer_id=domain.customer_id, domain_id=domain.id, hostname=hostname, ip_address=item.get("host"), alive=True, source="httpx")
            db.add(host)
            db.flush()
        else:
            host.alive = True
            if item.get("host") and not host.ip_address:
                host.ip_address = item.get("host")
            hosts_updated += 1

        tech_values = item.get("tech") or item.get("technologies") or []
        if isinstance(tech_values, str):
            tech_values = [tech_values]

        for tech in tech_values:
            tech_name = str(tech).strip()
            if not tech_name:
                continue

            exists = db.query(Technology).filter(Technology.host_id == host.id, Technology.name == tech_name).first()
            if exists:
                continue

            db.add(Technology(host_id=host.id, name=tech_name, category="web", source="httpx"))
            technologies_created += 1

    job.progress = 100
    job.status = "finished" if result.returncode == 0 else "failed"
    job.message = f"HTTPX finished. Hosts updated: {hosts_updated}. Technologies created: {technologies_created}" if result.returncode == 0 else f"HTTPX failed. Output: {output[-1000:]}"
    db.commit()


def run_naabu(db: Session, job: Job):
    domain = get_domain(db, job)
    if not domain:
        fail_job(db, job, "Domain not found")
        return

    hosts = db.query(Host).filter(Host.domain_id == domain.id).order_by(Host.id.asc()).all()
    if not hosts:
        fail_job(db, job, "No hosts found for Naabu")
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Starting Naabu port discovery for {domain.name}"
    db.commit()

    targets = sorted({h.hostname for h in hosts if h.hostname})
    input_data = "\n".join(targets) + "\n"

    cmd = ["naabu", "-silent", "-json", "-top-ports", "100"]

    result = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=1800)
    output = "\n".join([result.stdout or "", result.stderr or ""])
    created = 0

    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        hostname = str(item.get("host") or item.get("ip") or "").strip().lower()
        port_number = item.get("port")

        if not hostname or not port_number:
            continue

        host = db.query(Host).filter(Host.domain_id == domain.id, Host.hostname == hostname).first()

        if not host:
            host = db.query(Host).filter(Host.domain_id == domain.id, Host.ip_address == hostname).first()

        if not host:
            continue

        exists = db.query(Port).filter(Port.host_id == host.id, Port.port == int(port_number), Port.protocol == "tcp").first()
        if exists:
            continue

        db.add(Port(
            host_id=host.id,
            port=int(port_number),
            protocol="tcp",
            service=item.get("service"),
            banner=None,
            source="naabu",
        ))
        created += 1

    job.progress = 100
    job.status = "finished" if result.returncode == 0 else "failed"
    job.message = f"Naabu finished. Ports created: {created}" if result.returncode == 0 else f"Naabu failed. Ports created: {created}. Output: {output[-1000:]}"
    db.commit()


def run_nuclei(db: Session, job: Job):
    asset = db.query(Asset).filter(Asset.id == job.asset_id).first()
    if not asset:
        fail_job(db, job, "Asset not found")
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Starting Nuclei scan for {asset.target}"
    db.commit()

    cmd = ["nuclei", "-u", asset.target, "-severity", "critical,high,medium,low,info", "-jsonl", "-silent"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    combined_output = "\n".join([result.stdout or "", result.stderr or ""])
    findings_created = 0

    for line in combined_output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        db.add(normalize_nuclei_finding(item, asset.id, job.id))
        findings_created += 1

    job.progress = 100
    job.status = "finished" if result.returncode == 0 else "failed"
    job.message = f"Nuclei scan finished. Findings created: {findings_created}" if result.returncode == 0 else f"Nuclei failed. Output: {combined_output[-1000:]}"
    db.commit()


def run_dummy(db: Session, job: Job):
    for progress in [5, 25, 50, 75, 100]:
        job.status = "running"
        job.progress = progress
        job.message = f"Dummy job progress {progress}%"
        db.commit()
        time.sleep(2)

    job.status = "finished"
    job.message = "Dummy scan finished successfully"
    db.commit()


def process_job(db: Session, job: Job):
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
    elif job.plugin == "nuclei":
        run_nuclei(db, job)
    else:
        run_dummy(db, job)


def worker():
    print("CCVM worker started", flush=True)

    while True:
        db = SessionLocal()

        try:
            job = db.query(Job).filter(Job.status == "queued").order_by(Job.id.asc()).first()

            if job:
                print(f"Processing job {job.id} with plugin {job.plugin}", flush=True)
                process_job(db, job)

        except Exception as exc:
            print(f"Worker loop error: {exc}", flush=True)

        finally:
            db.close()

        time.sleep(2)


if __name__ == "__main__":
    worker()
