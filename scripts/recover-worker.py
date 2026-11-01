"""Explicit maintenance for interrupted jobs; no automatic recovery on worker startup."""

import argparse
import fcntl
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

BRANCH = "sprint-1.0.2-feature-architecture"
ACTIVE = {"queued", "running"}
TERMINAL = {"finished", "failed", "skipped", "cancelled"}
STAGES = (
    "subfinder",
    "dnsx",
    "httpx",
    "naabu",
    "katana",
    "urlprobe",
    "headerprobe",
    "headerfindings",
    "screenshot",
    "nucleiurl",
)
ALLOWED_CHANGES = {
    "backend/app/plugins/nucleiurl.py",
    "backend/integration/test_postgres_migrations.py",
    "backend/tests/test_neptun_features.py",
    "backend/tests/test_worker_recovery.py",
    "docs/backend-quality.md",
    "docs/worker-recovery.md",
    "scripts/recover-worker.py",
}

# This runs in the existing backend container, using its normal application
# connection. The host has stopped the worker and fsynced the API snapshots.
# No credentials are read by the host or printed, and no schema is changed.
RECOVER_IN_BACKEND = """
import json
import sys
import app.models
from sqlalchemy import text
from app.database.session import SessionLocal
from app.models.job import Job

payload = json.load(sys.stdin)
if payload.get("worker_stopped") is not True:
    raise RuntimeError("Worker stop was not confirmed")
snapshots = payload["jobs"]
fields = {
    "id", "uuid", "asset_id", "domain_id", "parent_job_id", "pipeline_id",
    "plugin", "status", "progress", "message", "worker",
}
if not snapshots or any(set(row) != fields for row in snapshots):
    raise RuntimeError("Incomplete job snapshot")
ids = [row["id"] for row in snapshots]
if len(ids) != len(set(ids)):
    raise RuntimeError("Duplicate job IDs")
closed = []
with SessionLocal.begin() as db:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SET LOCAL lock_timeout = '3s'"))
        db.execute(text("SET LOCAL statement_timeout = '10s'"))
    rows = (
        db.query(Job).filter(Job.id.in_(ids)).order_by(Job.id)
        .populate_existing().with_for_update(nowait=True).all()
    )
    by_id = {row.id: row for row in rows}
    if set(by_id) != set(ids):
        raise RuntimeError("Selected job disappeared")
    active = db.query(Job).filter(Job.status.in_(["queued", "running"])).all()
    if any(row.id not in ids for row in active):
        raise RuntimeError("Another active job appeared; transaction rolled back")
    # Check every snapshot before changing any record.
    for before in snapshots:
        row = by_id[before["id"]]
        if any(getattr(row, field) != before[field] for field in fields):
            raise RuntimeError("Job changed since backup: " + str(row.id))
        if row.status not in {"running", "finished", "failed", "skipped", "cancelled"}:
            raise RuntimeError("Selected job is not interrupted or terminal")
    for before in snapshots:
        row = by_id[before["id"]]
        if row.status == "running":
            row.status = "failed"
            row.progress = 100
            row.message = (
                "Interrupted during controlled worker recovery; execution was not completed. "
                "Previous state is preserved in the operator backup."
            )
            closed.append(row.id)
print(json.dumps({"closed_as_failed": closed}), flush=True)
"""


def command(root, *args, input_text=None, include_stderr=False):
    result = subprocess.run(
        args, cwd=root, input=input_text, text=True, capture_output=True, check=False
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-2000:]
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {detail}")
    return (result.stdout + (result.stderr if include_stderr else "")).strip()


class API:
    def __init__(self):
        self.opener = build_opener(ProxyHandler({}))

    def request(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = Request(
            "http://127.0.0.1:8088" + path,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        # Mutating requests are deliberately never retried.
        with self.opener.open(request, timeout=30) as response:
            return json.load(response)


def parse_job(value):
    try:
        identifier, identity = value.split(":", 1)
        identifier = int(identifier)
        if identifier <= 0:
            raise ValueError
        return identifier, str(uuid.UUID(identity))
    except (ValueError, AttributeError) as error:
        raise argparse.ArgumentTypeError("Use JOB_ID:FULL_JOB_UUID") from error


def select_jobs(jobs, identities):
    if len(identities) != len(dict(identities)):
        raise RuntimeError("Duplicate selected job ID")
    by_id = {job["id"]: job for job in jobs}
    selected = []
    for identifier, identity in identities:
        job = by_id.get(identifier)
        if not job or job["uuid"] != identity:
            raise RuntimeError(f"Job identity mismatch: {identifier}")
        if job["status"] not in TERMINAL | {"running"}:
            raise RuntimeError(f"Job {identifier} is queued; recovery refused")
        selected.append(job)
    unknown = [job["id"] for job in jobs if job["status"] in ACTIVE and job not in selected]
    if unknown:
        raise RuntimeError(f"Other queued/running jobs exist: {unknown}")
    return selected


def in_domain(host, domain):
    host = (host or "").lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def check_domain(api, name):
    matches = [
        row for row in api.request("/api/v1/domains") if row["name"].lower().rstrip(".") == name
    ]
    if len(matches) != 1:
        raise RuntimeError("Exactly one existing test domain is required")
    domain = matches[0]
    for path, field in (("subdomains", "name"), ("hosts", "hostname")):
        rows = api.request("/api/v1/" + path)
        if any(
            row["domain_id"] == domain["id"] and not in_domain(row[field], name) for row in rows
        ):
            raise RuntimeError(f"Stored {path} contain targets outside {name}")
    for row in api.request(f"/api/v1/urls?domain_id={domain['id']}"):
        parsed = urlsplit(row["url"])
        if (
            parsed.scheme not in {"http", "https"}
            or not in_domain(parsed.hostname, name)
            or parsed.username is not None
        ):
            raise RuntimeError("Stored URL lies outside the selected domain")
    if not any(
        row["customer_id"] == domain["customer_id"] for row in api.request("/api/v1/assets")
    ):
        raise RuntimeError("The domain's customer has no asset for findings")
    return domain


def check_processes(root):
    expected = {
        "ccvm-worker": ["python"],
        "ccvm-nuclei": ["tail"],
        "ccvm-backend": ["sh", "uvicorn"],
    }
    workers = command(root, "docker", "ps", "--format", "{{.Names}}")
    if sorted(name for name in workers.splitlines() if name.startswith("ccvm-worker")) != [
        "ccvm-worker"
    ]:
        raise RuntimeError("Unexpected number of CCVM worker containers")
    for container, permitted in expected.items():
        output = command(root, "docker", "top", container, "-eo", "comm")
        processes = [line.strip() for line in output.splitlines()[1:] if line.strip()]
        if sorted(processes) != sorted(permitted):
            raise RuntimeError(f"Unexpected processes in {container}: {processes}")
    for container in ("ccvm-worker", "ccvm-backend"):
        mounts = json.loads(command(root, "docker", "inspect", "-f", "{{json .Mounts}}", container))
        if not any(
            item["Destination"] == "/app" and Path(item["Source"]).resolve() == root / "backend"
            for item in mounts
        ):
            raise RuntimeError(f"Unexpected application mount in {container}")


def write_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def recover(root, target, api, snapshots, backup):
    write_json(backup / "jobs-before.json", {"jobs": snapshots})
    worker_stopped = False
    try:
        # Also attempt to resume if Docker stops the container but its client
        # fails before returning a successful response.
        worker_stopped = True
        command(root, "docker", "stop", "--time", "20", "ccvm-worker")
        running = command(root, "docker", "inspect", "-f", "{{.State.Running}}", "ccvm-worker")
        if running != "false":
            raise RuntimeError("Worker did not stop")
        print(command(root, "git", "merge", "--ff-only", target), flush=True)
        result = command(
            root,
            "docker",
            "exec",
            "-i",
            "--env",
            "PGCONNECT_TIMEOUT=10",
            "ccvm-backend",
            "python",
            "-c",
            RECOVER_IN_BACKEND,
            input_text=json.dumps({"worker_stopped": True, "jobs": snapshots}),
        )
        write_json(backup / "recovery-result.json", json.loads(result))
        print(result, flush=True)
    finally:
        if worker_stopped:
            command(root, "docker", "start", "ccvm-worker")
    after = api.request("/api/v1/jobs")
    for before in snapshots:
        current = next((job for job in after if job["id"] == before["id"]), None)
        if not current or current["uuid"] != before["uuid"] or current["status"] in ACTIVE:
            raise RuntimeError(f"Recovery verification failed for job {before['id']}")


def verify_worker(api, backup):
    job = api.request("/api/v1/jobs", {"plugin": "dummy"})
    write_json(backup / "dummy-job.json", job)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        job = api.request(f"/api/v1/jobs/{job['id']}")
        if job["status"] == "finished":
            print(f"Worker verified: dummy job {job['id']} finished", flush=True)
            return
        if job["status"] in TERMINAL:
            raise RuntimeError(f"Dummy job failed: {job}")
        time.sleep(2)
    raise RuntimeError(f"Dummy job did not finish within 45 seconds: {job}")


def monitor(api, pipeline_id, domain_name):
    deadline = time.monotonic() + 10800
    previous = None
    while True:
        state = api.request("/api/v1/pipelines/" + pipeline_id)
        if (state.get("domain_name") or "").lower().rstrip(".") != domain_name:
            raise RuntimeError("Pipeline domain mismatch")
        snapshot = json.dumps(state, sort_keys=True)
        if snapshot != previous:
            print(
                f"\nPipeline {pipeline_id}: {state['status']} ({state['progress']}%)",
                flush=True,
            )
            for job in state["jobs"]:
                print(
                    f"{job['id']:>6} {job['plugin']:<15} {job['status']:<9} "
                    f"{job['progress']:>3}% {job.get('message') or ''}",
                    flush=True,
                )
            previous = snapshot
        if not any(job["status"] in ACTIVE for job in state["jobs"]):
            if tuple(job["plugin"] for job in state["jobs"]) != STAGES or any(
                job["status"] != "finished" for job in state["jobs"]
            ):
                raise RuntimeError("Pilot ended with failed, skipped, or missing stages")
            print("CCVM pilot completed: all ten stages finished", flush=True)
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("Monitoring stopped after three hours; pipeline was not cancelled")
        time.sleep(15)


def execute(args, root, git_dir, api):
    marker = git_dir / "ccvm-worker-recovery-pipeline.json"
    if marker.exists():
        previous = json.loads(marker.read_text())
        if previous["target"] != args.target or previous["domain"] != args.domain:
            raise RuntimeError("An earlier pilot marker has a different target or domain")
        command(root, "git", "merge-base", "--is-ancestor", args.target, "HEAD")
        if not args.apply:
            print(
                f"Existing pilot: {previous['pipeline']['pipeline_id']}; no new run",
                flush=True,
            )
            return
        monitor(api, previous["pipeline"]["pipeline_id"], args.domain)
        return
    if command(root, "git", "branch", "--show-current") != BRANCH:
        raise RuntimeError("Unexpected deployment branch")
    edited = command(
        root,
        "git",
        "diff",
        "--name-only",
        "HEAD",
        "--",
        "backend/app",
        "backend/alembic",
    )
    untracked = command(
        root,
        "git",
        "ls-files",
        "--others",
        "--exclude-standard",
        "backend/app",
        "backend/alembic",
    )
    if edited or any(path.endswith(".py") for path in untracked.splitlines()):
        raise RuntimeError(
            "Application sources have unreviewed changes; private configuration is allowed"
        )
    command(root, "git", "merge-base", "--is-ancestor", "HEAD", args.target)
    changed = command(root, "git", "diff", "--name-only", "HEAD", args.target).splitlines()
    if set(changed) - ALLOWED_CHANGES:
        raise RuntimeError(
            f"Target changes unexpected paths: {sorted(set(changed) - ALLOWED_CHANGES)}"
        )
    health = api.request("/health")
    if health.get("status") != "ok" or health.get("version") != "4.4.0":
        raise RuntimeError("Unexpected backend health/version")
    snapshots = select_jobs(api.request("/api/v1/jobs"), args.job)
    domain = check_domain(api, args.domain)
    check_processes(root)
    help_text = command(root, "docker", "exec", "ccvm-worker", "nuclei", "-h", include_stderr=True)
    if "-disable-redirects" not in help_text:
        raise RuntimeError("Installed Nuclei lacks the required redirect flag")
    print(
        "Selected jobs:",
        [(job["id"], job["plugin"], job["status"]) for job in snapshots],
    )
    if not args.apply:
        print("Preflight passed; no changes made. Use --apply for the reviewed maintenance.")
        return
    backup = Path(tempfile.mkdtemp(prefix="ccvm-worker-recovery-", dir=git_dir))
    write_json(
        backup / "operation.json",
        {
            "head_before": command(root, "git", "rev-parse", "HEAD"),
            "target": args.target,
            "domain": args.domain,
        },
    )
    print(f"Backup: {backup}", flush=True)
    recover(root, args.target, api, snapshots, backup)
    verify_worker(api, backup)
    select_jobs(api.request("/api/v1/jobs"), args.job)
    if args.start_pipeline:
        pipeline = api.request("/api/v1/discover", {"domain_id": domain["id"]})
        record = {
            "target": args.target,
            "domain": args.domain,
            "pipeline": pipeline,
            "backup": str(backup),
        }
        write_json(backup / "pipeline.json", record)
        write_json(marker, record)
        print(f"Pipeline saved: {marker}", flush=True)
        monitor(api, pipeline["pipeline_id"], args.domain)
    else:
        print("Worker recovery and deployment verified", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/opt/ccvm"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--job", type=parse_job, action="append", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--start-pipeline", action="store_true")
    args = parser.parse_args()
    if len(args.target) != 40 or any(char not in "0123456789abcdef" for char in args.target):
        parser.error("--target must be a full commit SHA")
    args.domain = args.domain.strip().lower().rstrip(".")
    if not args.domain or any(char.isspace() or char in "/:@\\" for char in args.domain):
        parser.error("--domain must be a DNS name")
    root = args.root.resolve()
    git_dir = Path(command(root, "git", "rev-parse", "--absolute-git-dir"))
    api = API()
    os.umask(0o077)
    try:
        if args.apply:
            with (git_dir / "ccvm-worker-recovery.lock").open("a+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                execute(args, root, git_dir, api)
        else:
            execute(args, root, git_dir, api)
    except (Exception, KeyboardInterrupt) as error:
        print(f"Recovery stopped: {type(error).__name__}: {error}", flush=True)
        try:
            print(
                command(root, "docker", "logs", "--tail", "60", "ccvm-worker"),
                flush=True,
            )
        except Exception as diagnostic_error:
            print(f"Worker diagnostics unavailable: {diagnostic_error}", flush=True)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
