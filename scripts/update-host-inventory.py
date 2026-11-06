#!/usr/bin/env python3
"""Update a verified inventory deployment without changing ingress or secrets.

Read-only preflight by default. --apply publishes the reviewed source and UI,
after an idle-worker check and private database backup. --resume continues only
this update's journal. No host authentication or scanner job is submitted.
"""

import argparse
import base64
import copy
import fcntl
import hashlib
import io
import json
import os
import re
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import types
from pathlib import Path

VERSION = "1.0.0"
OLD_REVISION, REVISION = "a4c1d8e7f209", "b7e2c9d1a630"
BRANCH = "sprint-1.0.2-feature-architecture"
JOURNAL = "ccvm-host-inventory-update.json"
DEPLOYMENT_JOURNAL = "ccvm-authenticated-deployment.json"
ALLOWED = {
    "backend/app/models/host_audit.py",
    "backend/app/schemas/host_audit.py",
    "backend/app/api/v1/host_audits.py",
    "backend/app/plugins/hostinventory.py",
    "backend/app/services/audit_vault.py",
    "backend/app/services/host_audit_transport.py",
    "backend/app/services/host_inventory.py",
    "backend/integration/authenticated_deployment.py",
    "backend/integration/check_gateway_mounts.py",
    "backend/integration/check_winrm_http.py",
    "backend/integration/host_audit_postgres.py",
    "backend/integration/test_postgres_migrations.py",
    "backend/tests/test_host_audits.py",
    "backend/tests/test_winrm_http_transport.py",
    "backend/tests/test_winrm_transport_migration.py",
    "backend/tests/test_migrations.py",
    "backend/alembic/versions/b7e2c9d1a630_add_winrm_transport.py",
    "scripts/update-host-inventory.py",
    "scripts/tests/test_update_host_inventory.py",
    "scripts/deploy-authenticated-inventory.py",
    "scripts/repair-authenticated-gateway.py",
    "scripts/authenticated_ingress.py",
    "scripts/tests/test_authenticated_gateway_repair.py",
    "scripts/tests/test_authenticated_deployment.py",
    "docs/authenticated-inventory.md",
    ".github/workflows/ci.yml",
}
PREFIXES = ("frontend/src/features/host-audits/", "frontend/tests/")


def git(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, timeout=60, check=False
    )
    if result.returncode:
        raise RuntimeError("Git prerequisite failed; checkout retained")
    return result.stdout.decode().strip()


def load_helper(root, target, path, name):
    module = types.ModuleType(name)
    module.__file__ = f"<git:{path}>"
    sys.modules[name] = module
    source = git(root, "show", f"{target}:{path}").encode()
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def private_path(path, directory=False):
    if (
        path.is_symlink()
        or path.stat().st_uid != os.geteuid()
        or path.stat().st_mode & 0o077
        or (directory and not path.is_dir())
        or (not directory and not path.is_file())
    ):
        raise RuntimeError("Retained private update path or permissions changed")


def source_plan(root, target, base, *, resume=False):
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (target, base)):
        raise RuntimeError("Use a full reviewed target and retained deployment SHA")
    if (
        Path(git(root, "rev-parse", "--show-toplevel")).resolve() != root
        or git(root, "branch", "--show-current") != BRANCH
        or git(root, "rev-parse", f"origin/{BRANCH}") != target
    ):
        raise RuntimeError("Reviewed target or deployment checkout changed")
    before = git(root, "rev-parse", "HEAD")
    if before not in {base, target} or (before == target and not resume):
        raise RuntimeError("Installed source requires its retained update journal")
    git(root, "merge-base", "--is-ancestor", base, target)
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    for name in ("index.lock", "MERGE_HEAD", "CHERRY_PICK_HEAD", "rebase-merge", "rebase-apply"):
        if (directory / name).exists():
            raise RuntimeError("Another Git operation is unfinished")
    git(root, "diff", "--cached", "--exit-code")
    if set(git(root, "diff", "--name-only").splitlines()) - {
        "docker-compose.yml",
        "frontend/default.conf",
    }:
        raise RuntimeError("Additional tracked source edits retained")
    changes = git(root, "diff", "--name-only", "--no-renames", base, target).splitlines()
    if not changes or any(
        name not in ALLOWED and not name.startswith(PREFIXES) for name in changes
    ):
        raise RuntimeError("Target changes unrelated source or runtime dependencies")
    if git(root, "diff", "--name-only", "--diff-filter=D", base, target):
        raise RuntimeError("Source deletion is outside this inventory update")
    unknown = set(git(root, "ls-files", "--others", "--exclude-standard").splitlines())
    if unknown & set(changes) or any(
        name.startswith(("backend/app/", "backend/alembic/", "frontend/src/"))
        and Path(name).suffix in {".py", ".ts", ".tsx", ".js", ".jsx"}
        for name in unknown
    ):
        raise RuntimeError("Additional application source or target collision retained")
    for name in set(changes) | {"frontend/dist", "docker-compose.authenticated.yml"}:
        path = root / name
        while path != root:
            if path.is_symlink():
                raise RuntimeError("Symlink in inventory update path")
            path = path.parent
    return changes


def state_code(original):
    # The only schema change appends a defaulted transport column. Compare every
    # existing scalar, including encrypted credentials, on both sides of that
    # migration without treating its new column as changed historical evidence.
    needle = "dict(row._mapping)"
    if original.STATE_CODE.count(needle) != 1:
        raise RuntimeError("Reviewed database snapshot implementation changed")
    return original.STATE_CODE.replace(
        needle,
        "{key:value for key,value in row._mapping.items() "
        "if not (name=='host_audits' and key=='winrm_transport')}",
    )


def read_state(original, runtime, operation):
    return json.loads(runtime.helper(operation, state_code(original)))


def preserve_rows(before, after):
    if before["identity"] != after["identity"] or before["tables"] != after["tables"]:
        raise RuntimeError("Existing database rows changed; retain the private backup")


def capture_private(original, runtime, operation):
    files = {
        name: (
            base64.b64encode((runtime.root / name).read_bytes()).decode()
            if (runtime.root / name).is_file()
            else None
        )
        for name in (*original.PROTECTED, original.OVERRIDE)
    }
    files["deployment-journal"] = base64.b64encode(
        (Path(operation["private"]).parent / DEPLOYMENT_JOURNAL).read_bytes()
    ).decode()
    files["gateway.conf"] = base64.b64encode(
        (Path(operation["private"]) / "gateway.conf").read_bytes()
    ).decode()
    files["haproxy.cfg"] = runtime.root_io({"action": "read", "path": operation["edge_path"]})[
        "data"
    ]
    return files


def retained(original, runtime, operation, record):
    original.validate_secrets(Path(operation["private"]), operation)
    original.assert_retained(runtime, operation)
    if capture_private(original, runtime, operation) != record["private_files"]:
        raise RuntimeError("Private runtime, ingress or deployment journal changed")
    for name, identity in record["retained_ids"].items():
        if runtime.inspect(name)["Id"] != identity:
            raise RuntimeError("An ingress, frontend or database container changed")


def prepare(original, runtime, operation, target, marker):
    original.verify_runtime(runtime, operation, runtime.legacy)
    worker = runtime.inspect("ccvm-worker")
    original.worker_identity(runtime, worker)
    if [
        name
        for name in runtime.docker("ps", "--format", "{{.Names}}").splitlines()
        if name.startswith("ccvm-worker")
    ] != ["ccvm-worker"]:
        raise RuntimeError("Expected exactly the retained worker")
    current = read_state(original, runtime, operation)
    original.validate_state(current, OLD_REVISION)
    original.database_identity(current, runtime.inspect("ccvm-postgres"))
    record = {
        "version": VERSION,
        "target": target,
        "base": operation["target"],
        "host": operation["host"],
        "phase": "prepared",
        "private_files": capture_private(original, runtime, operation),
        "retained_ids": {
            name: runtime.inspect(name)["Id"]
            for name in (
                "ccvm-postgres",
                "haproxy-edge",
                "ccvm-audit-gateway",
                "ccvm-frontend",
            )
        },
        "application_ids": {
            name: runtime.inspect("ccvm-" + name)["Id"] for name in ("backend", "worker")
        },
    }
    if marker is None:
        return record
    backup = Path(tempfile.mkdtemp(prefix="ccvm-host-inventory-before-", dir=marker.parent))
    record["backup"] = str(backup)
    work = copy.deepcopy(operation)
    work.update(
        backup=str(backup),
        originals={
            name: runtime.inspect("ccvm-" + name)
            for name in ("backend", "worker", "frontend", "postgres")
        },
    )
    original.database_environment(work)
    original.write_json(backup / "retained-deployment.json", operation)
    original.write_json(backup / "private-files.json", record["private_files"])
    original.write_json(marker, record)
    return record


def work_operation(operation, record):
    work = copy.deepcopy(operation)
    work.update(
        backup=record["backup"],
        backend_source=str(Path(record["backup"]) / "release/backend"),
        built_frontend=str(Path(record["backup"]) / "release/frontend/dist"),
    )
    if record.get("attempt_dir"):
        work["attempt_dir"] = record["attempt_dir"]
    return work


def write_phase(original, marker, record, phase):
    record["phase"] = phase
    original.write_json(marker, record)


def build(original, runtime, record):
    backup = Path(record["backup"])
    archive = original.run(
        ["git", "-C", str(runtime.root), "archive", record["target"], "backend", "frontend"]
    )
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(backup / "release", filter="data")
    frontend = backup / "release/frontend"
    print("Building the reviewed inventory UI on the retained runtime...", flush=True)
    runtime.docker(
        "run",
        "--rm",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--mount",
        f"type=bind,src={frontend},dst=/work",
        "--workdir",
        "/work",
        "--env",
        "npm_config_cache=/tmp/ccvm-npm",
        "--entrypoint",
        "sh",
        "node:22-bookworm-slim",
        "-c",
        "umask 022; npm ci --no-fund && npm audit --audit-level=high && "
        "npm run build && node tests/check-build.mjs dist /api/v1",
        timeout=600,
    )
    if not (frontend / "dist/index.html").is_file():
        raise RuntimeError("Reviewed inventory frontend build is incomplete")
    record["artifacts"] = {
        "backend": directory_hashes(backup / "release/backend"),
        "frontend/dist": directory_hashes(frontend / "dist"),
    }


def directory_hashes(directory):
    result = {}
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError("Retained artifact directory changed")
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("Symlink in retained inventory artifacts")
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    if not result:
        raise RuntimeError("Retained inventory artifact directory is empty")
    return result


def validate_artifacts(record):
    release = Path(record["backup"]) / "release"
    if record.get("artifacts") != {
        name: directory_hashes(release / name) for name in ("backend", "frontend/dist")
    }:
        raise RuntimeError("Retained reviewed inventory artifacts changed")


def restore_before_migration(original, runtime, record):
    for name, identity in record["application_ids"].items():
        container = runtime.inspect("ccvm-" + name)
        if container["Id"] != identity:
            raise RuntimeError("Original application container changed")
        if container["State"]["Paused"]:
            runtime.docker("unpause", identity)
        if not container["State"]["Running"]:
            runtime.docker("start", identity)


def quiesce(original, runtime, work, record, marker):
    print("Closing submissions and saving the idle inventory database...", flush=True)
    worker = runtime.inspect("ccvm-worker")
    backend = runtime.inspect("ccvm-backend")
    if (
        worker["Id"] != record["application_ids"]["worker"]
        or backend["Id"] != record["application_ids"]["backend"]
    ):
        raise RuntimeError("Retained application containers changed")
    if worker["State"]["Running"] and not worker["State"]["Paused"]:
        runtime.docker("pause", worker["Id"])
    if backend["State"]["Running"]:
        runtime.docker("stop", "--time", "20", backend["Id"])
    for attempt in range(5):
        before = read_state(original, runtime, work)
        original.validate_state(before, OLD_REVISION)
        if not before["transactions"]:
            break
        if attempt == 4:
            raise RuntimeError("Open database transactions retained")
        runtime.docker("unpause", worker["Id"])
        time.sleep(0.3)
        runtime.docker("pause", worker["Id"])
    original.close_application(runtime)
    stopped = read_state(original, runtime, work)
    original.validate_state(stopped, OLD_REVISION)
    preserve_rows(before, stopped)
    if stopped["transactions"]:
        raise RuntimeError("Database transaction remained after quiescing")
    attempt = Path(tempfile.mkdtemp(prefix="attempt-", dir=record["backup"]))
    record["attempt_dir"] = str(attempt)
    record["before"] = stopped
    work["attempt_dir"] = str(attempt)
    original.write_json(attempt / "before.json", stopped)
    original.backup_database(runtime, work)
    write_phase(original, marker, record, "quiesced")


def verify(original, runtime, work, record):
    validate_artifacts(record)
    retained(original, runtime, work, record)
    original.verify_runtime(runtime, work, runtime.legacy)
    original.validate_state(read_state(original, runtime, work), REVISION, idle=False)
    runtime.tls_probe(work)
    with runtime.opener.open("http://127.0.0.1:8090/", timeout=5) as response:
        if response.read() != (Path(work["built_frontend"]) / "index.html").read_bytes():
            raise RuntimeError("Published frontend differs from the reviewed update")
    source = runtime.docker(
        "exec",
        "--workdir",
        "/tmp",
        "ccvm-backend",
        "python",
        "-I",
        "-c",
        "import sys;sys.path.insert(0,'/app');from app.main import app;import json;"
        "s=app.openapi()['components']['schemas'];"
        "print(json.dumps(s['HostAuditCreate']['properties']['winrm_transport']))",
    )
    spec = json.loads(source)
    if spec.get("default") != "https" or set(spec.get("enum", [])) != {"https", "http_ntlm"}:
        raise RuntimeError("Published API does not expose the reviewed transport choices")


def activate(original, runtime, operation, record, marker):
    work = work_operation(operation, record)
    runtime.diagnostic = Path(record["backup"]) / "last-command.log"
    retained(original, runtime, operation, record)
    if record["phase"] == "verified":
        verify(original, runtime, work, record)
        print(f"VERIFIED: inventory update already installed at {record['target']}")
        return
    if record["phase"] == "prepared":
        build(original, runtime, record)
        write_phase(original, marker, record, "built")
    validate_artifacts(record)
    if record["phase"] == "built":
        source_plan(runtime.root, record["target"], record["base"], resume=True)
        quiesce(original, runtime, work, record, marker)
    if record["phase"] in {"quiesced", "migrating"}:
        original.close_application(runtime)
        current = read_state(original, runtime, work)
        if current["revision"] == OLD_REVISION:
            original.validate_state(current, OLD_REVISION)
            preserve_rows(record["before"], current)
            if current["transactions"]:
                raise RuntimeError("Quiesced database changed; migration refused")
            write_phase(original, marker, record, "migrating")
            print("Applying the additive transport migration...", flush=True)
            runtime.helper(
                work,
                "from alembic import command\nfrom alembic.config import Config\n"
                "config=Config('/app/alembic.ini')\n"
                "config.set_main_option('script_location','/app/alembic')\n"
                f"command.upgrade(config,{REVISION!r})",
            )
            current = read_state(original, runtime, work)
        original.validate_state(current, REVISION)
        preserve_rows(record["before"], current)
        if current["transactions"]:
            raise RuntimeError("Unexpected transaction after inventory migration")
        defaults = runtime.helper(
            work,
            "from app.database.session import engine\n"
            "with engine.connect() as c:\n"
            " c.exec_driver_sql('SET TRANSACTION READ ONLY')\n"
            " c.exec_driver_sql(\"SET LOCAL statement_timeout='5s'\")\n"
            ' assert c.exec_driver_sql("SELECT count(*) FROM host_audits '
            "WHERE winrm_transport IS NULL OR winrm_transport <> 'https'\").scalar_one()==0\n"
            "print('retained-https')",
        )
        if defaults != "retained-https":
            raise RuntimeError("Existing audits did not retain their HTTPS transport")
        original.write_json(Path(record["attempt_dir"]) / "after.json", current)
        write_phase(original, marker, record, "migrated")
    if record["phase"] == "migrated":
        original.close_application(runtime)
        current = read_state(original, runtime, work)
        original.validate_state(current, REVISION)
        preserve_rows(record["before"], current)
        if current["transactions"]:
            raise RuntimeError("Database changed before source publication")
        source_plan(runtime.root, record["target"], record["base"], resume=True)
        if git(runtime.root, "rev-parse", "HEAD") != record["target"]:
            git(runtime.root, "merge", "--ff-only", record["target"])
        write_phase(original, marker, record, "source")
    if record["phase"] == "source":
        original.close_application(runtime)
        retained(original, runtime, operation, record)
        current = read_state(original, runtime, work)
        original.validate_state(current, REVISION)
        preserve_rows(record["before"], current)
        if current["transactions"]:
            raise RuntimeError("Database changed before frontend publication")
        print("Publishing the reviewed inventory UI...", flush=True)
        runtime.legacy.BACKEND_IMAGE = operation["images"]["backend"]
        runtime.legacy.publish_frontend(runtime, runtime.root, Path(work["built_frontend"]))
        write_phase(original, marker, record, "published")
    if record["phase"] in {"published", "services"}:
        write_phase(original, marker, record, "services")
        # The source bind and images remain unchanged. Start existing containers
        # without Compose recreation; gateway, HAProxy and frontend retain IDs.
        for name in ("backend", "worker"):
            container = runtime.inspect("ccvm-" + name)
            if container["Id"] != record["application_ids"][name]:
                raise RuntimeError("Retained application container was replaced")
            if not container["State"]["Running"]:
                runtime.docker("start", container["Id"])
        print("Verifying API, encrypted transport choices and preserved ingress...", flush=True)
        verify(original, runtime, work, record)
        write_phase(original, marker, record, "verified")
    if record["phase"] != "verified":
        raise RuntimeError("Unknown retained inventory update phase")
    print(f"VERIFIED: optional encrypted HTTP inventory at {record['target']}")
    print(f"Private recovery material: {record['backup']}")


def validate_record(record, marker, target, host, base):
    private_path(marker)
    if any(
        record.get(key) != value
        for key, value in {"version": VERSION, "target": target, "host": host, "base": base}.items()
    ):
        raise RuntimeError("Retained inventory update parameters changed")
    if record.get("phase") not in {
        "prepared",
        "built",
        "quiesced",
        "migrating",
        "migrated",
        "source",
        "published",
        "services",
        "verified",
    }:
        raise RuntimeError("Unknown retained inventory update phase")
    backup = Path(record["backup"])
    if backup.parent != marker.parent or not backup.name.startswith("ccvm-host-inventory-before-"):
        raise RuntimeError("Unexpected private inventory backup path")
    private_path(backup, directory=True)
    expected = backup / "release/backend"
    if expected.is_symlink() or expected.parent.is_symlink():
        raise RuntimeError("Retained release path changed")


def recover(original, runtime, record, marker):
    # Before a migration attempt, exactly the original containers can resume.
    # After the intent is durable, keep writers closed and retain the additive
    # schema, source and data for explicit --resume; never downgrade evidence.
    if record["phase"] in {"prepared", "built", "quiesced"}:
        restore_before_migration(original, runtime, record)
        if record["phase"] == "quiesced":
            write_phase(original, marker, record, "built")
    elif record["phase"] != "verified":
        original.close_application(runtime)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != args.host:
        raise RuntimeError("Unexpected inventory update host")
    if not re.fullmatch(r"[0-9a-f]{40}", args.target):
        raise RuntimeError("Use the full reviewed inventory update SHA")
    root = Path.cwd().resolve()
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    deployment_marker = directory / DEPLOYMENT_JOURNAL
    private_path(deployment_marker)
    operation = json.loads(deployment_marker.read_text())
    if operation.get("phase") != "verified" or operation.get("host") != args.host:
        raise RuntimeError("A verified authenticated inventory deployment is required")
    marker = directory / JOURNAL
    source_plan(root, args.target, operation["target"], resume=marker.exists())
    original = load_helper(
        root, args.target, "scripts/deploy-authenticated-inventory.py", "update_original"
    )
    ingress = load_helper(root, args.target, "scripts/authenticated_ingress.py", "update_ingress")
    legacy = load_helper(root, args.target, "scripts/deploy-network-scans.py", "update_legacy")
    runtime = original.Runtime(root, operation["target"], ingress)
    runtime.legacy = legacy
    runtime.diagnostic = directory / "ccvm-host-inventory-preflight.log"
    params = types.SimpleNamespace(
        hostname=operation["hostname"],
        clients=operation["clients"],
        certificate=operation["certificate"],
        host=args.host,
        **{name + "_image": value for name, value in operation["pins"].items()},
    )
    descriptor = os.open(
        directory / "ccvm-authenticated.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original.validate_journal(runtime, params, operation, deployment_marker)
        print(f"CCVM host inventory updater {VERSION}; reviewed target {args.target}", flush=True)
        record = None
        if os.path.lexists(marker):
            private_path(marker)
            record = json.loads(marker.read_text())
            validate_record(record, marker, args.target, args.host, operation["target"])
            if (
                record["phase"] in {"prepared", "built", "quiesced", "migrating"}
                and git(root, "rev-parse", "HEAD") != operation["target"]
            ):
                raise RuntimeError("Source advanced before the retained migration completed")
            retained(original, runtime, operation, record)
            if record["phase"] != "verified" and args.apply and not args.resume:
                raise RuntimeError("Retained incomplete update requires --resume")
        if not args.apply:
            if record:
                if record["phase"] == "verified":
                    verify(original, runtime, work_operation(operation, record), record)
                else:
                    print(
                        f"PREFLIGHT OK: retained update at {record['phase']}; use --apply --resume."
                    )
            else:
                prepare(original, runtime, operation, args.target, None)
                print("PREFLIGHT OK: idle inventory deployment; no changes performed.")
            return
        if record is None:
            record = prepare(original, runtime, operation, args.target, marker)
        print(f"Private backup: {record['backup']}", flush=True)
        try:
            activate(original, runtime, operation, record, marker)
        except BaseException:
            try:
                recover(original, runtime, record, marker)
            except BaseException:
                print("Recovery requires inspection of the retained private journal.", flush=True)
            print(
                f"Update stopped at {record['phase']}; retain {record['backup']}; "
                "rerun with --resume.",
                flush=True,
            )
            raise


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(f"STOPPED: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from None
