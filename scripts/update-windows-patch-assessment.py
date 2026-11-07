#!/usr/bin/env python3
"""Publish operator-only Windows patch assessment on a verified inventory update.

Read-only preflight by default. --apply uses the retained images and ingress,
checks a private database backup and adds two initially empty assessment tables.
No catalog download, host authentication or assessment is performed here.
"""

import argparse
import base64
import copy
import fcntl
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import types
from pathlib import Path

VERSION = "1.0.0"
OLD_REVISION, REVISION = "b7e2c9d1a630", "c8f3a0e2b741"
JOURNAL = "ccvm-windows-patch-deployment.json"
PRIOR_JOURNAL = "ccvm-host-inventory-update.json"
BACKUP_PREFIX = "ccvm-windows-patch-before-"
NEW_TABLES = {"windows_patch_catalogs", "host_assessments"}
ALLOWED = {
    "backend/app/models/__init__.py",
    "backend/app/models/host_assessment.py",
    "backend/app/schemas/host_assessment.py",
    "backend/app/api/v1/host_assessments.py",
    "backend/app/main.py",
    "backend/app/services/host_inventory.py",
    "backend/app/services/windows_inventory.ps1",
    "backend/app/services/windows_patch_catalog.py",
    "backend/app/services/windows_patch_assessment.py",
    "backend/app/services/windows_patch_sync.py",
    "backend/alembic/versions/c8f3a0e2b741_add_windows_patch_assessments.py",
    "backend/integration/authenticated_deployment.py",
    "backend/integration/check_windows_inventory.ps1",
    "backend/integration/check_windows_patch_source.py",
    "backend/integration/host_audit_postgres.py",
    "backend/integration/test_postgres_migrations.py",
    "backend/integration/host_patch_postgres.py",
    "backend/tests/test_host_audits.py",
    "backend/tests/test_windows_patch_catalog.py",
    "backend/tests/test_windows_patch_assessment.py",
    "backend/tests/test_host_assessments.py",
    "backend/tests/test_host_assessment_migration.py",
    "backend/tests/test_windows_inventory_identity.py",
    "scripts/update-host-inventory.py",
    "scripts/update-windows-patch-assessment.py",
    "scripts/tests/test_update_host_inventory.py",
    "scripts/tests/test_update_windows_patch_assessment.py",
    "scripts/deploy-authenticated-inventory.py",
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


def preserve_rows(before, after):
    """Keep every old scalar, including the per-run WinRM transport."""
    if before["identity"] != after["identity"]:
        raise RuntimeError("Existing database identity changed; retain the private backup")
    if any(after["tables"].get(name) != value for name, value in before["tables"].items()):
        raise RuntimeError("Existing database rows changed; retain the private backup")
    extra = set(after["tables"]) - set(before["tables"])
    expected = NEW_TABLES if after["revision"] == REVISION else set()
    if extra != expected or any(after["tables"][name]["count"] for name in extra):
        raise RuntimeError("Assessment migration did not add exactly two empty tables")


def verify_assessment_api(runtime, previous_verify):
    previous_verify(runtime)
    source = runtime.docker(
        "exec",
        "--workdir",
        "/tmp",
        "ccvm-backend",
        "python",
        "-I",
        "-c",
        "import sys;sys.path.insert(0,'/app');from app.main import app;import json;"
        "s=app.openapi();print(json.dumps({'paths':list(s['paths']),"
        "'schemas':list(s['components']['schemas'])}))",
    )
    spec = json.loads(source)
    if not {
        "/api/v1/host-audits/patch-catalog",
        "/api/v1/host-audits/{audit_id}/assess",
        "/api/v1/host-audits/{audit_id}/assessments",
    } <= set(spec.get("paths", [])) or not {
        "HostAssessmentOut",
        "PatchCatalogOut",
        "AssessmentCreate",
    } <= set(
        spec.get("schemas", [])
    ):
        raise RuntimeError("Published API does not expose the reviewed assessment workflow")


def configure(previous, original, runtime, directory, application_base):
    """Use the reviewed orchestration with a different explicit migration contract."""
    prior_capture = previous.capture_private
    prior_prepare = previous.prepare
    prior_verify = previous.verify_api
    previous.VERSION = VERSION
    previous.OLD_REVISION, previous.REVISION = OLD_REVISION, REVISION
    previous.BACKUP_PREFIX = BACKUP_PREFIX
    previous.MIGRATION_LABEL = "additive Windows assessment migration"
    previous.VERIFICATION_LABEL = "assessment API, preserved evidence and existing HTTPS ingress"
    previous.VERIFIED_LABEL = "operator-only Windows patch assessment"
    previous.ALLOWED, previous.PREFIXES = ALLOWED, PREFIXES
    previous.state_code = lambda source: source.STATE_CODE
    previous.preserve_rows = preserve_rows

    def capture(source, running, operation):
        files = prior_capture(source, running, operation)
        files["prior-inventory-update-journal"] = base64.b64encode(
            (directory / PRIOR_JOURNAL).read_bytes()
        ).decode()
        return files

    def prepare(source, running, operation, target, marker):
        record = prior_prepare(source, running, operation, target, None)
        record["base"] = application_base
        if marker is None:
            return record
        backup = Path(tempfile.mkdtemp(prefix=BACKUP_PREFIX, dir=marker.parent))
        record["backup"] = str(backup)
        work = copy.deepcopy(operation)
        work.update(
            backup=str(backup),
            originals={
                name: running.inspect("ccvm-" + name)
                for name in ("backend", "worker", "frontend", "postgres")
            },
        )
        source.database_environment(work)
        source.write_json(backup / "retained-deployment.json", operation)
        source.write_json(backup / "private-files.json", record["private_files"])
        source.write_json(marker, record)
        return record

    previous.capture_private = capture
    previous.prepare = prepare
    previous.assert_migrated = lambda source, running, work, record, current: preserve_rows(
        record["before"], current
    )
    previous.verify_api = lambda running: verify_assessment_api(running, prior_verify)


def previous_update(previous, original, runtime, operation, directory, host):
    marker = directory / PRIOR_JOURNAL
    previous.private_path(marker)
    record = json.loads(marker.read_text())
    if (
        record.get("phase") != "verified"
        or record.get("version") != "1.0.0"
        or record.get("host") != host
        or not re.fullmatch(r"[0-9a-f]{40}", str(record.get("target", "")))
    ):
        raise RuntimeError("A verified previous inventory update is required")
    previous.validate_record(record, marker, record["target"], host, operation["target"])
    previous.retained(original, runtime, operation, record)
    previous.validate_artifacts(record)
    return record["target"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != args.host:
        raise RuntimeError("Unexpected Windows assessment update host")
    if not re.fullmatch(r"[0-9a-f]{40}", args.target):
        raise RuntimeError("Use the full reviewed Windows assessment update SHA")
    root = Path.cwd().resolve()
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    previous = load_helper(root, args.target, "scripts/update-host-inventory.py", "patch_update")
    original = load_helper(
        root, args.target, "scripts/deploy-authenticated-inventory.py", "patch_deployment"
    )
    ingress = load_helper(root, args.target, "scripts/authenticated_ingress.py", "patch_ingress")
    legacy = load_helper(root, args.target, "scripts/deploy-network-scans.py", "patch_legacy")
    deployment_marker = directory / previous.DEPLOYMENT_JOURNAL
    previous.private_path(deployment_marker)
    operation = json.loads(deployment_marker.read_text())
    if operation.get("phase") != "verified" or operation.get("host") != args.host:
        raise RuntimeError("A verified authenticated inventory deployment is required")
    runtime = original.Runtime(root, operation["target"], ingress)
    runtime.legacy = legacy
    runtime.diagnostic = directory / "ccvm-windows-patch-preflight.log"
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
        application_base = previous_update(
            previous, original, runtime, operation, directory, args.host
        )
        configure(previous, original, runtime, directory, application_base)
        marker = directory / JOURNAL
        previous.source_plan(root, args.target, application_base, resume=marker.exists())
        print(f"CCVM Windows patch updater {VERSION}; reviewed target {args.target}", flush=True)
        record = None
        if os.path.lexists(marker):
            previous.private_path(marker)
            record = json.loads(marker.read_text())
            previous.validate_record(record, marker, args.target, args.host, application_base)
            if (
                record["phase"] in {"prepared", "built", "quiesced", "migrating"}
                and git(root, "rev-parse", "HEAD") != application_base
            ):
                raise RuntimeError("Source advanced before the retained migration completed")
            previous.retained(original, runtime, operation, record)
            if record["phase"] != "verified" and args.apply and not args.resume:
                raise RuntimeError("Retained incomplete assessment update requires --resume")
        if not args.apply:
            if record and record["phase"] == "verified":
                previous.verify(
                    original, runtime, previous.work_operation(operation, record), record
                )
            elif record:
                print(f"PREFLIGHT OK: retained update at {record['phase']}; use --apply --resume.")
            else:
                previous.prepare(original, runtime, operation, args.target, None)
                print("PREFLIGHT OK: idle assessment deployment; no changes performed.")
            return
        if record is None:
            record = previous.prepare(original, runtime, operation, args.target, marker)
        print(f"Private backup: {record['backup']}", flush=True)
        try:
            previous.activate(original, runtime, operation, record, marker)
        except BaseException:
            try:
                previous.recover(original, runtime, record, marker)
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
