#!/usr/bin/env python3
"""Publish CloudCollab UI, Windows client update queries and device coverage.

Read-only preflight by default. --apply uses the retained images and ingress,
checks a private database backup and preserves the existing schema and all rows.
No migration, catalog download, host authentication or assessment is performed here.
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
OLD_REVISION = REVISION = "d6a4b8e2f901"
JOURNAL = "ccvm-windows-clients-deployment.json"
PRIOR_JOURNAL = "ccvm-inventory-overview-deployment.json"
SOFTWARE_JOURNAL = "ccvm-software-assessment-deployment.json"
WINDOWS_JOURNAL = "ccvm-windows-patch-deployment.json"
INVENTORY_JOURNAL = "ccvm-host-inventory-update.json"
BACKUP_PREFIX = "ccvm-windows-clients-before-"
NEW_TABLES = set()
ALLOWED = {
    "backend/app/api/v1/host_assessments.py",
    "backend/app/api/v1/host_audits.py",
    "backend/app/api/v1/host_overview.py",
    "backend/app/api/v1/host_discovery.py",
    "backend/app/api/v1/software_assessments.py",
    "backend/app/schemas/host_assessment.py",
    "backend/app/schemas/host_audit.py",
    "backend/app/schemas/host_overview.py",
    "backend/app/schemas/scanner_capabilities.py",
    "backend/app/main.py",
    "backend/app/plugins/hostinventory.py",
    "backend/app/services/host_audit_transport.py",
    "backend/app/services/host_inventory.py",
    "backend/app/services/windows_inventory_command.py",
    "backend/app/services/windows_update_inventory.ps1",
    "backend/app/services/windows_update_assessment.py",
    "backend/app/services/scanner_capabilities.py",
    "backend/integration/authenticated_deployment.py",
    "backend/integration/check_windows_updates.ps1",
    "backend/integration/check_winrm_http.py",
    "scripts/update-windows-clients.py",
    "scripts/tests/test_update_windows_clients.py",
    "frontend/index.html",
    "frontend/public/assets/cloudcollab-logo.jpg",
    "frontend/src/shared/layout/AppLayout.tsx",
    "frontend/src/shared/theme/theme.ts",
    "frontend/src/shared/components/DonutChartCard.tsx",
    "frontend/src/shared/components/StatusChip.tsx",
    "frontend/src/features/dashboard/page.tsx",
    "frontend/src/features/customers/page.tsx",
    "docs/authenticated-inventory.md",
    ".github/workflows/ci.yml",
}
PREFIXES = ("frontend/src/features/host-audits/", "frontend/tests/", "backend/tests/")


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
    """No schema change and no rewrite of existing private or public evidence."""
    if before.get("revision") != REVISION or after.get("revision") != REVISION:
        raise RuntimeError("The retained Windows clients schema changed")
    if before["identity"] != after["identity"]:
        raise RuntimeError("Existing database identity changed; retain the private backup")
    if before["tables"] != after["tables"]:
        raise RuntimeError("Existing database rows or tables changed; retain the private backup")


def verify_clients_api(runtime, previous_verify):
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
        "s=app.openapi();print(json.dumps({'mode':s['components']['schemas']['HostAuditCreate']['properties']['mode'],'paths':list(s['paths']),"
        "'schemas':list(s['components']['schemas'])}))",
    )
    spec = json.loads(source)
    if not {
        "/api/v1/host-audits/overview",
        "/api/v1/host-audits/capabilities",
        "/api/v1/host-audits/discovered",
        "/api/v1/host-audits/software-catalog",
        "/api/v1/host-audits/{audit_id}/assess-software",
        "/api/v1/host-audits/{audit_id}/software-assessments",
    } <= set(spec.get("paths", [])) or not {
        "SoftwareAssessmentOut",
        "SoftwareCatalogOut",
        "SoftwareAssessmentCreate",
        "ScannerCapabilitiesOut",
        "DiscoveredDevicesOut",
    } <= set(
        spec.get("schemas", [])
    ):
        raise RuntimeError("Published API does not expose the reviewed Windows clients")

    if "windows_updates" not in spec.get("mode", {}).get("enum", []):
        raise RuntimeError("Published API does not expose the explicit Windows update query")


def configure(previous, original, runtime, directory, application_base):
    """Retain the reviewed runtime with a strict no-schema-change contract."""
    prior_capture = previous.capture_private
    prior_prepare = previous.prepare
    prior_verify = previous.verify_api
    previous.VERSION = VERSION
    previous.OLD_REVISION, previous.REVISION = OLD_REVISION, REVISION
    previous.BACKUP_PREFIX = BACKUP_PREFIX
    previous.MIGRATION_LABEL = "retained schema verification"
    previous.VERIFICATION_LABEL = "host clients API, preserved evidence and existing HTTPS ingress"
    previous.VERIFIED_LABEL = "CloudCollab UI, Windows client offers and platform coverage"
    previous.ALLOWED, previous.PREFIXES = ALLOWED, PREFIXES
    previous.state_code = lambda source: source.STATE_CODE
    previous.preserve_rows = preserve_rows

    def capture(source, running, operation):
        files = prior_capture(source, running, operation)
        files["prior-inventory-overview-journal"] = base64.b64encode(
            (directory / PRIOR_JOURNAL).read_bytes()
        ).decode()
        files["prior-software-assessment-journal"] = base64.b64encode(
            (directory / SOFTWARE_JOURNAL).read_bytes()
        ).decode()
        files["prior-windows-patch-journal"] = base64.b64encode(
            (directory / WINDOWS_JOURNAL).read_bytes()
        ).decode()
        files["prior-inventory-update-journal"] = base64.b64encode(
            (directory / INVENTORY_JOURNAL).read_bytes()
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
    previous.verify_api = lambda running: verify_clients_api(running, prior_verify)


def previous_update(previous, original, runtime, operation, directory, host):
    """Validate all retained inventory, Windows and software publications."""
    marker = directory / PRIOR_JOURNAL
    previous.private_path(marker)
    record = json.loads(marker.read_text())
    if (
        record.get("phase") != "verified"
        or record.get("version") != "1.0.0"
        or record.get("host") != host
        or not re.fullmatch(r"[0-9a-f]{40}", str(record.get("target", "")))
    ):
        raise RuntimeError("A verified previous inventory overview update is required")
    overview = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-inventory-overview.py",
        "clients_prior_overview",
    )
    application_base = overview.previous_update(
        previous, original, runtime, operation, directory, host
    )
    retained_driver = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-host-inventory.py",
        "clients_prior_software_driver",
    )
    overview.configure(retained_driver, original, runtime, directory, application_base)
    retained_driver.validate_record(record, marker, record["target"], host, application_base)
    retained_driver.retained(original, runtime, operation, record)
    retained_driver.validate_artifacts(record)
    return record["target"]


def activate(previous, original, runtime, operation, record, marker):
    """Publish retained artifacts after exact schema/row checks, without Alembic."""
    work = previous.work_operation(operation, record)
    runtime.diagnostic = Path(record["backup"]) / "last-command.log"
    previous.retained(original, runtime, operation, record)
    if record["phase"] == "verified":
        previous.verify(original, runtime, work, record)
        print(f"VERIFIED: Windows clients already installed at {record['target']}")
        return
    if record["phase"] == "prepared":
        previous.build(original, runtime, record)
        previous.write_phase(original, marker, record, "built")
    previous.validate_artifacts(record)
    if record["phase"] == "built":
        previous.source_plan(runtime.root, record["target"], record["base"], resume=True)
        previous.quiesce(original, runtime, work, record, marker)
    if record["phase"] in {"quiesced", "migrating"}:
        original.close_application(runtime)
        current = previous.read_state(original, runtime, work)
        original.validate_state(current, REVISION)
        preserve_rows(record["before"], current)
        if current["transactions"]:
            raise RuntimeError("Quiesced database changed; publication refused")
        print("Verifying unchanged schema and retained database rows...", flush=True)
        original.write_json(Path(record["attempt_dir"]) / "after.json", current)
        previous.write_phase(original, marker, record, "migrated")
    if record["phase"] == "migrated":
        original.close_application(runtime)
        current = previous.read_state(original, runtime, work)
        original.validate_state(current, REVISION)
        preserve_rows(record["before"], current)
        if current["transactions"]:
            raise RuntimeError("Database changed before source publication")
        previous.source_plan(runtime.root, record["target"], record["base"], resume=True)
        if git(runtime.root, "rev-parse", "HEAD") != record["target"]:
            git(runtime.root, "merge", "--ff-only", record["target"])
        previous.write_phase(original, marker, record, "source")
    if record["phase"] == "source":
        original.close_application(runtime)
        previous.retained(original, runtime, operation, record)
        current = previous.read_state(original, runtime, work)
        original.validate_state(current, REVISION)
        preserve_rows(record["before"], current)
        if current["transactions"]:
            raise RuntimeError("Database changed before frontend publication")
        print("Publishing the reviewed CloudCollab inventory UI...", flush=True)
        runtime.legacy.BACKEND_IMAGE = operation["images"]["backend"]
        runtime.legacy.publish_frontend(runtime, runtime.root, Path(work["built_frontend"]))
        previous.write_phase(original, marker, record, "published")
    if record["phase"] in {"published", "services"}:
        previous.write_phase(original, marker, record, "services")
        for name in ("backend", "worker"):
            container = runtime.inspect("ccvm-" + name)
            if container["Id"] != record["application_ids"][name]:
                raise RuntimeError("Retained application container was replaced")
            if not container["State"]["Running"]:
                runtime.docker("start", container["Id"])
        print(f"Verifying {previous.VERIFICATION_LABEL}...", flush=True)
        previous.verify(original, runtime, work, record)
        previous.write_phase(original, marker, record, "verified")
    if record["phase"] != "verified":
        raise RuntimeError("Unknown retained Windows clients update phase")
    print(f"VERIFIED: {previous.VERIFIED_LABEL} at {record['target']}")
    print(f"Private recovery material: {record['backup']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != args.host:
        raise RuntimeError("Unexpected Windows clients update host")
    if not re.fullmatch(r"[0-9a-f]{40}", args.target):
        raise RuntimeError("Use the full reviewed Windows clients update SHA")
    root = Path.cwd().resolve()
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    previous = load_helper(
        root, args.target, "scripts/update-host-inventory.py", "clients_prior_driver"
    )
    original = load_helper(
        root, args.target, "scripts/deploy-authenticated-inventory.py", "clients_deployment"
    )
    ingress = load_helper(root, args.target, "scripts/authenticated_ingress.py", "clients_ingress")
    legacy = load_helper(root, args.target, "scripts/deploy-network-scans.py", "clients_legacy")
    deployment_marker = directory / previous.DEPLOYMENT_JOURNAL
    previous.private_path(deployment_marker)
    operation = json.loads(deployment_marker.read_text())
    if operation.get("phase") != "verified" or operation.get("host") != args.host:
        raise RuntimeError("A verified authenticated inventory deployment is required")
    runtime = original.Runtime(root, operation["target"], ingress)
    runtime.legacy = legacy
    runtime.reviewed_target = args.target
    runtime.diagnostic = directory / "ccvm-windows-clients-preflight.log"
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
        previous = load_helper(
            root, args.target, "scripts/update-host-inventory.py", "clients_update_driver"
        )
        configure(previous, original, runtime, directory, application_base)
        marker = directory / JOURNAL
        previous.source_plan(root, args.target, application_base, resume=marker.exists())
        print(f"CCVM Windows clients updater {VERSION}; reviewed target {args.target}", flush=True)
        record = None
        if os.path.lexists(marker):
            previous.private_path(marker)
            record = json.loads(marker.read_text())
            previous.validate_record(record, marker, args.target, args.host, application_base)
            if (
                record["phase"] in {"prepared", "built", "quiesced", "migrating"}
                and git(root, "rev-parse", "HEAD") != application_base
            ):
                raise RuntimeError("Source advanced before retained schema verification completed")
            previous.retained(original, runtime, operation, record)
            if record["phase"] != "verified" and args.apply and not args.resume:
                raise RuntimeError("Retained incomplete clients update requires --resume")
        if not args.apply:
            if record and record["phase"] == "verified":
                previous.verify(
                    original, runtime, previous.work_operation(operation, record), record
                )
            elif record:
                print(f"PREFLIGHT OK: retained update at {record['phase']}; use --apply --resume.")
            else:
                previous.prepare(original, runtime, operation, args.target, None)
                print("PREFLIGHT OK: idle Windows clients deployment; no changes performed.")
            return
        if record is None:
            record = previous.prepare(original, runtime, operation, args.target, marker)
        print(f"Private backup: {record['backup']}", flush=True)
        try:
            activate(previous, original, runtime, operation, record, marker)
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
