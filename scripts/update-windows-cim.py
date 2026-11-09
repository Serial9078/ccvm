"""Publish basic shell-free Windows CIM inventory on the retained login runtime.

Read-only preflight by default. --apply builds the reviewed UI before an idle-only
publication, checks a private PostgreSQL backup and preserves the schema, evidence,
accounts, sessions, vault and ingress. Existing API and worker containers stop and
start to load reviewed Python code; images, settings and container IDs are retained.
"""

import argparse
import base64
import copy
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
OLD_REVISION = REVISION = "e7b5c9d2a401"
LOGIN_BASE = "51c9e544102900c0efb5070358c1c9da2f9942db"
ENROLLMENT_BASE = "7e7c36a9ccc410f7fe282759ae685ef1b15d3f8c"
PROBE_BASE = "e7e2804ab4c66c0d8d77a4056389bfb2548fc1b2"
BASES = {LOGIN_BASE, ENROLLMENT_BASE, PROBE_BASE}
JOURNAL = "ccvm-windows-cim-deployment.json"
PRIOR_JOURNAL = "ccvm-secure-login-deployment.json"
ENROLLMENT_JOURNAL = "ccvm-auth-enrollment-update.json"
BACKUP_PREFIX = "ccvm-windows-cim-before-"
ALLOWED = {
    "scripts/update-windows-cim.py",
    "scripts/tests/test_update_windows_cim.py",
    "scripts/probe-windows-cim.py",
    "scripts/tests/test_probe_windows_cim.py",
    "scripts/update-auth-enrollment.py",
    "scripts/tests/test_update_auth_enrollment.py",
    "backend/integration/authenticated_deployment.py",
    "backend/integration/check_auth_enrollment_deployment.py",
    "backend/integration/check_auth_enrollment_terminal.py",
    "backend/integration/check_enrollment_qr.py",
    "backend/integration/check_windows_cim_deployment.py",
    "backend/integration/check_windows_cim_native.py",
    "backend/app/auth_admin.py",
    "backend/app/services/enrollment_qr.py",
    "backend/app/vendor/__init__.py",
    "backend/app/vendor/qrcodegen.py",
    "backend/app/vendor/qrcodegen.LICENSE",
    "backend/app/vendor/qrcodegen.PROVENANCE.md",
    "backend/app/services/windows_cim.py",
    "backend/app/services/host_audit_transport.py",
    "backend/app/services/host_inventory.py",
    "backend/app/services/scanner_capabilities.py",
    "backend/app/plugins/hostinventory.py",
    "backend/app/schemas/host_audit.py",
    "backend/app/schemas/host_overview.py",
    "backend/app/api/v1/host_audits.py",
    "backend/app/api/v1/host_overview.py",
    "backend/app/api/v1/host_discovery.py",
    "backend/app/api/v1/host_assessments.py",
    "backend/app/api/v1/software_assessments.py",
    "docs/secure-login.md",
    "docs/windows-cim-readiness.md",
    "docs/windows-cim-inventory.md",
    ".github/workflows/ci.yml",
}
PREFIXES = ("frontend/src/features/host-audits/", "frontend/tests/", "backend/tests/")
REQUIRED = {
    "backend/app/services/windows_cim.py",
    "backend/app/services/host_audit_transport.py",
    "backend/app/services/host_inventory.py",
    "backend/app/plugins/hostinventory.py",
    "backend/app/schemas/host_audit.py",
    "backend/app/api/v1/host_audits.py",
}

POLICY_FINGERPRINT = r"""
import hashlib,json,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]);parent=root/'backend/.ccvm-auth';path=parent/'auth-policy.json'
if parent.resolve()!=parent: raise RuntimeError('Authentication path is a symlink')
if not os.path.lexists(path):
    print(json.dumps({'present':False}));raise SystemExit(0)
descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(descriptor,'rb') as stream:
    info=os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:
        raise RuntimeError('Private authentication policy changed')
    data=stream.read(4097)
if len(data)>4096: raise RuntimeError('Authentication policy is too large')
print(json.dumps({'present':True,'sha256':hashlib.sha256(data).hexdigest(),
                 'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode)}))
"""


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
    """No schema or row changes, including active users and encrypted credentials."""
    if before.get("revision") != REVISION or after.get("revision") != REVISION:
        raise RuntimeError("The retained CIM inventory schema changed")
    if before["identity"] != after["identity"]:
        raise RuntimeError("Existing database identity changed; retain the private backup")
    if before["tables"] != after["tables"]:
        raise RuntimeError("Existing database rows or tables changed; retain the private backup")


def policy_fingerprint(original, runtime):
    return json.loads(
        original.run(
            [*runtime.privileged, "python3", "-I", "-c", POLICY_FINGERPRINT, str(runtime.root)],
            diagnostic=runtime.diagnostic,
        )
    )


def previous_update(previous, original, runtime, operation, directory, host, base):
    """Validate the verified login publication and optional CLI-only successor."""
    if base not in BASES:
        raise RuntimeError("Installed source is not a reviewed CIM inventory predecessor")
    login = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-secure-login.py",
        "cim_retained_login",
    )
    marker = directory / PRIOR_JOURNAL
    previous.private_path(marker)
    record = json.loads(marker.read_text())
    if (
        record.get("phase") != "verified"
        or record.get("version") != login.VERSION
        or record.get("host") != host
        or record.get("target") != LOGIN_BASE
    ):
        raise RuntimeError("A verified reviewed secure login update is required")
    workspace_base = login.previous_update(previous, original, runtime, operation, directory, host)
    retained = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-host-inventory.py",
        "cim_login_driver",
    )
    login.configure(retained, original, runtime, directory, workspace_base)
    retained.validate_record(record, marker, LOGIN_BASE, host, workspace_base)
    retained.retained(original, runtime, operation, record)
    retained.validate_artifacts(record)
    enrollment = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-auth-enrollment.py",
        "cim_retained_enrollment",
    )
    enrollment_marker = directory / ENROLLMENT_JOURNAL
    if os.path.lexists(enrollment_marker):
        previous.private_path(enrollment_marker)
        enrolled = json.loads(enrollment_marker.read_text())
        enrollment.validate_record(runtime.root, enrolled, ENROLLMENT_BASE, host)
        if enrolled.get("phase") != "verified" or base == LOGIN_BASE:
            raise RuntimeError("Complete the retained enrollment update before CIM publication")
    elif base != LOGIN_BASE:
        raise RuntimeError("The installed enrollment source lacks its verified private journal")
    return base


def validate_fixed_source(root, target):
    """The rollout may install the prior CLI release but never change its assets."""
    enrollment = load_helper(
        root, target, "scripts/update-auth-enrollment.py", "cim_enrollment_assets"
    )
    for name in enrollment.ASSETS:
        if git(root, "rev-parse", f"{target}:{name}") != git(
            root, "rev-parse", f"{ENROLLMENT_BASE}:{name}"
        ):
            raise RuntimeError("CIM target changes unrelated authentication enrollment source")
    for name in (
        "scripts/deploy-authenticated-inventory.py",
        "scripts/authenticated_ingress.py",
        "scripts/deploy-network-scans.py",
        "scripts/update-host-inventory.py",
        "scripts/update-windows-clients.py",
        "scripts/update-host-workspace.py",
        "scripts/update-secure-login.py",
        "scripts/update-auth-enrollment.py",
    ):
        if git(root, "rev-parse", f"{target}:{name}") != git(
            root, "rev-parse", f"{ENROLLMENT_BASE}:{name}"
        ):
            raise RuntimeError("Retained publication helpers changed outside this CIM update")


def verify_cim_api(runtime):
    result = json.loads(
        runtime.docker(
            "exec",
            "--workdir",
            "/tmp",
            "ccvm-backend",
            "python",
            "-I",
            "-B",
            "-c",
            "import sys,json;sys.path.insert(0,'/app');from app.main import app;"
            "from app.services import windows_cim;"
            "s=app.openapi()['components']['schemas'];"
            "print(json.dumps({'modes':s['HostAuditCreate']['properties']['mode']['enum'],"
            "'transport':s['HostAuditCreate']['properties']['winrm_transport'],"
            "'provider':windows_cim.COLLECTION_METHOD}))",
        )
    )
    if (
        not {"connection", "inventory", "windows_updates", "cim_connection", "cim_inventory"}
        <= set(result.get("modes", []))
        or result.get("provider") != "cim"
        or result.get("transport", {}).get("default") != "https"
        or set(result.get("transport", {}).get("enum", [])) != {"https", "http_ntlm"}
    ):
        raise RuntimeError("Published API does not expose the reviewed CIM collection modes")
    ready = runtime.docker(
        "exec",
        "--workdir",
        "/tmp",
        "ccvm-worker",
        "python",
        "-I",
        "-B",
        "-c",
        "import sys;sys.path.insert(0,'/app');from app.services import windows_cim;"
        "assert windows_cim.COLLECTION_METHOD=='cim';print('cim-provider-ready')",
    )
    if ready != "cim-provider-ready":
        raise RuntimeError("Retained worker cannot load the reviewed CIM collection provider")


def configure(previous, original, runtime, directory, application_base):
    """Retain secure ingress, replace the additive migration with row equality."""
    base_prepare, base_source_plan = previous.prepare, previous.source_plan
    login = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-secure-login.py",
        "cim_login_publisher",
    )
    login.configure(previous, original, runtime, directory, application_base)
    prior_capture, prior_verify = previous.capture_private, previous.verify
    enrollment = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-auth-enrollment.py",
        "cim_private_config",
    )
    previous.VERSION = VERSION
    previous.OLD_REVISION, previous.REVISION = OLD_REVISION, REVISION
    previous.BACKUP_PREFIX = BACKUP_PREFIX
    previous.ALLOWED, previous.PREFIXES = ALLOWED, PREFIXES
    previous.MIGRATION_LABEL = "unchanged secure inventory schema"
    previous.VERIFICATION_LABEL = "CIM inventory API, retained evidence and existing HTTPS ingress"
    previous.VERIFIED_LABEL = "shell-free Windows CIM inventory and retained operator access"
    previous.state_code = lambda source: source.STATE_CODE
    previous.preserve_rows = preserve_rows
    previous.assert_migrated = lambda source, running, work, record, current: preserve_rows(
        record["before"], current
    )

    def source_plan(root, target, base, *, resume=False):
        changes = base_source_plan(root, target, base, resume=resume)
        if not REQUIRED <= set(changes):
            raise RuntimeError("Reviewed target lacks the complete CIM collection source")
        return changes

    previous.source_plan = source_plan

    def capture(source, running, operation):
        files = prior_capture(source, running, operation)
        files["prior-secure-login-journal"] = base64.b64encode(
            (directory / PRIOR_JOURNAL).read_bytes()
        ).decode()
        marker = directory / ENROLLMENT_JOURNAL
        files["prior-enrollment-journal"] = (
            base64.b64encode(marker.read_bytes()).decode() if marker.is_file() else None
        )
        files["auth-policy-fingerprint"] = policy_fingerprint(source, running)
        files["retained-private-config-hashes"] = enrollment.protected_config(running.root)
        return files

    previous.capture_private = capture

    def prepare(source, running, operation, target, marker):
        # Unlike login's first activation, a CIM publication preserves either
        # already-selected auth mode and all populated authentication tables.
        login.policy_state(source, running, operation)
        record = base_prepare(source, running, operation, target, None)
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

    previous.prepare = prepare

    def verify(source, running, work, record):
        prior_verify(source, running, work, record)
        verify_cim_api(running)

    previous.verify = verify


def activate(previous, original, runtime, operation, record, marker):
    if record["phase"] == "verified":
        previous.retained(original, runtime, operation, record)
        previous.verify(original, runtime, previous.work_operation(operation, record), record)
        print(f"VERIFIED: CIM inventory already installed at {record['target']}")
        return
    clients = load_helper(
        runtime.root, runtime.reviewed_target, "scripts/update-windows-clients.py", "cim_activation"
    )
    clients.REVISION = REVISION
    clients.preserve_rows = preserve_rows
    clients.activate(previous, original, runtime, operation, record, marker)
    if record["phase"] != "verified":
        raise RuntimeError("CIM inventory publication did not reach verification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != args.host:
        raise RuntimeError("Unexpected CIM inventory publication host")
    if not re.fullmatch(r"[0-9a-f]{40}", args.target):
        raise RuntimeError("Use the full reviewed CIM inventory target SHA")
    root = Path.cwd().resolve()
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    previous = load_helper(
        root, args.target, "scripts/update-host-inventory.py", "cim_prior_driver"
    )
    original = load_helper(
        root, args.target, "scripts/deploy-authenticated-inventory.py", "cim_deployment"
    )
    ingress = load_helper(root, args.target, "scripts/authenticated_ingress.py", "cim_ingress")
    legacy = load_helper(root, args.target, "scripts/deploy-network-scans.py", "cim_legacy")
    enrollment = load_helper(
        root, args.target, "scripts/update-auth-enrollment.py", "cim_enrollment_lock"
    )
    deployment_marker = directory / previous.DEPLOYMENT_JOURNAL
    previous.private_path(deployment_marker)
    operation = json.loads(deployment_marker.read_text())
    if operation.get("phase") != "verified" or operation.get("host") != args.host:
        raise RuntimeError("A verified authenticated inventory deployment is required")
    runtime = original.Runtime(root, operation["target"], ingress)
    runtime.legacy, runtime.reviewed_target = legacy, args.target
    runtime.diagnostic = directory / "ccvm-windows-cim-preflight.log"
    params = types.SimpleNamespace(
        hostname=operation["hostname"],
        clients=operation["clients"],
        certificate=operation["certificate"],
        host=args.host,
        **{name + "_image": value for name, value in operation["pins"].items()},
    )
    with (
        enrollment.publication_lock(root, create=args.apply),
        enrollment.AdminLock(root, create=args.apply),
    ):
        validate_fixed_source(root, args.target)
        original.validate_journal(runtime, params, operation, deployment_marker)
        marker, record = directory / JOURNAL, None
        if os.path.lexists(marker):
            previous.private_path(marker)
            record = json.loads(marker.read_text())
        base = record.get("base") if record else git(root, "rev-parse", "HEAD")
        application_base = previous_update(
            previous, original, runtime, operation, directory, args.host, base
        )
        previous = load_helper(
            root, args.target, "scripts/update-host-inventory.py", "cim_update_driver"
        )
        configure(previous, original, runtime, directory, application_base)
        previous.source_plan(root, args.target, application_base, resume=record is not None)
        print(f"CCVM Windows CIM updater {VERSION}; reviewed target {args.target}", flush=True)
        if record:
            previous.validate_record(record, marker, args.target, args.host, application_base)
            if (
                record["phase"] in {"prepared", "built", "quiesced", "migrating"}
                and git(root, "rev-parse", "HEAD") != application_base
            ):
                raise RuntimeError("Source advanced before retained schema verification completed")
            previous.retained(original, runtime, operation, record)
            if record["phase"] != "verified" and args.apply and not args.resume:
                raise RuntimeError("Retained incomplete CIM publication requires --resume")
        if not args.apply:
            if record and record["phase"] == "verified":
                previous.verify(
                    original, runtime, previous.work_operation(operation, record), record
                )
            elif record:
                print(
                    f"PREFLIGHT OK: retained CIM publication at {record['phase']}; "
                    "use --apply --resume."
                )
            else:
                previous.prepare(original, runtime, operation, args.target, None)
                print("PREFLIGHT OK: idle CIM inventory deployment; no changes performed.")
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
