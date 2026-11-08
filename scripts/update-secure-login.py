#!/usr/bin/env python3
"""Publish secure sessions and classified transport errors on the retained workspace.

Read-only preflight by default. --apply builds the UI before a short idle-only
publication, retains a checked private database backup, and preserves every row.
Only three initially empty authentication tables are added. No scanner,
credential, ingress, dependency, image or container identity is changed. Account
bootstrap and MFA activation remain a separate, interactive, root-local step.
Use --resume only to continue this updater's own retained publication journal.
"""

import argparse
import base64
import copy
import fcntl
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

VERSION = "1.0.0"
OLD_REVISION, REVISION = "d6a4b8e2f901", "e7b5c9d2a401"
JOURNAL = "ccvm-secure-login-deployment.json"
PRIOR_JOURNAL = "ccvm-host-workspace-deployment.json"
BACKUP_PREFIX = "ccvm-secure-login-before-"
NEW_TABLES = {"auth_users", "auth_sessions", "auth_login_limits"}
ALLOWED = {
    ".gitignore",
    "scripts/update-secure-login.py",
    "scripts/tests/test_update_secure_login.py",
    "backend/integration/authenticated_deployment.py",
    "backend/app/auth_admin.py",
    "backend/app/api/v1/auth.py",
    "backend/app/models/__init__.py",
    "backend/app/models/auth.py",
    "backend/app/services/auth_session.py",
    "backend/app/services/audit_vault.py",
    "backend/app/services/host_inventory.py",
    "backend/app/services/host_audit_transport.py",
    "backend/app/main.py",
    "backend/alembic/versions/e7b5c9d2a401_add_local_operator_auth.py",
    "backend/integration/test_postgres_migrations.py",
    "frontend/src/App.tsx",
    "frontend/src/main.tsx",
    "frontend/src/shared/api/api.ts",
    "frontend/src/shared/layout/AppLayout.tsx",
    "frontend/package.json",
    "docs/authenticated-inventory.md",
    "docs/secure-login.md",
    ".github/workflows/ci.yml",
}
PREFIXES = (
    "frontend/src/features/auth/",
    "frontend/src/features/host-audits/",
    "frontend/src/shared/auth/",
    "frontend/tests/",
    "backend/tests/",
)

POLICY_PROBE = r"""
import json,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]);path=root/'backend/.ccvm-auth/auth-policy.json'
for parent in (path.parent,path.parent.parent):
    if parent.is_symlink(): raise RuntimeError('Authentication policy parent is a symlink')
if path.parent.exists():
    info=path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022:
        raise RuntimeError('Authentication policy directory is not private root configuration')
if not os.path.lexists(path):
    print(json.dumps({'mode':'legacy'}))
else:
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:
            raise RuntimeError('Authentication policy owner or permissions changed')
        raw=stream.read(4097)
    if len(raw)>4096: raise RuntimeError('Authentication policy is too large')
    policy=json.loads(raw)
    if (not isinstance(policy,dict) or set(policy)!={'version','mode','origin'}
        or type(policy['version']) is not int or policy['version']!=1 or policy['mode']!='local'):
        raise RuntimeError('Authentication policy differs from the reviewed local mode')
    print(json.dumps({'mode':'local','origin':policy['origin']}))
"""

SESSION_TLS_PROBE = r"""
import http.client,json,socket,ssl,sys
p=json.load(sys.stdin)
context=ssl.create_default_context(cafile=p.get('ca_file'))
def request(port,client,path,token=None,spoof=False,method='GET',headers=()):
    raw=socket.create_connection(('127.0.0.1',port),timeout=8)
    if client:
        version='TCP6' if ':' in client else 'TCP4'
        destination='::1' if version=='TCP6' else '127.0.0.1'
        raw.sendall(f'PROXY {version} {client} {destination} 12345 {port}\r\n'.encode())
    with context.wrap_socket(raw,server_hostname=p['hostname']) as tls:
        lines=[f'{method} {path} HTTP/1.1',f"Host: {p['hostname']}",'Connection: close']
        if token: lines.append('Authorization: Bearer '+token)
        if spoof: lines += ['X-Forwarded-For: '+p['allowed'],'X-Forwarded-Proto: https']
        lines.extend(headers)
        tls.sendall(('\r\n'.join(lines)+'\r\n\r\n').encode())
        response=http.client.HTTPResponse(tls);response.begin()
        status,marker=response.status,response.getheader('X-CCVM-Route')
        body=response.read(2*1024*1024)
        return status,marker,body,response.getheader('Cache-Control')
def status(*args,**kwargs):
    code,marker,_,_=request(*args,**kwargs)
    return code,marker
expected=p['marker']
assert status(p['port'],p['allowed'],'/health')==(200,expected)
assert status(p['port'],p['denied'],'/health',spoof=True)==(403,expected)
assert status(443,None,'/health',spoof=True)==(403,expected)
code,marker,body,cache=request(p['port'],p['allowed'],'/api/v1/auth/session')
assert (code,marker,cache)==(200,expected,'no-store')
session=json.loads(body)
assert session.get('authenticated') is False
assert session.get('mode') in {'local','legacy'}
path='/api/v1/host-audits?customer_id=1'
assert status(p['port'],p['allowed'],path)==(401,expected)
assert status(p['port'],p['allowed'],path,'incorrect-operator-token')==(401,expected)
if session['mode']=='legacy':
    assert status(p['port'],p['allowed'],path,p['token'])==(200,expected)
else:
    assert status(p['port'],p['allowed'],path,p['token'])==(401,expected)
    for path in ('/api/v1/customers','/api/v1/network-scans/capabilities','/api/v1/jobs'):
        code,marker,_,cache=request(p['port'],p['allowed'],path)
        assert (code,marker,cache)==(401,expected,'no-store')
    assert status(p['port'],p['allowed'],'/api/v1/auth/login',method='POST',
                  headers=['Content-Length: 0'])==(403,expected)
print(json.dumps({'tls':True,'sni':True,'allowed_client':True,'denied_client':True,
                  'header_spoof_denied':True,'auth_mode':session['mode']}))
"""


def policy_state(original, runtime, operation):
    """Read only the root-local activation selection, never authentication secrets."""
    result = json.loads(
        original.run(
            [*runtime.privileged, "python3", "-I", "-c", POLICY_PROBE, str(runtime.root)],
            diagnostic=runtime.diagnostic,
        )
    )
    expected = {"mode": "local", "origin": "https://" + operation["hostname"]}
    if result not in ({"mode": "legacy"}, expected):
        raise RuntimeError("Local login origin differs from the retained HTTPS ingress")
    return result


def preserve_rows(before, after):
    """Add exactly the empty auth schema; preserve every existing scalar and ID."""
    if before["revision"] != OLD_REVISION or after["revision"] not in {OLD_REVISION, REVISION}:
        raise RuntimeError("The retained secure login schema changed")
    if before["identity"] != after["identity"]:
        raise RuntimeError("Existing database identity changed; retain the private backup")
    if any(after["tables"].get(name) != value for name, value in before["tables"].items()):
        raise RuntimeError("Existing database rows changed; retain the private backup")
    extra = set(after["tables"]) - set(before["tables"])
    if extra != (NEW_TABLES if after["revision"] == REVISION else set()) or any(
        after["tables"][name]["count"] for name in extra
    ):
        raise RuntimeError("Secure login migration did not add exactly three empty tables")


def wait_secure_application(original, runtime, operation):
    """Verify health without turning protected capabilities into a public bypass."""
    from urllib.error import HTTPError

    for attempt in range(30):
        try:
            for port in (8088, 8090):
                with runtime.opener.open(f"http://127.0.0.1:{port}/health", timeout=5) as reply:
                    if reply.status != 200:
                        raise RuntimeError("Application health endpoint failed")
                try:
                    with runtime.opener.open(
                        f"http://127.0.0.1:{port}/api/v1/network-scans/capabilities", timeout=5
                    ):
                        raise RuntimeError("Direct HTTP unexpectedly reached a private API")
                except HTTPError as error:
                    if error.code != 403:
                        raise RuntimeError("Direct HTTP session guard changed") from None
            capabilities = json.loads(
                runtime.docker(
                    "exec",
                    "--workdir",
                    "/tmp",
                    "ccvm-backend",
                    "python",
                    "-I",
                    "-c",
                    "import sys,json;sys.path.insert(0,'/app');"
                    "from app.api.v1.network_scans import capabilities;"
                    "print(json.dumps(capabilities()))",
                )
            )
            expected = [
                str(ipaddress.ip_network(n.strip())) for n in operation["scanner_policy"].split(",")
            ]
            if not capabilities["enabled"] or capabilities["allowed_cidrs"] != expected:
                raise RuntimeError("Scanner policy changed")
            return
        except (OSError, ValueError):
            if attempt == 10:
                runtime.docker("exec", "ccvm-frontend", "nginx", "-s", "reload")
            time.sleep(1)
    raise RuntimeError("Secure application API/proxy did not become healthy")


def verify_login_api(runtime):
    spec = json.loads(
        runtime.docker(
            "exec",
            "--workdir",
            "/tmp",
            "ccvm-backend",
            "python",
            "-I",
            "-c",
            "import sys,json;sys.path.insert(0,'/app');from app.main import app;"
            "print(json.dumps(list(app.openapi()['paths'])))",
        )
    )
    if not {"/api/v1/auth/session", "/api/v1/auth/login", "/api/v1/auth/logout"} <= set(spec):
        raise RuntimeError("Published API does not expose the reviewed session workflow")


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


def previous_update(previous, original, runtime, operation, directory, host):
    """Validate every predecessor through the retained workspace publication."""
    workspace = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-host-workspace.py",
        "login_retained_workspace",
    )
    marker = directory / PRIOR_JOURNAL
    previous.private_path(marker)
    record = json.loads(marker.read_text())
    if (
        record.get("phase") != "verified"
        or record.get("version") != workspace.VERSION
        or record.get("host") != host
        or not re.fullmatch(r"[0-9a-f]{40}", str(record.get("target", "")))
    ):
        raise RuntimeError("A verified previous host workspace update is required")
    application_base = workspace.previous_update(
        previous, original, runtime, operation, directory, host
    )
    retained_driver = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-host-inventory.py",
        "login_retained_driver",
    )
    workspace.configure(retained_driver, original, runtime, directory, application_base)
    retained_driver.validate_record(record, marker, record["target"], host, application_base)
    retained_driver.retained(original, runtime, operation, record)
    retained_driver.validate_artifacts(record)
    return record["target"]


def configure(previous, original, runtime, directory, application_base):
    """Retain the whole publication chain with one explicit additive migration."""
    base_prepare = previous.prepare
    workspace = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-host-workspace.py",
        "login_publisher",
    )
    workspace.configure(previous, original, runtime, directory, application_base)
    prior_capture = previous.capture_private
    prior_verify = previous.verify
    previous.VERSION = VERSION
    previous.OLD_REVISION, previous.REVISION = OLD_REVISION, REVISION
    previous.BACKUP_PREFIX = BACKUP_PREFIX
    previous.ALLOWED, previous.PREFIXES = ALLOWED, PREFIXES
    previous.state_code = lambda source: source.STATE_CODE
    previous.preserve_rows = preserve_rows
    previous.assert_migrated = lambda source, running, work, record, current: preserve_rows(
        record["before"], current
    )
    previous.MIGRATION_LABEL = "additive secure login migration"
    previous.VERIFICATION_LABEL = "secure login API, retained evidence and existing HTTPS ingress"
    previous.VERIFIED_LABEL = "secure login and classified host transport diagnostics"

    def capture(source, running, operation):
        files = prior_capture(source, running, operation)
        files["prior-host-workspace-journal"] = base64.b64encode(
            (directory / PRIOR_JOURNAL).read_bytes()
        ).decode()
        return files

    previous.capture_private = capture

    def prepare(source, running, operation, target, marker):
        if policy_state(source, running, operation)["mode"] != "legacy":
            raise RuntimeError("Initial login publication requires the retained token mode")
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
    old_wait = original.wait_application

    def wait_application(running, operation):
        if policy_state(original, running, operation)["mode"] == "legacy":
            return old_wait(running, operation)
        return wait_secure_application(original, running, operation)

    original.wait_application = wait_application
    original.TLS_PROBE = SESSION_TLS_PROBE

    def verify(source, running, work, record):
        prior_verify(source, running, work, record)
        verify_login_api(running)

    previous.verify = verify


def activate(previous, original, runtime, operation, record, marker):
    """Use the reviewed idle, backup, migration, publication and resume sequence."""
    previous.activate(original, runtime, operation, record, marker)
    if record["phase"] != "verified":
        raise RuntimeError("Secure login publication did not reach verification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != args.host:
        raise RuntimeError("Unexpected secure login update host")
    if not re.fullmatch(r"[0-9a-f]{40}", args.target):
        raise RuntimeError("Use the full reviewed secure login update SHA")
    root = Path.cwd().resolve()
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    previous = load_helper(
        root, args.target, "scripts/update-host-inventory.py", "login_prior_driver"
    )
    original = load_helper(
        root, args.target, "scripts/deploy-authenticated-inventory.py", "login_deployment"
    )
    ingress = load_helper(root, args.target, "scripts/authenticated_ingress.py", "login_ingress")
    legacy = load_helper(root, args.target, "scripts/deploy-network-scans.py", "login_legacy")
    deployment_marker = directory / previous.DEPLOYMENT_JOURNAL
    previous.private_path(deployment_marker)
    operation = json.loads(deployment_marker.read_text())
    if operation.get("phase") != "verified" or operation.get("host") != args.host:
        raise RuntimeError("A verified authenticated inventory deployment is required")
    runtime = original.Runtime(root, operation["target"], ingress)
    runtime.legacy = legacy
    runtime.reviewed_target = args.target
    runtime.diagnostic = directory / "ccvm-secure-login-preflight.log"
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
            root, args.target, "scripts/update-host-inventory.py", "login_update_driver"
        )
        configure(previous, original, runtime, directory, application_base)
        marker = directory / JOURNAL
        previous.source_plan(root, args.target, application_base, resume=marker.exists())
        print(f"CCVM secure login updater {VERSION}; reviewed target {args.target}", flush=True)
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
                raise RuntimeError("Retained incomplete secure login update requires --resume")
        if not args.apply:
            if record and record["phase"] == "verified":
                previous.verify(
                    original, runtime, previous.work_operation(operation, record), record
                )
            elif record:
                print(f"PREFLIGHT OK: retained update at {record['phase']}; use --apply --resume.")
            else:
                previous.prepare(original, runtime, operation, args.target, None)
                print("PREFLIGHT OK: idle secure login deployment; no changes performed.")
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
