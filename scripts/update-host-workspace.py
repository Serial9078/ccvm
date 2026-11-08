#!/usr/bin/env python3
"""Publish the reviewed host workspace on a verified Windows clients deployment.

Read-only preflight by default. --apply builds the UI before a short idle-only
publication, retains a checked private database backup, and preserves every row.
No schema, dependency, scanner, credential, ingress or runtime changes are allowed.
Use --resume only to continue this updater's own retained publication journal.
"""

import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import types
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath

VERSION = "1.0.0"
OLD_REVISION = REVISION = "d6a4b8e2f901"
JOURNAL = "ccvm-host-workspace-deployment.json"
PRIOR_JOURNAL = "ccvm-windows-clients-deployment.json"
BACKUP_PREFIX = "ccvm-host-workspace-before-"
NEW_TABLES = set()
ALLOWED = {
    "scripts/update-host-workspace.py",
    "scripts/tests/test_update_host_workspace.py",
    "backend/integration/authenticated_deployment.py",
    "docs/authenticated-inventory.md",
    ".github/workflows/ci.yml",
}
PREFIXES = ("frontend/src/features/host-audits/", "frontend/tests/")


UI_PROBE = r"""
import hashlib,http.client,json,socket,ssl,sys
p=json.load(sys.stdin)
context=ssl.create_default_context()
for path,expected in p['files'].items():
    raw=socket.create_connection(('127.0.0.1',p['port']),timeout=8)
    version='TCP6' if ':' in p['client'] else 'TCP4'
    destination='::1' if version=='TCP6' else '127.0.0.1'
    raw.sendall(f"PROXY {version} {p['client']} {destination} 12345 {p['port']}\r\n".encode())
    with context.wrap_socket(raw,server_hostname=p['hostname']) as tls:
        request=f"GET {path} HTTP/1.1\r\nHost: {p['hostname']}\r\nConnection: close\r\n\r\n"
        tls.sendall(request.encode())
        response=http.client.HTTPResponse(tls)
        response.begin()
        if response.status!=200 or response.getheader('X-CCVM-Route')!=p['marker']:
            raise RuntimeError('Published HTTPS UI route is unavailable or changed')
        body=response.read(expected['bytes']+1)
        if len(body)!=expected['bytes'] or hashlib.sha256(body).hexdigest()!=expected['sha256']:
            raise RuntimeError('Published HTTPS UI content differs from the reviewed build')
print(json.dumps({'ui':True,'assets':len(p['files'])-1}))
"""


class EntryAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = set()
        self.scripts = set()

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.paths.add(values["src"])
            self.scripts.add(values["src"])
        if tag == "link" and {"stylesheet", "icon"} & set(values.get("rel", "").split()):
            if values.get("href"):
                self.paths.add(values["href"])


def ui_manifest(work, record):
    """Only request recorded local application assets, never arbitrary URLs."""
    directory = Path(work["built_frontend"])
    expected = record["artifacts"]["frontend/dist"]
    entry = (directory / "index.html").read_bytes()
    parser = EntryAssets()
    parser.feed(entry.decode("utf-8"))
    if not parser.scripts:
        raise RuntimeError("Reviewed UI entrypoint has no application script")
    logo = "assets/cloudcollab-logo.jpg"
    if logo in expected:
        parser.paths.add("/" + logo)
    files = {"/": {"bytes": len(entry), "sha256": hashlib.sha256(entry).hexdigest()}}
    if files["/"]["sha256"] != expected.get("index.html"):
        raise RuntimeError("Reviewed UI entrypoint changed")
    for path in sorted(parser.paths):
        relative = path.removeprefix("/")
        if (
            not re.fullmatch(r"/assets/[A-Za-z0-9_./-]+", path)
            or ".." in PurePosixPath(path).parts
            or relative not in expected
        ):
            raise RuntimeError("UI entrypoint references an unrecorded local asset")
        asset = directory / relative
        size = asset.stat().st_size
        if asset.is_symlink() or not asset.is_file() or not 0 < size <= 16 * 1024 * 1024:
            raise RuntimeError("Unexpected UI asset path or size")
        files[path] = {"bytes": size, "sha256": expected[relative]}
    return files


def verify_ui(runtime, work, record):
    files = ui_manifest(work, record)
    network = ipaddress.ip_network(work["clients"][0])
    payload = {
        "hostname": work["hostname"],
        "client": str(next(network.hosts())),
        "port": work["tls_port"],
        "marker": work["target"][:12],
        "files": files,
    }
    result = json.loads(
        runtime.docker(
            "run",
            "-i",
            "--rm",
            "--pull=never",
            "--network",
            "container:haproxy-edge",
            "--workdir",
            "/tmp",
            "--entrypoint",
            "python",
            work["images"]["backend"],
            "-I",
            "-B",
            "-c",
            UI_PROBE,
            data=json.dumps(payload).encode(),
            timeout=90,
        )
    )
    if result != {"ui": True, "assets": len(files) - 1}:
        raise RuntimeError("HTTPS UI verification did not attest the reviewed assets")
    print(f"HTTPS UI and {result['assets']} reviewed assets verified.", flush=True)


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
    """Validate the five predecessors with their unchanged versions and prefixes."""
    clients = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-windows-clients.py",
        "workspace_retained_clients",
    )
    marker = directory / PRIOR_JOURNAL
    previous.private_path(marker)
    record = json.loads(marker.read_text())
    if (
        record.get("phase") != "verified"
        or record.get("version") != clients.VERSION
        or record.get("host") != host
        or not re.fullmatch(r"[0-9a-f]{40}", str(record.get("target", "")))
    ):
        raise RuntimeError("A verified previous Windows clients update is required")
    application_base = clients.previous_update(
        previous, original, runtime, operation, directory, host
    )
    retained_driver = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-host-inventory.py",
        "workspace_retained_driver",
    )
    clients.configure(retained_driver, original, runtime, directory, application_base)
    retained_driver.validate_record(record, marker, record["target"], host, application_base)
    retained_driver.retained(original, runtime, operation, record)
    retained_driver.validate_artifacts(record)
    return record["target"]


def configure(previous, original, runtime, directory, application_base):
    """Reuse the no-schema publisher with a separate journal and UI-only boundary."""
    clients = load_helper(
        runtime.root,
        runtime.reviewed_target,
        "scripts/update-windows-clients.py",
        "workspace_publisher",
    )
    clients.VERSION = VERSION
    clients.BACKUP_PREFIX = BACKUP_PREFIX
    clients.ALLOWED, clients.PREFIXES = ALLOWED, PREFIXES
    clients.configure(previous, original, runtime, directory, application_base)
    prior_capture = previous.capture_private

    def capture(source, running, operation):
        files = prior_capture(source, running, operation)
        files["prior-windows-clients-journal"] = base64.b64encode(
            (directory / PRIOR_JOURNAL).read_bytes()
        ).decode()
        return files

    previous.capture_private = capture
    previous.VERIFICATION_LABEL = "host workspace, preserved evidence and existing HTTPS ingress"
    previous.VERIFIED_LABEL = "CloudCollab host workspace and preserved inventory evidence"
    previous.workspace_activate = clients.activate
    prior_verify = previous.verify

    def verify(source, running, work, record):
        prior_verify(source, running, work, record)
        verify_ui(running, work, record)

    previous.verify = verify


def activate(previous, original, runtime, operation, record, marker):
    """Use the already-tested idle, backup, row-check, publish and resume sequence."""
    previous.workspace_activate(previous, original, runtime, operation, record, marker)
    if record["phase"] != "verified":
        raise RuntimeError("Host workspace publication did not reach verification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != args.host:
        raise RuntimeError("Unexpected host workspace update host")
    if not re.fullmatch(r"[0-9a-f]{40}", args.target):
        raise RuntimeError("Use the full reviewed host workspace update SHA")
    root = Path.cwd().resolve()
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    previous = load_helper(
        root, args.target, "scripts/update-host-inventory.py", "workspace_prior_driver"
    )
    original = load_helper(
        root, args.target, "scripts/deploy-authenticated-inventory.py", "workspace_deployment"
    )
    ingress = load_helper(
        root, args.target, "scripts/authenticated_ingress.py", "workspace_ingress"
    )
    legacy = load_helper(root, args.target, "scripts/deploy-network-scans.py", "workspace_legacy")
    deployment_marker = directory / previous.DEPLOYMENT_JOURNAL
    previous.private_path(deployment_marker)
    operation = json.loads(deployment_marker.read_text())
    if operation.get("phase") != "verified" or operation.get("host") != args.host:
        raise RuntimeError("A verified authenticated inventory deployment is required")
    runtime = original.Runtime(root, operation["target"], ingress)
    runtime.legacy = legacy
    runtime.reviewed_target = args.target
    runtime.diagnostic = directory / "ccvm-host-workspace-preflight.log"
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
            root, args.target, "scripts/update-host-inventory.py", "workspace_update_driver"
        )
        configure(previous, original, runtime, directory, application_base)
        marker = directory / JOURNAL
        previous.source_plan(root, args.target, application_base, resume=marker.exists())
        print(f"CCVM host workspace updater {VERSION}; reviewed target {args.target}", flush=True)
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
                raise RuntimeError("Retained incomplete workspace update requires --resume")
        if not args.apply:
            if record and record["phase"] == "verified":
                previous.verify(
                    original, runtime, previous.work_operation(operation, record), record
                )
            elif record:
                print(f"PREFLIGHT OK: retained update at {record['phase']}; use --apply --resume.")
            else:
                previous.prepare(original, runtime, operation, args.target, None)
                print("PREFLIGHT OK: idle host workspace deployment; no changes performed.")
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
