#!/usr/bin/env python3
"""Repair the diagnosed socket mount of an already migrated inventory deployment.

No build, migration, key rotation, scan submission or source update. The original
deployment journal and its exact reviewed verifier finish the retained rollout.
"""

import argparse
import copy
import fcntl
import hashlib
import json
import os
import re
import socket
import sys
import tempfile
import time
import types
from pathlib import Path

DEPLOYMENT = "742206c4f7af960fb54f653c4aa181cf84c2bec4"
REPAIR_JOURNAL = "ccvm-authenticated-socket-repair.json"
ALLOWED = {
    "scripts/repair-authenticated-gateway.py",
    "scripts/authenticated_ingress.py",
    "scripts/deploy-authenticated-inventory.py",
    "scripts/tests/test_authenticated_gateway_repair.py",
    "backend/integration/check_gateway_mounts.py",
    "backend/integration/authenticated_deployment.py",
    "docs/authenticated-inventory.md",
    ".github/workflows/ci.yml",
}


def load_module(root, revision, path, name):
    import subprocess

    source = subprocess.check_output(["git", "-C", str(root), "show", f"{revision}:{path}"])
    module = types.ModuleType(name)
    module.__file__ = f"<git:{path}>"
    sys.modules[name] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def overlay_pair(ingress, operation, root):
    before = ingress.render_override(
        operation["images"],
        operation["private"],
        operation["socket_dir"],
        operation["gateway_address"],
        str(root / "frontend/dist"),
    ).encode()
    old = b'"target": "/run/ccvm"'
    if before.count(old) != 1:
        raise RuntimeError("Unexpected reviewed socket mount layout")
    return before, before.replace(old, b'"target": "/var/run/ccvm"')


def database_unchanged(original, runtime, operation):
    after = json.loads((Path(operation["attempt_dir"]) / "after.json").read_text())
    current = runtime.state(operation)
    original.validate_state(current, original.REVISION)
    if (
        current["identity"] != after["identity"]
        or current["tables"] != after["tables"]
        or current["transactions"]
    ):
        raise RuntimeError("Retained database evidence changed; no repair performed")


def validate_gateway(original, runtime, legacy, resolved, gateway, operation, recorded):
    if gateway["Image"] != operation["images"]["frontend"]:
        raise RuntimeError("Prepared gateway image changed")
    if set(gateway["HostConfig"].get("Tmpfs", {})) != {"/var/cache/nginx", "/var/run", "/tmp"}:
        raise RuntimeError("Prepared gateway temporary mounts changed")
    clean = {**gateway, "Mounts": [m for m in gateway["Mounts"] if m["Type"] != "tmpfs"]}
    candidates = [resolved]
    if recorded:
        previous = copy.deepcopy(resolved)
        mounts = [
            m
            for m in previous["services"]["audit-gateway"]["volumes"]
            if m.get("type") == "bind" and m.get("source") == operation["socket_dir"]
        ]
        if len(mounts) != 1 or mounts[0]["target"] not in {"/run/ccvm", "/var/run/ccvm"}:
            raise RuntimeError("Unexpected resolved socket mount")
        mounts[0]["target"] = (
            "/run/ccvm" if mounts[0]["target"] == "/var/run/ccvm" else "/var/run/ccvm"
        )
        candidates.append(previous)
    for candidate in candidates:
        try:
            original.validate_service(
                legacy, candidate, "audit-gateway", clean, runtime.inspect(gateway["Image"])
            )
            return
        except RuntimeError:
            pass
    raise RuntimeError("Live gateway differs from the recorded original/corrected configuration")


def wait_gateway(runtime, operation):
    previous = None
    for _ in range(30):
        gateway = runtime.inspect("ccvm-audit-gateway")
        state = gateway["State"]
        net = gateway["NetworkSettings"]["Networks"].get(operation["network"], {})
        good = (
            state["Running"]
            and not state["Paused"]
            and not state["Restarting"]
            and net.get("IPAddress") == operation["gateway_address"]
        )
        identity = (gateway["Id"], state["StartedAt"])
        if good and identity == previous:
            # Prove the listening socket is on the shared host bind, not an
            # unrelated temporary filesystem hidden by a parent mount.
            code = (
                "import json,os,stat,sys; p=json.load(sys.stdin); s=os.lstat(p['path']);"
                "assert stat.S_ISSOCK(s.st_mode) and s.st_gid==p['gid']"
            )
            from subprocess import run

            checked = run(
                [*runtime.privileged, "python3", "-I", "-c", code],
                input=json.dumps(
                    {
                        "path": operation["socket_dir"] + "/gateway.sock",
                        "gid": operation["socket_gid"],
                    }
                ).encode(),
                capture_output=True,
                check=False,
                timeout=10,
            )
            if checked.returncode:
                raise RuntimeError("Gateway did not expose the expected shared host socket")
            return
        previous = identity if good else None
        time.sleep(1)
    raise RuntimeError("Gateway remains unhealthy; inspect its startup log")


def repair(original, ingress, runtime, legacy, args, marker, operation, repair_marker):
    if operation.get("target") != DEPLOYMENT or operation.get("phase") not in {
        "services",
        "edge",
        "verified",
    }:
        raise RuntimeError("This is not the retained diagnosed deployment")
    params = types.SimpleNamespace(
        hostname=operation["hostname"],
        clients=operation["clients"],
        certificate=operation["certificate"],
        host=args.host,
        **{name + "_image": value for name, value in operation["pins"].items()},
    )
    original.validate_journal(runtime, params, operation, marker)
    original.validate_secrets(Path(operation["private"]), operation)
    conf = Path(operation["private"]) / "gateway.conf"
    if hashlib.sha256(conf.read_bytes()).hexdigest() != operation["gateway_hash"]:
        raise RuntimeError("Retained gateway configuration changed")
    expected_conf = ingress.render_gateway(operation["hostname"], operation["clients"]).encode()
    if conf.read_bytes() != expected_conf:
        raise RuntimeError("Gateway configuration differs from the reviewed listener")
    before, after = overlay_pair(ingress, operation, runtime.root)
    overlay = runtime.root / original.OVERRIDE
    actual = overlay.read_bytes()
    if actual not in {before, after}:
        raise RuntimeError("Private overlay changed outside this socket correction")
    if repair_marker.is_symlink():
        raise RuntimeError("Repair journal is a symlink")
    if repair_marker.exists() and (
        repair_marker.stat().st_mode & 0o077 or repair_marker.stat().st_uid != os.geteuid()
    ):
        raise RuntimeError("Private repair journal permissions changed")
    record = json.loads(repair_marker.read_text()) if repair_marker.exists() else None
    if record and (
        record.get("repair_target") != args.target
        or record.get("deployment") != DEPLOYMENT
        or record.get("after") != hashlib.sha256(after).hexdigest()
    ):
        raise RuntimeError("Retained repair identity differs")
    if record and actual == after and operation["phase"] == "verified":
        original.activate(runtime, params, legacy, marker, operation)
        print("VERIFIED: socket repair already applied; existing work retained.")
        return
    if not record and (actual != before or operation["phase"] != "services"):
        raise RuntimeError("Missing original repair intent; current state retained")
    resolved = original.verify_resolved(runtime, operation, legacy)
    for name in ("backend", "worker"):
        container = runtime.inspect("ccvm-" + name)
        if container["State"]["Running"] or container["Image"] != operation["images"][name]:
            raise RuntimeError("Expected the stopped, prepared application containers")
    names = runtime.docker("ps", "-a", "--format", "{{.Names}}").splitlines()
    if "ccvm-audit-gateway" in names:
        gateway = runtime.inspect("ccvm-audit-gateway")
        validate_gateway(original, runtime, legacy, resolved, gateway, operation, bool(record))
    elif not record:
        raise RuntimeError("Original diagnosed gateway is missing")
    if not record:
        import subprocess

        result = subprocess.run(
            [*runtime.prefix, "logs", "--tail", "120", "ccvm-audit-gateway"],
            capture_output=True,
            check=False,
            timeout=15,
        )
        if result.returncode:
            raise RuntimeError("Could not inspect gateway startup diagnostics")
        logs = (result.stdout + result.stderr).decode(errors="replace")
        if (
            "bind() to unix:/run/ccvm/gateway.sock failed (2: No such file or directory)"
            not in logs
        ):
            raise RuntimeError("Gateway startup does not match the diagnosed missing socket")
    if (
        runtime.docker(
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--read-only",
            "--entrypoint",
            "readlink",
            operation["images"]["frontend"],
            "-f",
            "/var/run",
        )
        != "/run"
    ):
        raise RuntimeError("Pinned nginx image does not have the required /var/run alias")
    database_unchanged(original, runtime, operation)
    if not args.apply:
        print("PREFLIGHT OK: diagnosed socket mount; database, images and keys retained.")
        return
    if not record:
        backup = Path(tempfile.mkdtemp(prefix="socket-repair-", dir=operation["backup"]))
        original.private_write(backup / "overlay.before", before)
        original.private_write(backup / "overlay.after", after)
        record = {
            "repair_target": args.target,
            "deployment": DEPLOYMENT,
            "backup": str(backup),
            "before": hashlib.sha256(before).hexdigest(),
            "after": hashlib.sha256(after).hexdigest(),
            "phase": "intent",
        }
        original.write_json(repair_marker, record)
    runtime.diagnostic = Path(record["backup"]) / "last-command.log"
    print("Repairing the socket bind and recreating only the gateway...", flush=True)
    try:
        original.private_write(overlay, after)
        runtime.compose(
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            "--force-recreate",
            "audit-gateway",
            extra=True,
        )
        wait_gateway(runtime, operation)
        print("Shared socket and reserved IP verified. Resuming retained deployment...", flush=True)
        original.activate(runtime, params, legacy, marker, operation)
        record["phase"] = "verified"
        original.write_json(repair_marker, record)
    except BaseException:
        if operation["phase"] != "verified":
            original.recover_failure(runtime, operation, marker)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Full reviewed repair merge SHA")
    parser.add_argument("--host", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != args.host:
        raise RuntimeError("Unexpected host")
    if not re.fullmatch(r"[a-f0-9]{40}", args.target):
        raise RuntimeError("Use the full repair SHA")
    root = Path.cwd().resolve()
    original = load_module(
        root, DEPLOYMENT, "scripts/deploy-authenticated-inventory.py", "socket_repair_original"
    )
    if (
        original.git(root, "branch", "--show-current") != original.BRANCH
        or original.git(root, "rev-parse", "HEAD") != DEPLOYMENT
        or original.git(root, "rev-parse", f"origin/{original.BRANCH}") != args.target
    ):
        raise RuntimeError("Checkout or reviewed repair target changed")
    original.git(root, "merge-base", "--is-ancestor", DEPLOYMENT, args.target)
    changes = set(original.git(root, "diff", "--name-only", DEPLOYMENT, args.target).splitlines())
    if not changes or changes - ALLOWED:
        raise RuntimeError("Repair includes unrelated source changes")
    original.git(root, "diff", "--cached", "--exit-code")
    if set(original.git(root, "diff", "--name-only").splitlines()) - {
        "docker-compose.yml",
        "frontend/default.conf",
    }:
        raise RuntimeError("Additional application edits retained")
    ingress = load_module(
        root, DEPLOYMENT, "scripts/authenticated_ingress.py", "socket_repair_ingress"
    )
    legacy = load_module(
        root, DEPLOYMENT, "scripts/deploy-network-scans.py", "socket_repair_legacy"
    )
    runtime = original.Runtime(root, DEPLOYMENT, ingress)
    directory = Path(original.git(root, "rev-parse", "--absolute-git-dir"))
    descriptor = os.open(
        directory / "ccvm-authenticated.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = directory / original.JOURNAL
        if marker.is_symlink():
            raise RuntimeError("Deployment journal is a symlink")
        operation = json.loads(marker.read_text())
        repair(
            original, ingress, runtime, legacy, args, marker, operation, directory / REPAIR_JOURNAL
        )


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(f"STOPPED: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from None
