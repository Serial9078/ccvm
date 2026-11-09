#!/usr/bin/env python3
"""Publish the reviewed terminal enrollment assistant without restarting services.

The default is a read-only preflight. --apply changes only reviewed CLI assets;
--resume continues this updater's own source-publication journal. Database,
credentials, application configuration and container identities are retained.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

VERSION = "1.0.0"
BASE = "51c9e544102900c0efb5070358c1c9da2f9942db"
BRANCH = "sprint-1.0.2-feature-architecture"
JOURNAL = "ccvm-auth-enrollment-update.json"
BACKUP_PREFIX = "ccvm-auth-enrollment-before-"
ASSETS = {
    "backend/app/auth_admin.py",
    "backend/app/services/enrollment_qr.py",
    "backend/app/vendor/__init__.py",
    "backend/app/vendor/qrcodegen.py",
    "backend/app/vendor/qrcodegen.LICENSE",
    "backend/app/vendor/qrcodegen.PROVENANCE.md",
}
ALLOWED = ASSETS | {
    "scripts/update-auth-enrollment.py",
    "scripts/tests/test_update_auth_enrollment.py",
    "backend/tests/test_auth_session.py",
    "backend/tests/test_auth_enrollment.py",
    "backend/tests/test_enrollment_qr.py",
    "backend/integration/check_enrollment_qr.py",
    "backend/integration/check_auth_enrollment_terminal.py",
    "backend/integration/check_auth_enrollment_deployment.py",
    "backend/integration/authenticated_deployment.py",
    "docs/secure-login.md",
    ".github/workflows/ci.yml",
}
LOCAL_CONFIG = {"docker-compose.yml", "frontend/default.conf"}

ROOT_LOCK = r"""
import fcntl,hashlib,json,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]);create=sys.argv[2]=='1'
parent=root/'backend/.ccvm-auth';lock=parent/'auth-admin.lock'
if root.resolve()!=root or parent.resolve()!=parent:
    raise RuntimeError('Authentication path must not use symlinks')
if not parent.exists():
    if not create:
        print(json.dumps({'ready':True,'policy':None}),flush=True)
        sys.stdin.readline();raise SystemExit(0)
    parent.mkdir(mode=0o700)
info=parent.stat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
    raise RuntimeError('Private root-owned authentication directory required')
if not os.path.lexists(lock) and not create:
    print(json.dumps({'ready':True,'policy':None}),flush=True)
    sys.stdin.readline();raise SystemExit(0)
fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW|(os.O_CREAT if create else 0),0o600)
try:
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:
        raise RuntimeError('Private root-owned authentication lock required')
    try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        print(json.dumps({'ready':False,'busy':True}),flush=True);raise SystemExit(2)
    def policy():
        path=parent/'auth-policy.json'
        try: handle=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        except FileNotFoundError: return None
        with os.fdopen(handle,'rb') as source:
            info=os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0
                or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096):
                raise RuntimeError('Private authentication policy changed')
            return hashlib.sha256(source.read(4097)).hexdigest()
    before=policy()
    print(json.dumps({'ready':True,'policy':before}),flush=True)
    sys.stdin.readline()
    if policy()!=before: raise RuntimeError('Authentication policy changed during publication')
finally: os.close(fd)
"""

PROBE = """import json,sys
sys.path.insert(0,'/app')
from app import auth_admin
from app.services.enrollment_qr import encode_matrix
assert auth_admin.ENROLLMENT_UI_VERSION==2
matrix=encode_matrix('CCVM setup check')
assert len(matrix)>20 and all(len(row)==len(matrix) for row in matrix)
print(json.dumps({'enrollment_ui':2,'offline_qr':True}))
"""


def run(argv):
    result = subprocess.run(argv, capture_output=True, timeout=60, check=False)
    if result.returncode:
        raise RuntimeError("Prerequisite command failed; retained services were not changed")
    return result.stdout.decode()


def git(root, *args):
    return run(["git", "-C", str(root), *args]).strip()


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def private(path, *, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
    ):
        raise RuntimeError("Private enrollment update path or permissions changed")


def write_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".enrollment-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(value, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def source_plan(root, target, *, resume=False):
    if not re.fullmatch(r"[0-9a-f]{40}", target):
        raise RuntimeError("Use the full reviewed enrollment target SHA")
    if (
        Path(git(root, "rev-parse", "--show-toplevel")).resolve() != root
        or git(root, "branch", "--show-current") != BRANCH
        or git(root, "rev-parse", "origin/" + BRANCH) != target
        or Path(git(root, "rev-parse", "--absolute-git-dir")) != root / ".git"
    ):
        raise RuntimeError("Reviewed target or deployment checkout changed")
    head = git(root, "rev-parse", "HEAD")
    if head not in {BASE, target} or (head == target and not resume):
        raise RuntimeError("Installed source requires its retained enrollment update journal")
    prior = root / ".git/ccvm-secure-login-deployment.json"
    if os.path.lexists(prior):
        private(prior)
        if json.loads(prior.read_text()).get("phase") != "verified":
            raise RuntimeError(
                "Retained ccvm-secure-login-deployment.json publication is unfinished; "
                "complete its existing resume before advancing enrollment source"
            )
    git(root, "merge-base", "--is-ancestor", BASE, target)
    for name in ("index.lock", "MERGE_HEAD", "CHERRY_PICK_HEAD", "rebase-merge", "rebase-apply"):
        if (root / ".git" / name).exists():
            raise RuntimeError("Another Git operation is unfinished")
    git(root, "diff", "--cached", "--exit-code")
    if set(git(root, "diff", "--name-only").splitlines()) - LOCAL_CONFIG:
        raise RuntimeError("Additional tracked source edits retained")
    changes = set(git(root, "diff", "--name-only", "--no-renames", BASE, target).splitlines())
    if not ASSETS <= changes or changes - ALLOWED:
        raise RuntimeError("Target changes unrelated source or lacks reviewed enrollment assets")
    if git(root, "diff", "--name-only", "--diff-filter=D", BASE, target):
        raise RuntimeError("Source deletion is outside this enrollment update")
    unknown = set(git(root, "ls-files", "--others", "--exclude-standard").splitlines())
    if unknown & changes or any(
        name.startswith(("backend/app/", "backend/alembic/", "frontend/src/"))
        and Path(name).suffix in {".py", ".ts", ".tsx", ".js", ".jsx"}
        for name in unknown
    ):
        raise RuntimeError("Additional application source or target collision retained")
    for name in changes:
        entry = git(root, "ls-tree", target, "--", name).split()
        if len(entry) != 4 or entry[0] not in {"100644", "100755"} or entry[1] != "blob":
            raise RuntimeError("Target contains an unexpected source file type")
        path = root / name
        while path != root:
            if path.is_symlink():
                raise RuntimeError("Symlink in enrollment update path")
            path = path.parent
    return sorted(changes)


def protected_config(root):
    paths = set(root.glob("docker-compose*.yml")) | {root / "frontend/default.conf", root / ".env"}
    paths |= set((root / ".git/ccvm-audit-secrets").glob("*"))
    paths.add(root / ".git/ccvm-secure-login-deployment.json")
    result = {}
    for path in sorted(paths):
        if path.is_symlink():
            raise RuntimeError("Symlink in retained runtime configuration")
        if path.is_file():
            result[str(path.relative_to(root))] = sha256(path.read_bytes())
    return result


class Backend:
    def __init__(self, root):
        self.root = root
        self.privileged = [] if os.geteuid() == 0 else ["sudo", "-n"]

    def docker(self, *args):
        return run([*self.privileged, "docker", *args])

    def inspect(self):
        info = json.loads(self.docker("inspect", "ccvm-backend"))[0]
        state = info["State"]
        mounts = [item for item in info.get("Mounts", []) if item["Destination"] == "/app"]
        if (
            state.get("Status") != "running"
            or state.get("Paused")
            or state.get("Restarting")
            or not state.get("Pid")
            or len(mounts) != 1
            or mounts[0].get("Type") != "bind"
            or not mounts[0].get("RW")
            or Path(mounts[0]["Source"]).resolve() != self.root / "backend"
            or any(str(arg).startswith("--reload") for arg in info["Config"].get("Cmd") or [])
        ):
            raise RuntimeError("Expected running retained backend with writable source bind")
        # Retain the complete runtime settings, but never print its environment.
        settings = {key: info.get(key) for key in ("Config", "HostConfig", "Mounts")}
        return {
            "id": info["Id"],
            "pid": state["Pid"],
            "started": state.get("StartedAt"),
            "settings_sha256": sha256(json.dumps(settings, sort_keys=True).encode()),
        }

    def verify(self, expected):
        if self.inspect() != expected:
            raise RuntimeError("Backend identity, process or runtime configuration changed")

    def probe(self):
        result = json.loads(
            self.docker("exec", "--workdir", "/tmp", "ccvm-backend", "python", "-I", "-c", PROBE)
        )
        if result != {"enrollment_ui": 2, "offline_qr": True}:
            raise RuntimeError("Published enrollment assistant differs from the reviewed version")


class AdminLock:
    def __init__(self, root, *, create=False):
        self.root, self.create, self.process = root, create, None

    def __enter__(self):
        privileged = [] if os.geteuid() == 0 else ["sudo", "-n"]
        self.process = subprocess.Popen(
            [*privileged, "python3", "-I", "-c", ROOT_LOCK, str(self.root), str(int(self.create))],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            ready = json.loads(self.process.stdout.readline())
            if ready.get("busy"):
                raise RuntimeError(
                    "Eine Kontoeinrichtung läuft bereits. Dort zuerst Strg+C drücken; "
                    "anschließend das Update erneut starten."
                )
            if ready.get("ready") is not True:
                raise RuntimeError("Private enrollment lock could not be verified")
            return self
        except (ValueError, RuntimeError) as error:
            self.close(check=False)
            if isinstance(error, ValueError):
                raise RuntimeError(
                    "Private root-owned enrollment lock could not be opened"
                ) from None
            raise

    def close(self, *, check=True):
        if self.process is None:
            return
        try:
            _output, _error = self.process.communicate(input="release\n", timeout=10)
        except (subprocess.TimeoutExpired, BrokenPipeError):
            self.process.kill()
            self.process.communicate(timeout=10)
            if check:
                raise RuntimeError("Enrollment lock helper did not terminate cleanly") from None
        else:
            if check and self.process.returncode:
                raise RuntimeError("Private authentication policy changed or lock helper failed")
        finally:
            self.process = None

    def __exit__(self, kind, value, traceback):
        self.close(check=kind is None)


@contextmanager
def publication_lock(root, *, create):
    path = root / ".git/ccvm-authenticated.lock"
    if not create and not path.exists():
        yield
        return
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else 0), 0o600)
    try:
        private(path)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another retained application update is running") from error
        yield
    finally:
        os.close(descriptor)


def validate_record(root, record, target, host):
    if (
        record.get("version") != VERSION
        or record.get("base") != BASE
        or record.get("target") != target
        or record.get("host") != host
        or record.get("phase") not in {"prepared", "published", "verified"}
    ):
        raise RuntimeError("Retained enrollment update journal changed")
    backup = Path(record["backup"])
    if backup.parent != root / ".git" or not backup.name.startswith(BACKUP_PREFIX):
        raise RuntimeError("Private enrollment backup location changed")
    private(backup, directory=True)
    original = backup / "before.json"
    private(original)
    saved = json.loads(original.read_text())
    if saved != {**record, "phase": "prepared"}:
        raise RuntimeError("Private enrollment backup metadata changed")


def verify_source(root, target):
    for name in ASSETS:
        if (root / name).read_bytes() != subprocess.check_output(
            ["git", "-C", str(root), "show", f"{target}:{name}"], timeout=30
        ):
            raise RuntimeError("Published enrollment assets differ from the reviewed target")


def publish(root, target, host, *, apply=False, resume=False):
    os.umask(0o077)
    marker = root / ".git" / JOURNAL
    record = None
    if os.path.lexists(marker):
        private(marker)
        record = json.loads(marker.read_text())
        validate_record(root, record, target, host)
    changes = source_plan(root, target, resume=record is not None)
    backend = Backend(root)
    current = backend.inspect()
    configs = protected_config(root)
    was_verified = record is not None and record["phase"] == "verified"
    if record:
        # A completed publication remains verifiable after a later legitimate
        # application restart. Pending recovery still binds the exact process.
        def stable_settings(value):
            return {key: item for key, item in value.items() if key not in {"pid", "started"}}

        same_runtime = (
            stable_settings(current) == stable_settings(record["before"])
            if was_verified
            else current == record["before"]
        )
        if not same_runtime or configs != record["configs"]:
            raise RuntimeError("Retained backend process or private configuration changed")
    if record and record["phase"] != "verified" and apply and not resume:
        raise RuntimeError("Incomplete enrollment publication requires --apply --resume")
    with publication_lock(root, create=apply), AdminLock(root, create=apply):
        backend.verify(current)
        if protected_config(root) != configs:
            raise RuntimeError("Private configuration changed before publication")
        if not apply:
            if record and record["phase"] == "verified":
                verify_source(root, target)
                backend.probe()
            print(
                "PREFLIGHT OK: enrollment update checked; no source or service changes performed."
            )
            return
        if record is None:
            backup = Path(tempfile.mkdtemp(prefix=BACKUP_PREFIX, dir=root / ".git"))
            record = {
                "version": VERSION,
                "host": host,
                "base": BASE,
                "target": target,
                "phase": "prepared",
                "backup": str(backup),
                "before": current,
                "configs": configs,
                "changes": changes,
            }
            write_json(backup / "before.json", record)
            write_json(marker, record)
        print(f"Private source recovery metadata: {record['backup']}", flush=True)
        try:
            if record["phase"] == "prepared":
                source_plan(root, target, resume=True)
                if git(root, "rev-parse", "HEAD") != target:
                    git(root, "merge", "--ff-only", target)
                record["phase"] = "published"
                write_json(marker, record)
            if git(root, "rev-parse", "HEAD") != target:
                raise RuntimeError("Published enrollment source changed")
            verify_source(root, target)
            backend.probe()
            backend.verify(current)
            if protected_config(root) != configs:
                raise RuntimeError("Private configuration changed during publication")
            if not was_verified:
                record["phase"] = "verified"
                write_json(marker, record)
        except BaseException:
            print(
                f"Update stopped at {record['phase']}; retain {record['backup']}; "
                "rerun with --apply --resume.",
                flush=True,
            )
            raise
    print(f"VERIFIED: visible-code and offline QR enrollment at {target}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if socket.gethostname().split(".")[0] != args.host:
        raise RuntimeError("Unexpected enrollment update host")
    publish(Path.cwd().resolve(), args.target, args.host, apply=args.apply, resume=args.resume)


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(f"STOPPED: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from None
