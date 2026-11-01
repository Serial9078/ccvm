#!/usr/bin/env python3
"""Apply the reviewed long-URL fix on Neptun. Preflight by default; --apply activates it.

Requires a full --target SHA already merged into the deployment branch. The
existing API is stopped and the idle worker's main process is frozen while its
container remains available for migration commands. No scanner is interrupted,
no scan is started, and no existing database rows are modified or removed.
"""

import argparse
import fcntl
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener

VERSION = "1.0.1"
BASE = "e51860b931bec53c8b7ba9375c101678374d40af"
BRANCH = "sprint-1.0.2-feature-architecture"
OLD_REVISION = "7f91c32a60d1"
REVISION = "bc64c6f0e217"
CONFIGS = (
    "docker-compose.yml",
    "frontend/default.conf",
    "docker-compose.override.yml",
    "docker-compose.screenshot.yml",
)
SCANNERS = {"nuclei", "katana", "httpx", "subfinder", "dnsx", "naabu"}
STATE_CODE = r"""
import hashlib, json
import sqlalchemy as sa
from app.database.session import engine
with engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection:
    connection.execute(sa.text("SET TRANSACTION READ ONLY"))
    connection.execute(sa.text("SET LOCAL statement_timeout = '60s'"))
    identity = dict(connection.execute(sa.text(
        "SELECT current_database() AS database, inet_server_addr()::text AS address, "
        "inet_server_port() AS port, current_setting('server_version_num')::int AS version"
    )).one()._mapping)
    active = [dict(row._mapping) for row in connection.execute(sa.text(
        "SELECT id, plugin, status FROM jobs WHERE status IN ('queued', 'running') ORDER BY id"))]
    revision = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
    indexes = [dict(row._mapping) for row in connection.execute(sa.text(
        "SELECT c.relname AS name, i.indisunique AS unique, i.indisvalid AS valid, "
        "pg_get_indexdef(i.indexrelid) AS definition "
        "FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid "
        "WHERE i.indrelid='urls'::regclass ORDER BY c.relname"))]
    tables = {}
    for name in sa.inspect(connection).get_table_names():
        if name == "alembic_version":
            continue
        table = sa.Table(name, sa.MetaData(), autoload_with=connection)
        fingerprint, count = hashlib.sha256(), 0
        result = connection.execution_options(stream_results=True).execute(
            sa.select(table).order_by(*table.primary_key.columns))
        for row in result:
            encoded = json.dumps(dict(row._mapping), sort_keys=True, default=str).encode()
            fingerprint.update(len(encoded).to_bytes(8, 'big') + encoded)
            count += 1
        result.close()
        tables[name] = {'count': count, 'sha256': fingerprint.hexdigest()}
    print(json.dumps({'revision': revision, 'active': active, 'identity': identity,
                      'indexes': indexes, 'tables': tables}))
"""


def run(args, *, data=None, output=None, timeout=180):
    result = subprocess.run(
        args,
        input=data,
        stdout=output or subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace")[-2000:]
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {detail}")
    return result.stdout or b""


def git(root, *args):
    return run(["git", "-C", str(root), *args]).decode().strip()


def validate_state(state, *, expected=None):
    if state["active"]:
        raise RuntimeError(f"Active jobs preserved; update refused: {state['active']}")
    if state["revision"] not in {OLD_REVISION, REVISION}:
        raise RuntimeError(f"Unexpected database revision: {state['revision']}")
    if expected and state["revision"] != expected:
        raise RuntimeError("Database revision does not match installed source")
    indexes = {row["name"]: row for row in state["indexes"]}
    if state["revision"] == OLD_REVISION:
        index = indexes.get("uq_urls_domain_url", {})
        if not index.get("unique") or not index.get("valid"):
            raise RuntimeError("The original URL identity constraint is not valid")
    if state["revision"] == REVISION:
        index = indexes.get("uq_urls_domain_url_sha256", {})
        if (
            not index.get("unique")
            or not index.get("valid")
            or "sha256(" not in index.get("definition", "")
            or "uq_urls_domain_url" in indexes
        ):
            raise RuntimeError("URL identity index does not match the reviewed migration")


def source_plan(root, target):
    if not re.fullmatch(r"[0-9a-f]{40}", target) or target == BASE:
        raise RuntimeError("--target must be the full reviewed merge commit SHA")
    if Path(git(root, "rev-parse", "--show-toplevel")).resolve() != root:
        raise RuntimeError("Unexpected repository root")
    if git(root, "branch", "--show-current") != BRANCH:
        raise RuntimeError("Unexpected deployment branch")
    before = git(root, "rev-parse", "HEAD")
    if before not in {BASE, target}:
        raise RuntimeError(f"Unexpected source commit: {before}")
    if git(root, "rev-parse", f"origin/{BRANCH}") != target:
        raise RuntimeError("The deployment branch is not at the reviewed target")
    git(root, "merge-base", "--is-ancestor", BASE, target)
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    for marker in ("index.lock", "MERGE_HEAD", "CHERRY_PICK_HEAD", "rebase-merge", "rebase-apply"):
        if (directory / marker).exists():
            raise RuntimeError(f"Unfinished Git operation: {marker}")
    git(root, "diff", "--cached", "--exit-code")
    dirty = git(root, "diff", "--name-only").splitlines()
    if set(dirty) - set(CONFIGS[:2]):
        raise RuntimeError("Additional tracked edits preserved; update refused")
    changes = git(root, "diff", "--name-only", "--no-renames", BASE, target).splitlines()
    if any(
        name in CONFIGS or not name.startswith(("backend/", "scripts/", "docs/"))
        for name in changes
    ):
        raise RuntimeError("Target changes files outside this backend-only correction")
    if git(root, "diff", "--name-only", "--diff-filter=D", BASE, target):
        raise RuntimeError("Code deletions are outside this correction")
    unknown = git(root, "ls-files", "--others", "--exclude-standard").splitlines()
    if set(unknown) & set(changes):
        raise RuntimeError("Untracked target file collision preserved")
    for name in unknown:
        if name.startswith(("backend/app/", "backend/alembic/")) and Path(name).suffix == ".py":
            raise RuntimeError(f"Additional application source preserved: {name}")
    for name in set(changes) | set(CONFIGS):
        if any(
            parent.is_symlink()
            for parent in (root / name, *(root / name).parents)
            if parent != root and root in parent.parents
        ):
            raise RuntimeError(f"Symlink in update path: {name}")
    return before, changes


class Runtime:
    def __init__(self):
        self.prefix = ["docker"]
        try:
            run([*self.prefix, "info", "--format", "{{.ServerVersion}}"])
        except RuntimeError:
            self.prefix = ["sudo", "-n", "docker"]
            self.docker("info", "--format", "{{.ServerVersion}}")
        self.opener = build_opener(ProxyHandler({}))

    def docker(self, *args):
        return run([*self.prefix, *args]).decode().strip()

    def state(self):
        return json.loads(self.docker("exec", "ccvm-worker", "python", "-c", STATE_CODE))

    def preflight(self, root):
        postgres = None
        for name in ("ccvm-backend", "ccvm-worker", "ccvm-postgres"):
            info = json.loads(self.docker("inspect", "--format", "{{json .}}", name))
            if not info["State"]["Running"] or info["State"]["Paused"]:
                raise RuntimeError(f"Container is not running normally: {name}")
            if name == "ccvm-postgres":
                postgres = info
            if name == "ccvm-worker":
                argv = info.get("Config", {}).get("Cmd", [])
                if (
                    not isinstance(argv, list)
                    or "-m" not in argv
                    or argv[argv.index("-m") + 1 :] != ["app.worker.main"]
                ):
                    raise RuntimeError("The worker main process is not the expected Python module")
            if name != "ccvm-postgres":
                mounted = [m["Source"] for m in info["Mounts"] if m["Destination"] == "/app"]
                if mounted != [str(root / "backend")]:
                    raise RuntimeError(f"Unexpected backend bind mount: {name}")
        workers = [
            name
            for name in self.docker("ps", "--format", "{{.Names}}").splitlines()
            if name.startswith("ccvm-worker")
        ]
        if workers != ["ccvm-worker"]:
            raise RuntimeError("Expected exactly one existing CCVM worker container")
        argv = json.loads(
            self.docker(
                "exec",
                "ccvm-worker",
                "python",
                "-c",
                "import json; print(json.dumps(open('/proc/1/cmdline', 'rb').read()"
                ".decode().strip(chr(0)).split(chr(0))))",
            )
        )
        if (
            len(argv) != 3
            or not re.fullmatch(r"python(?:3(?:\.\d+)?)?", Path(argv[0]).name)
            or argv[1:] != ["-m", "app.worker.main"]
        ):
            raise RuntimeError("Container PID 1 is not the expected worker main process")
        listing = self.docker("top", "ccvm-worker", "-eo", "pid,comm").splitlines()
        if not listing or listing[0].split() not in (["PID", "COMMAND"], ["PID", "COMM"]):
            raise RuntimeError("Could not verify worker process listing")
        names = [line.split()[-1] for line in listing[1:]]
        if sum(bool(re.fullmatch(r"python(?:3(?:\.\d+)?)?", n)) for n in names) != 1:
            raise RuntimeError("Expected exactly one Python worker")
        if set(names) & SCANNERS:
            raise RuntimeError("A scanner process is active; update refused")
        standalone = self.docker("top", "ccvm-nuclei", "-eo", "pid,comm").splitlines()
        if len(standalone) != 2 or standalone[1].split()[-1] != "tail":
            raise RuntimeError("Standalone Nuclei container is not idle")
        state = self.state()
        validate_state(state)
        settings = dict(
            item.split("=", 1) for item in postgres["Config"].get("Env", []) if "=" in item
        )
        addresses = {
            network.get(key)
            for network in postgres.get("NetworkSettings", {}).get("Networks", {}).values()
            for key in ("IPAddress", "GlobalIPv6Address")
        } - {None, ""}
        identity = state["identity"]
        try:
            # PostgreSQL's inet::text includes /32 or /128; Docker returns a
            # plain host address. Compare exact IP objects, never subnet membership.
            actual_address = ipaddress.ip_interface(identity["address"]).ip
            backup_addresses = {ipaddress.ip_address(address) for address in addresses}
        except (ValueError, TypeError) as error:
            raise RuntimeError(
                "Invalid database IP address: "
                + json.dumps({"actual": identity["address"], "expected": sorted(addresses)})
            ) from error
        if (
            identity["database"] != settings.get("POSTGRES_DB")
            or actual_address not in backup_addresses
            or identity["port"] != 5432
            or identity["version"] // 10000 != 16
        ):
            raise RuntimeError(
                "Application database does not match the PostgreSQL 16 backup target: "
                + json.dumps(
                    {
                        "actual": identity,
                        "expected": {
                            "database": settings.get("POSTGRES_DB"),
                            "addresses": sorted(addresses),
                            "port": 5432,
                            "version_major": 16,
                        },
                    }
                )
            )
        return state

    def freeze(self):
        self.docker("kill", "--signal=STOP", "ccvm-worker")
        status = self.docker(
            "exec", "ccvm-worker", "python", "-c", "print(open('/proc/1/status').read())"
        )
        if not re.search(r"^State:\s+T\b", status, re.MULTILINE):
            raise RuntimeError("Worker main process did not stop")

    def resume(self):
        self.docker("kill", "--signal=CONT", "ccvm-worker")

    def database_backup(self, destination):
        with destination.open("xb") as handle:
            run(
                [
                    *self.prefix,
                    "exec",
                    "ccvm-postgres",
                    "sh",
                    "-c",
                    'exec pg_dump --format=custom --no-password -U "$POSTGRES_USER" '
                    '-d "$POSTGRES_DB"',
                ],
                output=handle,
                timeout=600,
            )
            handle.flush()
            os.fsync(handle.fileno())
        if destination.stat().st_size < 100:
            raise RuntimeError("Database backup is incomplete")
        with destination.open("rb") as handle:
            result = subprocess.run(
                [*self.prefix, "exec", "-i", "ccvm-postgres", "pg_restore", "--list"],
                stdin=handle,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
                check=False,
            )
        if result.returncode or not result.stdout.strip():
            raise RuntimeError("The custom-format database backup could not be inspected")

    def migrate(self):
        return self.docker(
            "exec",
            "--workdir",
            "/app",
            "ccvm-worker",
            "python",
            "-m",
            "alembic",
            "upgrade",
            REVISION,
        )

    def verify(self):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                with self.opener.open("http://127.0.0.1:8088/health", timeout=5) as response:
                    if json.load(response).get("status") == "ok":
                        break
            except Exception:
                pass
            time.sleep(2)
        else:
            raise RuntimeError("API health did not recover")
        for port in (8088, 8090):
            with self.opener.open(f"http://127.0.0.1:{port}/api/v1/urls", timeout=15) as response:
                if not isinstance(json.load(response), list):
                    raise RuntimeError("URL API verification failed")

        request = Request(
            "http://127.0.0.1:8088/api/v1/jobs",
            data=json.dumps({"plugin": "dummy"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with self.opener.open(request, timeout=15) as response:
            job_id = json.load(response)["id"]
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            with self.opener.open(
                f"http://127.0.0.1:8088/api/v1/jobs/{job_id}", timeout=10
            ) as response:
                job = json.load(response)
            if job["status"] == "finished" and job["progress"] == 100:
                print(f"Worker dummy job {job_id} finished.", flush=True)
                return
            if job["status"] in {"failed", "skipped", "cancelled"}:
                raise RuntimeError(f"Worker dummy job {job_id} failed; record retained")
            time.sleep(2)
        raise RuntimeError(f"Worker dummy job {job_id} did not finish; record retained")


def apply(root, target, runtime, plan):
    before, changes = plan
    initial = runtime.preflight(root)
    if before == target:
        validate_state(initial, expected=REVISION)
        runtime.verify()
        print(f"VERIFIED: Git, URL identity index and API already at {target}")
        return
    validate_state(initial, expected=OLD_REVISION)
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    backup = Path(tempfile.mkdtemp(prefix="ccvm-url-index-before-", dir=directory))
    for name in CONFIGS:
        path = root / name
        if path.is_file():
            saved = backup / "config" / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, saved)
    (backup / "operation.json").write_text(json.dumps({"before": before, "target": target}))
    print(f"Private backup: {backup}", flush=True)
    api_stopped = frozen = mutated = False
    coherent = True
    try:
        api_stopped = True
        runtime.docker("stop", "--time", "20", "ccvm-backend")
        validate_state(runtime.state(), expected=OLD_REVISION)
        frozen = True
        runtime.freeze()
        snapshot = runtime.state()
        validate_state(snapshot, expected=OLD_REVISION)
        (backup / "before.json").write_text(json.dumps(snapshot, indent=2))
        runtime.database_backup(backup / "database.dump")
        if source_plan(root, target) != plan:
            raise RuntimeError("Git state changed during backup")
        mutated = True
        git(root, "merge", "--ff-only", target)
        runtime.migrate()
        after = runtime.state()
        (backup / "after.json").write_text(json.dumps(after, indent=2))
        validate_state(after, expected=REVISION)
        if after["tables"] != snapshot["tables"]:
            raise RuntimeError("Database row fingerprints changed; inspect the private backup")
        for saved in (backup / "config").rglob("*"):
            if (
                saved.is_file()
                and saved.read_bytes() != (root / saved.relative_to(backup / "config")).read_bytes()
            ):
                raise RuntimeError("Private configuration changed")
    except BaseException:
        if mutated:
            # A failed migration rolls back its DDL. Undo code only if the old
            # revision is positively confirmed. Never downgrade a migrated DB.
            try:
                state = runtime.state()
                if state["revision"] == OLD_REVISION:
                    if git(root, "rev-parse", "HEAD") != target:
                        raise RuntimeError("Concurrent Git change; automatic rollback refused")
                    git(root, "diff", "--exit-code", "--", *changes)
                    git(
                        root,
                        "restore",
                        "--source",
                        before,
                        "--staged",
                        "--worktree",
                        "--",
                        *changes,
                    )
                    git(root, "update-ref", "HEAD", before, target)
                elif state["revision"] == REVISION:
                    validate_state(state, expected=REVISION)
                else:
                    coherent = False
            except BaseException:
                coherent = False
        print(f"Update stopped; retain backup for inspection: {backup}", flush=True)
        raise
    finally:
        if coherent:
            try:
                if frozen:
                    try:
                        runtime.resume()
                    finally:
                        runtime.docker("restart", "--time", "20", "ccvm-worker")
            finally:
                if api_stopped:
                    runtime.docker("start", "ccvm-backend")
        else:
            # Do not resume an unknown code/schema combination into the queue.
            runtime.docker("stop", "--time", "5", "ccvm-worker")
            print("Code/schema state could not be established; API and worker remain stopped.")
    runtime.verify()
    if git(root, "rev-parse", "HEAD") != target:
        raise RuntimeError("Final Git verification failed")
    print(f"VERIFIED: Neptun Git, URL identity migration, API and worker updated to {target}")
    print("Existing URLs and dependent records retained. Start a new Discover run in the browser.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != "neptun":
        raise RuntimeError("This operator command is restricted to Neptun")
    print(f"CCVM URL identity updater {VERSION}; reviewed target {args.target}", flush=True)
    root = Path("/opt/ccvm").resolve()
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    with (directory / "ccvm-pr6-update.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        git(root, "fetch", "origin", BRANCH)
        plan = source_plan(root, args.target)
        runtime = Runtime()
        state = runtime.preflight(root)
        validate_state(state, expected=REVISION if plan[0] == args.target else OLD_REVISION)
        if args.apply:
            apply(root, args.target, runtime, plan)
        else:
            print(f"Preflight passed: {plan[0]} -> {args.target}; use --apply to activate.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"STOPPED: {type(error).__name__}: {error}")
        raise SystemExit(1) from error
