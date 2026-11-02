#!/usr/bin/env python3
"""Preserve long finding URLs and resume one diagnosed HeaderFindings pipeline.

Read-only preflight unless --apply is supplied. Requires the reviewed deployment
commit and JOB_ID:UUID. No new pipeline is created. Existing scan data, job IDs,
dependencies and private configuration are retained.
"""

import argparse
import fcntl
import functools
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import textwrap
import time
import types
import uuid
from pathlib import Path
from urllib.error import HTTPError

VERSION = "1.0.0"
BASE = "47866568efe70538034c1a1611b8fdf80430e2ad"
OLD_REVISION = "bc64c6f0e217"
REVISION = "d91e6a2f4c80"
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
RETRY_MESSAGE = "Retrying HeaderFindings after preserving complete finding URLs"

# Extend the proven read-only fingerprint snapshot without changing its query
# isolation or emitting either credentials or row contents to the console.
STATE_EXTENSION = r"""
snapshot = json.loads(snapshot_output.getvalue())
with engine.connect() as connection:
    connection.execute(sa.text("SET TRANSACTION READ ONLY"))
    connection.execute(sa.text("SET LOCAL statement_timeout = '10s'"))
    snapshot['jobs'] = [dict(row._mapping) for row in connection.execute(sa.text(
        "SELECT * FROM jobs ORDER BY id"))]
    snapshot['matched_at_type'] = connection.scalar(sa.text(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='findings' AND column_name='matched_at'"))
    snapshot['transactions'] = [dict(row._mapping) for row in connection.execute(sa.text(
        "SELECT pid, state, wait_event_type, wait_event FROM pg_stat_activity "
        "WHERE datname=current_database() AND pid<>pg_backend_pid() "
        "AND backend_type='client backend' AND xact_start IS NOT NULL"))]
print(json.dumps(snapshot))
"""

REQUEUE_CODE = r"""
import json
import sqlalchemy as sa
from app.database.session import engine
payload = json.loads(PAYLOAD)
with engine.begin() as connection:
    connection.execute(sa.text("SET LOCAL lock_timeout = '3s'"))
    connection.execute(sa.text("SET LOCAL statement_timeout = '10s'"))
    if connection.scalar(sa.text("SELECT version_num FROM alembic_version")) != REVISION:
        raise RuntimeError('Finding URL migration is not installed')
    table = sa.Table('jobs', sa.MetaData(), autoload_with=connection)
    rows = [dict(row._mapping) for row in connection.execute(
        sa.select(table).where(table.c.pipeline_id == payload['pipeline_id'])
        .order_by(table.c.id).with_for_update(nowait=True))]
    if rows != payload['jobs']:
        raise RuntimeError('Pipeline changed since backup; no job was changed')
    active = set(connection.scalars(sa.select(table.c.id).where(
        table.c.status.in_(['queued', 'running']))))
    if active != set(payload['active_ids']):
        raise RuntimeError('Other active work appeared; no job was changed')
    result = connection.execute(table.update().where(
        table.c.id == payload['job_id'], table.c.uuid == payload['job_uuid'],
        table.c.plugin == 'headerfindings', table.c.status == 'running',
        table.c.progress == 10
    ).values(status='queued', progress=0, message=RETRY_MESSAGE, worker=None))
    if result.rowcount != 1:
        raise RuntimeError('Selected HeaderFindings job changed; transaction rolled back')
print(json.dumps({'requeued': payload['job_id'], 'pipeline_id': payload['pipeline_id']}))
"""


def parse_job(value):
    try:
        identifier, identity = value.split(":", 1)
        identifier = int(identifier)
        if identifier <= 0:
            raise ValueError
        return identifier, str(uuid.UUID(identity))
    except (ValueError, AttributeError) as error:
        raise argparse.ArgumentTypeError("Use JOB_ID:FULL_JOB_UUID") from error


def validate_schema(state, *, expected=None):
    if state["revision"] not in {OLD_REVISION, REVISION}:
        raise RuntimeError("Unexpected database revision")
    if expected and state["revision"] != expected:
        raise RuntimeError("Code and database revision do not match")
    expected_type = "text" if state["revision"] == REVISION else "character varying"
    if state["matched_at_type"] != expected_type:
        raise RuntimeError("Finding URL column does not match the expected schema")
    indexes = {row["name"]: row for row in state["indexes"]}
    index = indexes.get("uq_urls_domain_url_sha256", {})
    if (
        not index.get("unique")
        or not index.get("valid")
        or "sha256(" not in index.get("definition", "")
        or "uq_urls_domain_url" in indexes
    ):
        raise RuntimeError("The existing SHA-256 URL identity index must remain valid")


def selected_pipeline(state, selection):
    identifier, identity = selection
    selected = next((row for row in state["jobs"] if row["id"] == identifier), None)
    if not selected or selected["uuid"] != identity:
        raise RuntimeError("Selected job identity does not match")
    if (
        selected["plugin"] != "headerfindings"
        or selected["status"] != "running"
        or selected["progress"] != 10
        or selected["worker"] != "ccvm-worker-01"
        or not (selected["message"] or "").startswith("Correlating security headers for ")
        or not selected["pipeline_id"]
        or not selected["domain_id"]
    ):
        raise RuntimeError("Selected job is not the diagnosed interrupted HeaderFindings step")
    rows = [row for row in state["jobs"] if row["pipeline_id"] == selected["pipeline_id"]]
    if [row["plugin"] for row in rows] != list(STAGES) or rows[7]["id"] != identifier:
        raise RuntimeError("Unexpected discovery pipeline topology")
    for index, row in enumerate(rows):
        parent = rows[index - 1]["id"] if index else None
        if row["parent_job_id"] != parent or row["domain_id"] != selected["domain_id"]:
            raise RuntimeError("Pipeline dependencies or domain changed")
        if index < 7 and (row["status"] != "finished" or row["progress"] != 100):
            raise RuntimeError("Earlier discovery stages must already be finished")
        if index > 7 and (
            row["status"] != "queued" or row["progress"] != 0 or row["worker"] is not None
        ):
            raise RuntimeError("Downstream stages are no longer waiting untouched")
    if {row["id"] for row in state["active"]} != {row["id"] for row in rows[7:]}:
        raise RuntimeError("Other queued or running work exists; recovery refused")
    return rows


def validate_state(state, *, selection, expected=None):
    validate_schema(state, expected=expected)
    selected_pipeline(state, selection)


def configure_maintenance(module, selection=None):
    """Adapt an isolated copy of the already reviewed Docker/Git maintenance code."""
    module.BASE, module.OLD_REVISION, module.REVISION = BASE, OLD_REVISION, REVISION
    module.STATE_CODE = (
        "import contextlib, io\nsnapshot_output = io.StringIO()\n"
        "with contextlib.redirect_stdout(snapshot_output):\n"
        + textwrap.indent(module.STATE_CODE, "    ")
        + STATE_EXTENSION
    )
    module.validate_state = (
        functools.partial(validate_state, selection=selection) if selection else validate_schema
    )
    return module


def load_maintenance(root, selection):
    # Load the immutable, reviewed historical source from Git, never a locally
    # modified working-tree Python module. This also supports `git show | python -`.
    source = subprocess.check_output(
        ["git", "-C", str(root), "show", f"{BASE}:scripts/update-url-index.py"], timeout=15
    )
    module = types.ModuleType("ccvm_finding_url_maintenance")
    exec(compile(source, "<reviewed-ccvm-maintenance>", "exec"), module.__dict__)
    return configure_maintenance(module, selection)


def write_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(value, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def freeze_idle(runtime):
    for _ in range(5):
        runtime.freeze()
        state = runtime.state()
        if not state["transactions"]:
            return state
        runtime.resume()
        time.sleep(0.3)
    raise RuntimeError("Database transactions remained open; no job was changed")


def requeue_source(rows, selection):
    payload = {
        "job_id": selection[0],
        "job_uuid": selection[1],
        "jobs": rows,
        "pipeline_id": rows[7]["pipeline_id"],
        "active_ids": [row["id"] for row in rows[7:]],
    }
    return (
        f"PAYLOAD = {json.dumps(payload)!r}\nREVISION = {REVISION!r}\n"
        f"RETRY_MESSAGE = {RETRY_MESSAGE!r}\n" + REQUEUE_CODE
    )


def ready_api(runtime, selection):
    def request(port, path):
        with runtime.opener.open(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
            return json.load(response)

    for _ in range(30):
        try:
            if request(8088, "/health").get("status") == "ok":
                break
        except (OSError, ValueError):
            pass
        time.sleep(2)
    else:
        raise RuntimeError("Backend health did not recover; retain the operator backup")
    path = f"/api/v1/jobs/{selection[0]}"
    request(8088, path)
    reloaded = False
    for _ in range(15):
        try:
            request(8090, path)
            break
        except HTTPError as error:
            if error.code not in {502, 503, 504}:
                raise
            if not reloaded:
                runtime.docker("exec", "ccvm-frontend", "nginx", "-t")
                runtime.docker("exec", "ccvm-frontend", "nginx", "-s", "reload")
                reloaded = True
        except OSError:
            pass
        time.sleep(2)
    else:
        raise RuntimeError("Frontend API proxy did not recover")
    return request


def verify(runtime, module, root, target, selection):
    request = ready_api(runtime, selection)
    path = f"/api/v1/jobs/{selection[0]}"
    for _ in range(45):
        job = request(8088, path)
        if job["uuid"] != selection[1]:
            raise RuntimeError("Selected job identity changed")
        if job["status"] == "finished" and job["progress"] == 100:
            if module.git(root, "rev-parse", "HEAD") != target:
                raise RuntimeError("Final Git verification failed")
            print(f"VERIFIED: HeaderFindings job {selection[0]} finished at {target}", flush=True)
            rows = request(8088, f"/api/v1/jobs?pipeline_id={job['pipeline_id']}")
            for row in sorted(rows, key=lambda item: item["id"]):
                if row["plugin"] in STAGES[7:]:
                    print(
                        f"Job {row['id']} {row['plugin']}: {row['status']} "
                        f"{row['progress']}% — {row.get('message') or ''}",
                        flush=True,
                    )
            return
        if job["status"] in {"failed", "skipped", "cancelled"}:
            raise RuntimeError(f"HeaderFindings ended {job['status']}: {job.get('message')}")
        time.sleep(2)
    raise RuntimeError("HeaderFindings did not finish within 90s; job retained, no duplicate retry")


def apply(
    root,
    target,
    selection,
    module,
    runtime,
    plan,
    *,
    journal_name="ccvm-header-findings-resume.json",
    backup_prefix="ccvm-header-findings-before-",
    install_runtime=None,
):
    before, changes = plan
    directory = Path(module.git(root, "rev-parse", "--absolute-git-dir"))
    marker = directory / journal_name
    if marker.exists():
        previous = json.loads(marker.read_text())
        if previous["target"] != target or previous["selection"] != list(selection):
            raise RuntimeError("A different HeaderFindings recovery journal exists")
        if previous["phase"] in {"requeue-intent", "resumed"}:
            if before != target:
                raise RuntimeError("Recovery journal does not match installed source")
            verify(runtime, module, root, target, selection)
            return
    initial = runtime.preflight(root)
    expected = REVISION if before == target else OLD_REVISION
    validate_state(initial, selection=selection, expected=expected)
    backup = Path(tempfile.mkdtemp(prefix=backup_prefix, dir=directory))
    for name in module.CONFIGS:
        path = root / name
        if path.is_file():
            saved = backup / "config" / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, saved)
    operation = {
        "before": before,
        "target": target,
        "selection": selection,
        "backup": str(backup),
        "phase": "prepared",
    }
    write_json(backup / "operation.json", operation)
    print(f"Private backup: {backup}", flush=True)
    runtime.prepare_maintenance(backup)
    api_stopped = frozen = mutated = intent = False
    coherent = True
    snapshot = None
    try:
        api_stopped = True
        runtime.docker("stop", "--time", "20", "ccvm-backend")
        frozen = True
        snapshot = freeze_idle(runtime)
        validate_state(snapshot, selection=selection, expected=expected)
        rows = selected_pipeline(snapshot, selection)
        write_json(backup / "before.json", snapshot)
        runtime.database_backup(backup / "database.dump")
        if module.source_plan(root, target) != plan:
            raise RuntimeError("Git changed during backup")
        if before != target:
            mutated = True
            module.git(root, "merge", "--ff-only", target)
        if install_runtime is not None:
            install_runtime(runtime, backup)
        elif before != target:
            runtime.migrate()
        after = runtime.state()
        write_json(backup / "after-migration.json", after)
        validate_state(after, selection=selection, expected=REVISION)
        if after["tables"] != snapshot["tables"]:
            coherent = False
            raise RuntimeError("Existing database row fingerprints changed")
        for saved in (backup / "config").rglob("*"):
            if (
                saved.is_file()
                and saved.read_bytes() != (root / saved.relative_to(backup / "config")).read_bytes()
            ):
                coherent = False
                raise RuntimeError("Private configuration changed")
        # The selected row remains running, so it and its children cannot be
        # claimed while the existing worker reloads the corrected source.
        runtime.resume()
        started = json.loads(
            runtime.docker("inspect", "--format", "{{json .State}}", "ccvm-worker")
        )["StartedAt"]
        try:
            runtime.docker("restart", "--time", "20", "ccvm-worker")
        except BaseException:
            coherent = False
            raise
        restarted = json.loads(
            runtime.docker("inspect", "--format", "{{json .State}}", "ccvm-worker")
        )
        if not restarted["Running"] or restarted["StartedAt"] == started:
            coherent = False
            raise RuntimeError("Worker reload was not confirmed")
        current = freeze_idle(runtime)
        validate_state(current, selection=selection, expected=REVISION)
        if current["tables"] != after["tables"]:
            coherent = False
            raise RuntimeError("Database rows changed before the selected retry")
        operation["phase"] = "requeue-intent"
        write_json(marker, operation)
        intent = True
        result = json.loads(runtime.maintenance_python(requeue_source(rows, selection)))
        write_json(backup / "requeue-result.json", result)
        operation["phase"] = "resumed"
        write_json(marker, operation)
    except BaseException:
        if mutated and coherent:
            try:
                current = runtime.state()
                if current["revision"] == OLD_REVISION and not intent:
                    if module.git(root, "rev-parse", "HEAD") != target:
                        raise RuntimeError("Concurrent Git change; rollback refused")
                    module.git(root, "diff", "--exit-code", "--", *changes)
                    module.git(
                        root,
                        "restore",
                        "--source",
                        before,
                        "--staged",
                        "--worktree",
                        "--",
                        *changes,
                    )
                    module.git(root, "update-ref", "HEAD", before, target)
                else:
                    validate_schema(current, expected=REVISION)
                    if snapshot and any(
                        value != current["tables"].get(name)
                        for name, value in snapshot["tables"].items()
                        if not (intent and name == "jobs")
                    ):
                        raise RuntimeError("Database fingerprints changed unexpectedly")
            except BaseException:
                coherent = False
        print(f"Update stopped; retain backup: {backup}", flush=True)
        raise
    finally:
        if coherent:
            if frozen:
                runtime.resume()
            if api_stopped:
                runtime.docker("start", "ccvm-backend")
        else:
            try:
                runtime.freeze()
            except Exception as error:
                print(f"Worker pause could not be confirmed: {error}", flush=True)
            print("API remains stopped; inspect the retained backup before continuing.", flush=True)
    verify(runtime, module, root, target, selection)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--job", required=True, type=parse_job)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != "neptun":
        raise RuntimeError("This command is restricted to Neptun")
    if not re.fullmatch(r"[0-9a-f]{40}", args.target):
        raise RuntimeError("Use the full reviewed deployment commit SHA")
    root = Path("/opt/ccvm").resolve()
    module = load_maintenance(root, args.job)
    directory = Path(module.git(root, "rev-parse", "--absolute-git-dir"))
    with (directory / "ccvm-pr6-update.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        module.git(root, "fetch", "origin", module.BRANCH)
        plan = module.source_plan(root, args.target)
        runtime = module.Runtime()
        print(f"CCVM finding URL updater {VERSION}; reviewed target {args.target}", flush=True)
        if args.apply:
            apply(root, args.target, args.job, module, runtime, plan)
        else:
            state = runtime.preflight(root)
            validate_state(
                state,
                selection=args.job,
                expected=REVISION if plan[0] == args.target else OLD_REVISION,
            )
            print("Preflight passed; --apply preserves scan data and resumes the selected job.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"STOPPED: {type(error).__name__}: {error}", flush=True)
        raise SystemExit(1) from error
