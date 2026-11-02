#!/usr/bin/env python3
"""Install persistent Nuclei templates and retry one diagnosed failed job on Neptun."""

import argparse
import fcntl
import functools
import json
import os
import re
import socket
import subprocess
import time
import types
from pathlib import Path

VERSION = "1.0.0"
BASE = "e2a7fc16592e88b54a25313f8b6c57abe14132f9"
REVISION = "d91e6a2f4c80"
CATALOG = "/app/.scanner-data/nuclei-templates"
RETRY_MESSAGE = "Retrying Nuclei URL scan after installing persistent scan templates"
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
REQUEUE_CODE = r"""
import json
import sqlalchemy as sa
from app.database.session import engine
payload = json.loads(PAYLOAD)
with engine.begin() as connection:
    connection.execute(sa.text("SET LOCAL lock_timeout = '3s'"))
    connection.execute(sa.text("SET LOCAL statement_timeout = '10s'"))
    if connection.scalar(sa.text("SELECT version_num FROM alembic_version")) != REVISION:
        raise RuntimeError('Unexpected schema; no job was changed')
    table = sa.Table('jobs', sa.MetaData(), autoload_with=connection)
    rows = [dict(row._mapping) for row in connection.execute(
        sa.select(table).where(table.c.pipeline_id == payload['pipeline_id'])
        .order_by(table.c.id).with_for_update(nowait=True))]
    if rows != payload['jobs']:
        raise RuntimeError('Pipeline changed since backup; no job was changed')
    if connection.scalar(sa.select(sa.func.count()).select_from(table).where(
        table.c.status.in_(['queued', 'running']))):
        raise RuntimeError('Other active work appeared; no job was changed')
    result = connection.execute(table.update().where(
        table.c.id == payload['job_id'], table.c.uuid == payload['job_uuid'],
        table.c.plugin == 'nucleiurl', table.c.status == 'failed', table.c.progress == 100
    ).values(status='queued', progress=0, message=RETRY_MESSAGE, worker=None))
    if result.rowcount != 1:
        raise RuntimeError('Selected Nuclei job changed; transaction rolled back')
print(json.dumps({'requeued': payload['job_id'], 'pipeline_id': payload['pipeline_id']}))
"""


def selected_pipeline(state, selection):
    selected = next((row for row in state["jobs"] if row["id"] == selection[0]), None)
    if not selected or selected["uuid"] != selection[1]:
        raise RuntimeError("Selected job identity does not match")
    if (
        selected["plugin"] != "nucleiurl"
        or selected["status"] != "failed"
        or selected["progress"] != 100
        or not selected["pipeline_id"]
        or "no templates provided for scan" not in (selected["message"] or "")
    ):
        raise RuntimeError("Selected job is not the diagnosed missing-template failure")
    rows = [row for row in state["jobs"] if row["pipeline_id"] == selected["pipeline_id"]]
    if [row["plugin"] for row in rows] != list(STAGES) or rows[9]["id"] != selection[0]:
        raise RuntimeError("Unexpected discovery pipeline topology")
    for index, row in enumerate(rows):
        if (
            row["parent_job_id"] != (rows[index - 1]["id"] if index else None)
            or row["domain_id"] != selected["domain_id"]
            or not row["domain_id"]
        ):
            raise RuntimeError("Pipeline dependencies or domain changed")
        if index < 9 and (row["status"] != "finished" or row["progress"] != 100):
            raise RuntimeError("All earlier stages must already be finished")
    if state["active"]:
        raise RuntimeError("Other queued or running work exists; retry refused")
    return rows


def validate_state(state, *, schema_validator, selection, expected=None):
    schema_validator(state, expected=expected)
    selected_pipeline(state, selection)


def requeue_source(rows, selection):
    payload = {
        "job_id": selection[0],
        "job_uuid": selection[1],
        "jobs": rows,
        "pipeline_id": rows[9]["pipeline_id"],
    }
    return (
        f"PAYLOAD = {json.dumps(payload)!r}\nREVISION = {REVISION!r}\n"
        f"RETRY_MESSAGE = {RETRY_MESSAGE!r}\n" + REQUEUE_CODE
    )


def install_templates(root, runtime, backup):
    settings = dict(
        item.split("=", 1) for item in runtime.worker_info["Config"].get("Env", []) if "=" in item
    )
    if settings.get("NUCLEI_TEMPLATES_DIR", CATALOG) != CATALOG:
        raise RuntimeError("Worker has a different explicit template directory; preserved")
    cache = root / "backend" / ".scanner-data"
    if cache.is_symlink() or (cache.exists() and not cache.is_dir()):
        raise RuntimeError("Unexpected scanner data path; preserved")
    cache.mkdir(mode=0o700, exist_ok=True)
    # Overlay only this cache as writable. Application source stays read-only
    # in the proven same-image helper while the real worker remains paused.
    index = runtime.maintenance_args.index("--workdir")
    runtime.maintenance_args[index:index] = [
        "--mount",
        f"type=bind,src={cache},dst=/app/.scanner-data",
    ]
    result = runtime.maintenance_python("""
import json
from app.plugins.nuclei_templates import prepare_templates, yaml_count, selected_template_count
from app.plugins.nucleiurl import NUCLEI_TAGS, NUCLEI_SEVERITIES
directory = prepare_templates()
loaded = selected_template_count(directory, NUCLEI_TAGS, NUCLEI_SEVERITIES)
print(json.dumps({'directory': str(directory), 'yaml_files': yaml_count(directory),
                  'selected_templates': loaded}))
""")
    status = json.loads(result)
    (backup / "templates.json").write_text(json.dumps(status, indent=2))
    print(
        f"Templates ready: {status['yaml_files']} YAML files; "
        f"{status['selected_templates']} selected by the real Nuclei engine.",
        flush=True,
    )


def verify(runtime, module, root, target, selection, *, ready_api):
    request = ready_api(runtime, selection)
    if module.git(root, "rev-parse", "HEAD") != target:
        raise RuntimeError("Final Git verification failed")
    for _ in range(45):
        job = request(8088, f"/api/v1/jobs/{selection[0]}")
        if job["uuid"] != selection[1]:
            raise RuntimeError("Selected job identity changed")
        if job["status"] in {"failed", "skipped", "cancelled"}:
            raise RuntimeError(f"Nuclei job ended {job['status']}: {job.get('message')}")
        if job["status"] == "finished" or (job["status"] == "running" and job["progress"] >= 10):
            print(f"VERIFIED: Neptun Git and persistent Nuclei templates at {target}", flush=True)
            print(
                f"Job {job['id']} nucleiurl: {job['status']} {job['progress']}% — "
                f"{job.get('message') or ''}",
                flush=True,
            )
            return
        time.sleep(2)
    raise RuntimeError("Selected Nuclei job did not start within 90s; no duplicate retry")


def load_operator(root, target, selection):
    source = subprocess.check_output(
        ["git", "-C", str(root), "show", f"{target}:scripts/update-header-findings.py"], timeout=15
    )
    header = types.ModuleType("ccvm_staged_pipeline_maintenance")
    exec(compile(source, "<reviewed-staged-pipeline-maintenance>", "exec"), header.__dict__)
    header.BASE, header.OLD_REVISION = BASE, REVISION
    module = header.load_maintenance(root, None)
    header.selected_pipeline = selected_pipeline
    header.validate_state = functools.partial(
        validate_state, schema_validator=header.validate_schema
    )
    header.requeue_source = requeue_source
    header.verify = functools.partial(verify, ready_api=header.ready_api)
    module.validate_state = functools.partial(header.validate_state, selection=selection)
    return header, module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != "neptun":
        raise RuntimeError("This command is restricted to Neptun")
    if not re.fullmatch(r"[0-9a-f]{40}", args.target):
        raise RuntimeError("Use the full reviewed deployment commit SHA")
    root = Path("/opt/ccvm").resolve()
    header, module = load_operator(root, args.target, None)
    selection = header.parse_job(args.job)
    module.validate_state = functools.partial(header.validate_state, selection=selection)
    directory = Path(module.git(root, "rev-parse", "--absolute-git-dir"))
    with (directory / "ccvm-pr6-update.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        module.git(root, "fetch", "origin", module.BRANCH)
        plan = module.source_plan(root, args.target)
        runtime = module.Runtime()
        print(f"CCVM Nuclei templates updater {VERSION}; reviewed target {args.target}", flush=True)
        if args.apply:
            header.apply(
                root,
                args.target,
                selection,
                module,
                runtime,
                plan,
                journal_name="ccvm-nuclei-templates-retry.json",
                backup_prefix="ccvm-nuclei-templates-before-",
                install_runtime=functools.partial(install_templates, root),
            )
        else:
            header.validate_state(runtime.preflight(root), selection=selection, expected=REVISION)
            print("Preflight passed; --apply installs templates and retries only the selected job.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"STOPPED: {type(error).__name__}: {error}", flush=True)
        raise SystemExit(1) from error
