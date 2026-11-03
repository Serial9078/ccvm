#!/usr/bin/env python3
"""Install the reviewed SMB coverage correction and re-evaluate one saved audit.

No scanner, migration, rebuild, or pipeline submission is performed. Operational
customer/network identities are supplied locally, never stored in repository code.
"""

import argparse
import fcntl
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
import textwrap
import time
import types
import uuid
from pathlib import Path

BASE = "5f89ed9dc225566b9613621ba1f3c0c922e8ce7a"
REVISION = "f93b70a4e628"
MARKER = "Host-scoped SMB coverage corrected from retained evidence."
VERSION = "1.0.0"
SELECTION_CODE = r"""
snapshot = json.loads(output.getvalue())
with engine.connect() as connection:
    connection.exec_driver_sql('SET TRANSACTION READ ONLY')
    connection.exec_driver_sql("SET LOCAL statement_timeout = '10s'")
    scan = connection.execute(sa.text('SELECT * FROM network_scans WHERE id=:id'),
                              {'id': SELECTION['scan_id']}).mappings().one()
    customer = connection.execute(sa.text('SELECT id, uuid FROM customers WHERE id=:id'),
                                  {'id': scan['customer_id']}).mappings().one()
    jobs = [dict(row) for row in connection.execute(sa.text(
        'SELECT * FROM jobs WHERE id IN (:first,:second) ORDER BY id'),
        {'first': scan['discovery_job_id'], 'second': scan['audit_job_id']}).mappings()]
    snapshot['selection'] = {'scan': dict(scan), 'customer': dict(customer), 'jobs': jobs}
    snapshot['transactions'] = [dict(row) for row in connection.exec_driver_sql(
        "SELECT pid FROM pg_stat_activity WHERE datname=current_database() "
        "AND pid<>pg_backend_pid() AND backend_type='client backend' AND xact_start IS NOT NULL"
    ).mappings()]
    snapshot['others'] = {}
    for name, column, excluded in (
        ('jobs', 'id', scan['audit_job_id']), ('network_observations', 'scan_id', scan['id'])
    ):
        table = sa.Table(name, sa.MetaData(), autoload_with=connection)
        digest = hashlib.sha256()
        for row in connection.execute(sa.select(table).where(table.c[column] != excluded)
                                       .order_by(table.c.id)).mappings():
            encoded = json.dumps(dict(row), sort_keys=True, default=str).encode()
            digest.update(len(encoded).to_bytes(8,'big') + encoded)
        snapshot['others'][name] = digest.hexdigest()
print(json.dumps(snapshot, default=str))
"""

REPAIR_CODE = r"""
from sqlalchemy.orm import Session
from app.models.job import Job
from app.plugins.network import saved_audit_report, correct_saved_audit
with Session(engine, autoflush=False) as db, db.begin():
    db.execute(sa.text("SET LOCAL lock_timeout = '3s'"))
    db.execute(sa.text("SET LOCAL statement_timeout = '30s'"))
    scan = dict(db.execute(sa.text('SELECT * FROM network_scans WHERE id=:id FOR UPDATE NOWAIT'),
                           {'id': EXPECTED['scan']['id']}).mappings().one())
    jobs = [dict(row) for row in db.execute(sa.text(
        'SELECT * FROM jobs WHERE id IN (:first,:second) ORDER BY id FOR UPDATE NOWAIT'),
        {'first': scan['discovery_job_id'], 'second': scan['audit_job_id']}).mappings()]
    if json.loads(json.dumps(scan, default=str)) != EXPECTED['scan'] or jobs != EXPECTED['jobs']:
        raise RuntimeError('Selected scan/jobs changed; correction rolled back')
    job = db.get(Job, scan['audit_job_id'])
    result = correct_saved_audit(db, job, saved_audit_report(db, job))
print(json.dumps(result))
"""


def validate_selection(state, selection):
    selected = state["selection"]
    scan, customer = selected["scan"], selected["customer"]
    jobs = {job["id"]: job for job in selected["jobs"]}
    first, audit = jobs[scan["discovery_job_id"]], jobs[scan["audit_job_id"]]
    if (
        scan["id"] != selection["scan_id"]
        or scan["customer_id"] != selection["customer_id"]
        or scan["target"] != selection["cidr"]
        or scan["cancel_requested"]
        or customer != {"id": selection["customer_id"], "uuid": selection["customer_uuid"]}
    ):
        raise RuntimeError("Selected scan/customer identity changed")
    if (
        first["plugin"] != "networkdiscovery"
        or first["status"] != "finished"
        or first["progress"] != 100
        or audit["plugin"] != "networkaudit"
        or audit["progress"] != 100
        or audit["parent_job_id"] != first["id"]
        or any(job["pipeline_id"] != scan["pipeline_id"] for job in (first, audit))
    ):
        raise RuntimeError("Selected pipeline is not the completed discovery/audit pair")
    if not (
        (
            audit["status"] == "failed"
            and (audit["message"] or "").startswith("Network audit failed.")
        )
        or (audit["status"] == "finished" and (audit["message"] or "").endswith(MARKER))
    ):
        raise RuntimeError("Selected audit is not the diagnosed terminal audit")


def load_maintenance(root, selection):
    source = subprocess.check_output(
        ["git", "-C", str(root), "show", f"{BASE}:scripts/update-url-index.py"], timeout=15
    )
    module = types.ModuleType("reviewed_network_audit_correction")
    exec(compile(source, "<reviewed-maintenance>", "exec"), module.__dict__)
    original_state, original_validator = module.STATE_CODE, module.validate_state
    module.BASE, module.OLD_REVISION, module.REVISION = BASE, "not-accepted", REVISION
    module.CONFIGS += ("docker-compose.network.yml", ".env", "backend/.env")
    module.SCANNERS |= {"nmap"}
    module.STATE_CODE = (
        f"SELECTION = {selection!r}\nimport contextlib, io\noutput = io.StringIO()\n"
        "with contextlib.redirect_stdout(output):\n"
        + textwrap.indent(original_state, "    ")
        + SELECTION_CODE
    )

    def validate(state, *, expected=None):
        original_validator(state, expected=REVISION)
        validate_selection(state, selection)

    module.validate_state = validate
    return module


def assert_unchanged(before, after, *, corrected=False):
    if before["identity"] != after["identity"] or before["others"] != after["others"]:
        raise RuntimeError("Database identity or unrelated rows changed")
    mutable = {"jobs", "network_observations"} if corrected else set()
    if set(before["tables"]) != set(after["tables"]) or any(
        after["tables"][name]["count"] != value["count"]
        or (name not in mutable and after["tables"][name] != value)
        for name, value in before["tables"].items()
    ):
        raise RuntimeError("Findings, inventory, counters or unrelated data changed")


def verify(runtime, expected):
    audit = next(job for job in expected["jobs"] if job["plugin"] == "networkaudit")
    for _ in range(45):
        try:
            with runtime.opener.open(
                f"http://127.0.0.1:8088/api/v1/jobs/{audit['id']}", timeout=5
            ) as response:
                row = json.load(response)
            if (
                row["uuid"] != audit["uuid"]
                or row["status"] != "finished"
                or not row["message"].endswith(MARKER)
            ):
                raise RuntimeError("Audit API did not confirm the selected correction")
            print(
                f"VERIFIED: Job {row['id']} {row['status']} {row['progress']}% — {row['message']}",
                flush=True,
            )
            return
        except (OSError, ValueError):
            time.sleep(2)
    raise RuntimeError("API did not recover; the original backup is retained")


def apply(module, runtime, root, target, plan, selection):
    initial = runtime.preflight(root)
    module.validate_state(initial)
    audit = next(job for job in initial["selection"]["jobs"] if job["plugin"] == "networkaudit")
    if audit["status"] == "finished" and plan[0] == target:
        verify(runtime, initial["selection"])
        return
    git_dir = Path(module.git(root, "rev-parse", "--absolute-git-dir"))
    backup = Path(tempfile.mkdtemp(prefix="ccvm-smb-coverage-before-", dir=git_dir))
    captured = {
        name: (root / name).read_bytes() if (root / name).is_file() else None
        for name in module.CONFIGS
    }
    for name, content in captured.items():
        if content is not None:
            path = backup / "config" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    (backup / "operation.json").write_text(json.dumps({"target": target, "selection": selection}))
    print(f"Private backup: {backup}", flush=True)
    runtime.prepare_maintenance(backup)
    additions = ["--env", "CCVM_NETWORK_ALLOWED_CIDRS=" + selection["cidr"]]
    env = dict(
        item.split("=", 1) for item in runtime.worker_info["Config"].get("Env", []) if "=" in item
    )
    if env.get("CCVM_NETWORK_LOG_DIR"):
        additions += ["--env", "CCVM_NETWORK_LOG_DIR=" + env["CCVM_NETWORK_LOG_DIR"]]
    index = runtime.maintenance_args.index("--workdir")
    runtime.maintenance_args[index:index] = additions
    stopped = frozen = changed = False
    coherent = True
    before = None
    try:
        stopped = True
        runtime.docker("stop", "--time", "20", "ccvm-backend")
        for _ in range(5):
            frozen = True
            runtime.freeze()
            before = runtime.state()
            if not before.get("transactions"):
                break
            runtime.resume()
            frozen = False
            time.sleep(0.3)
        else:
            raise RuntimeError("Open transactions remained; no audit was changed")
        module.validate_state(before)
        if before["selection"] != initial["selection"]:
            raise RuntimeError("Selected audit changed before its backup")
        (backup / "before.json").write_text(json.dumps(before, indent=2))
        runtime.database_backup(backup / "database.dump")
        if module.source_plan(root, target) != plan:
            raise RuntimeError("Git changed during backup")
        if plan[0] != target:
            changed = True
            module.git(root, "merge", "--ff-only", target)
        assert_unchanged(before, runtime.state())
        code = (
            f'EXPECTED = {before["selection"]!r}\n'
            "import json, sqlalchemy as sa\nfrom app.database.session import engine\n" + REPAIR_CODE
        )
        result = json.loads(runtime.maintenance_python(code))
        after = runtime.state()
        module.validate_state(after)
        assert_unchanged(before, after, corrected=True)
        (backup / "after.json").write_text(json.dumps(after, indent=2))
        (backup / "result.json").write_text(json.dumps(result, indent=2))
        if captured != {
            name: (root / name).read_bytes() if (root / name).is_file() else None
            for name in module.CONFIGS
        }:
            raise RuntimeError("Private configuration changed")
    except BaseException:
        if before is not None:
            try:
                current = runtime.state()
                audit = next(
                    job for job in current["selection"]["jobs"] if job["plugin"] == "networkaudit"
                )
                corrected = audit["status"] == "finished" and (audit["message"] or "").endswith(
                    MARKER
                )
                module.validate_state(current)
                assert_unchanged(before, current, corrected=corrected)
            except BaseException:
                coherent = False
        raise
    finally:
        if coherent:
            if frozen:
                runtime.resume()
            if changed:
                started = json.loads(
                    runtime.docker("inspect", "--format", "{{json .State}}", "ccvm-worker")
                )["StartedAt"]
                runtime.docker("restart", "--time", "20", "ccvm-worker")
                info = json.loads(
                    runtime.docker("inspect", "--format", "{{json .State}}", "ccvm-worker")
                )
                if not info["Running"] or info["StartedAt"] == started:
                    raise RuntimeError("Worker reload not confirmed; API remains stopped")
            if stopped:
                runtime.docker("start", "ccvm-backend")
        else:
            print(
                f"Unexpected data change; API stopped and worker paused. Retain {backup}",
                flush=True,
            )
    verify(runtime, before["selection"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--scan-id", required=True, type=int)
    parser.add_argument("--customer-id", required=True, type=int)
    parser.add_argument("--customer-uuid", required=True)
    parser.add_argument("--cidr", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != "neptun":
        raise RuntimeError("This operation is restricted to Neptun")
    if args.scan_id <= 0 or args.customer_id <= 0:
        raise ValueError("Use positive scan and customer identifiers")
    selection = {
        "scan_id": args.scan_id,
        "customer_id": args.customer_id,
        "customer_uuid": str(uuid.UUID(args.customer_uuid)),
        "cidr": str(ipaddress.ip_network(args.cidr, strict=True)),
    }
    root = Path("/opt/ccvm").resolve()
    module = load_maintenance(root, selection)
    directory = Path(module.git(root, "rev-parse", "--absolute-git-dir"))
    with (directory / "ccvm-network-audit-correction.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan = module.source_plan(root, args.target)
        runtime = module.Runtime()
        print(
            f"CCVM saved SMB audit correction {VERSION}; reviewed target {args.target}", flush=True
        )
        if args.apply:
            apply(module, runtime, root, args.target, plan, selection)
        else:
            module.validate_state(runtime.preflight(root))
            print("Read-only preflight passed; use --apply for the selected saved audit")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"STOPPED: {type(error).__name__}: {error}", flush=True)
        raise SystemExit(1) from error
