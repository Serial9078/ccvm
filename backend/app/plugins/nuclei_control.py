"""Narrow operator control for replacing one active two-hour Nuclei attempt.

This is never called by the public API or normal worker. The pinned deployment
operator supplies the backed-up pipeline snapshot and executes this source in
the existing worker's PID namespace. Database operations here are read-only.
"""

import hashlib
import json
import os
import re
import signal
import time
from pathlib import Path

import sqlalchemy as sa

from app.database.session import engine
from app.plugins.nuclei_templates import DEFAULT_DIRECTORY
from app.plugins.nucleiurl import write_diagnostic

RUNNING_MESSAGE = re.compile(
    r"Nuclei URL scan running\. Targets: \d+\. Elapsed: \d+s\. "
    r"Limit: 7200s\. Requests: \d+/\d+\. Results: \d+"
)


def snapshot(pipeline_id):
    with engine.connect() as connection:
        connection.exec_driver_sql("SET TRANSACTION READ ONLY")
        connection.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
        jobs = [
            dict(row)
            for row in connection.execute(
                sa.text("SELECT * FROM jobs WHERE pipeline_id = :pipeline ORDER BY id"),
                {"pipeline": pipeline_id},
            ).mappings()
        ]
        active = list(
            connection.execute(
                sa.text("SELECT id FROM jobs WHERE status IN ('queued', 'running') ORDER BY id")
            ).scalars()
        )
    return jobs, active


def verify_running(rows, active, expected):
    if len(rows) != 10 or len(expected) != 10 or rows[:9] != expected[:9]:
        raise RuntimeError("Completed pipeline stages changed; scanner preserved")
    row, previous = rows[9], expected[9]
    mutable = {"status", "progress", "message"}
    if (
        {k: v for k, v in row.items() if k not in mutable}
        != {k: v for k, v in previous.items() if k not in mutable}
        or row["plugin"] != "nucleiurl"
        or row["worker"] != "ccvm-worker-01"
        or row["status"] != "running"
        or not 10 <= row["progress"] < 100
        or not RUNNING_MESSAGE.fullmatch(row.get("message") or "")
        or active != [row["id"]]
    ):
        raise RuntimeError("Selected scan or other active work changed; scanner preserved")
    return row


def process_info(path):
    argv = (path / "cmdline").read_bytes().decode().rstrip("\0").split("\0")
    fields = (path / "stat").read_text().rsplit(") ", 1)[1].split()
    return {"pid": int(path.name), "argv": argv, "parent": int(fields[1]), "start": fields[19]}


def inspect_scan(row, root, *, proc=Path("/proc")):
    candidates = []
    for path in proc.iterdir():
        if not path.name.isdecimal():
            continue
        try:
            info = process_info(path)
        except (OSError, ValueError, IndexError):
            continue
        if Path(info["argv"][0]).name == "nuclei":
            candidates.append(info)
    if len(candidates) != 1 or candidates[0]["parent"] != 1:
        raise RuntimeError("Expected exactly one Nuclei child of the worker; scanner preserved")
    info = candidates[0]
    argv = info["argv"]
    try:
        target = Path(argv[argv.index("-l") + 1])
    except (ValueError, IndexError) as error:
        raise RuntimeError("Scanner has no expected target file") from error
    directory = target.parent
    if (
        target.name != "targets.txt"
        or directory.parent != root
        or directory.resolve().parent != root.resolve()
        or not directory.name.startswith(f"job-{row['id']}-")
    ):
        raise RuntimeError("Scanner target file is outside the selected private attempt")
    expected = [
        "nuclei",
        "-t",
        str(DEFAULT_DIRECTORY),
        "-update-template-dir",
        str(DEFAULT_DIRECTORY),
        "-l",
        str(target),
        "-jsonl",
        "-o",
        str(directory / "results.jsonl"),
        "-no-color",
        "-no-stdin",
        "-severity",
        "info,low,medium,high,critical",
        "-tags",
        "http,ssl,misconfig,exposure,panel,tech,default-login,cve",
        "-scan-strategy",
        "host-spray",
        "-timeout",
        "10",
        "-retries",
        "0",
        "-rate-limit",
        "30",
        "-bulk-size",
        "10",
        "-concurrency",
        "5",
        "-headless-concurrency",
        "1",
        "-no-interactsh",
        "-disable-redirects",
        "-disable-update-check",
        "-stats",
        "-stats-json",
        "-stats-interval",
        "5",
    ]
    if argv != expected:
        raise RuntimeError("Nuclei command differs from the diagnosed scan; scanner preserved")
    identity = json.loads((directory / "identity.json").read_text())
    progress = json.loads((directory / "progress.json").read_text())
    if (
        identity != {"job_id": row["id"], "uuid": row["uuid"]}
        or progress.get("timeout_seconds") != 7200
        or not 0 <= progress.get("elapsed_seconds", 7200) < 7000
        or time.time() - (directory / "progress.json").stat().st_mtime > 20
    ):
        raise RuntimeError("Attempt identity or live execution budget changed; scanner preserved")
    info["targets_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    return info, directory


def interrupt_two_hour_scan(expected, *, proc=Path("/proc"), wait_seconds=90):
    root = Path(
        os.environ.get("CCVM_NUCLEI_LOG_DIR", str(DEFAULT_DIRECTORY.parent / "nuclei-runs"))
    )
    rows, active = snapshot(expected[9]["pipeline_id"])
    row = rows[9] if len(rows) == 10 else None
    if row and any(row[key] != expected[9][key] for key in ("id", "uuid", "pipeline_id")):
        raise RuntimeError("Selected job identity changed; scanner preserved")
    if row and row["status"] == "finished" and not active and rows[:9] == expected[:9]:
        return {"phase": "finished", "job": row}
    # A lost response after graceful interruption must not signal again or turn
    # an unrelated failed scan into a retry. The exact terminal row is journaled.
    if row and row["status"] == "failed" and not active and rows[:9] == expected[:9]:
        for path in root.glob(f"job-{row['id']}-*/budget-interruption.json"):
            record = json.loads(path.read_text())
            if record.get("phase") == "stopped" and record.get("job") == row:
                return record
        raise RuntimeError("No matching graceful-interruption record; failed job preserved")
    row = verify_running(rows, active, expected)
    info, directory = inspect_scan(row, root, proc=proc)
    marker = directory / "budget-interruption.json"
    record = {
        "phase": "intent",
        "job_id": row["id"],
        "uuid": row["uuid"],
        "process": info,
        "before": dict(row),
    }
    if marker.exists():
        previous = json.loads(marker.read_text())
        if previous.get("phase") == "sent" and previous.get("process") == info:
            record = previous
        else:
            raise RuntimeError("An existing interruption record needs inspection")
    else:
        descriptor = os.pidfd_open(info["pid"])
        try:
            # Recheck after opening the PID handle, including the live database.
            current, current_directory = inspect_scan(row, root, proc=proc)
            verify_running(*snapshot(row["pipeline_id"]), expected)
            if current != info or current_directory != directory:
                raise RuntimeError("Scanner process changed; no signal sent")
            write_diagnostic(marker, record)
            signal.pidfd_send_signal(descriptor, signal.SIGINT)
            record["phase"] = "sent"
            write_diagnostic(marker, record)
        finally:
            os.close(descriptor)
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        rows, active = snapshot(row["pipeline_id"])
        if len(rows) != 10 or rows[:9] != expected[:9]:
            raise RuntimeError("Completed stages changed during scanner shutdown")
        terminal = rows[9]
        if terminal["status"] == "finished":
            return {"phase": "finished", "job": terminal}
        if terminal["status"] == "failed":
            if (
                active
                or terminal["progress"] != 100
                or not (terminal.get("message") or "").startswith(
                    "Nuclei URL scan incomplete: exit code 1."
                )
            ):
                raise RuntimeError("Unexpected terminal scan state; inspect retained diagnostics")
            record.update(phase="stopped", job=terminal)
            write_diagnostic(marker, record)
            return record
        time.sleep(2)
    raise RuntimeError("Graceful scanner shutdown was not confirmed; no retry performed")
