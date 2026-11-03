"""Fixed read-only collector sent over SSH stdin; also executed by native CI.

No API-supplied code or shell commands are accepted. Python 3 is required on the
target. Package versions are evidence only; no banner-based CVEs are inferred.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time

MAX_ROWS = 10000
MAX_BYTES = 3 * 1024 * 1024


def packages():
    if shutil.which("dpkg-query"):
        manager = "dpkg"
        command = [
            "dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n",
        ]
    elif shutil.which("rpm"):
        manager = "rpm"
        command = [
            "rpm",
            "-qa",
            "--qf",
            "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n",
        ]
    else:
        return {"status": "unavailable", "source": "none", "items": []}
    # Keep a slow or unexpectedly large package database bounded on the target.
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 45
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline or os.fstat(output.fileno()).st_size > MAX_BYTES:
                    process.kill()
                    process.wait(timeout=5)
                    return {"status": "unavailable", "source": manager, "items": []}
                time.sleep(0.1)
            if process.returncode != 0 or os.fstat(output.fileno()).st_size > MAX_BYTES:
                return {"status": "unavailable", "source": manager, "items": []}
            output.seek(0)
            lines = output.read(MAX_BYTES + 1).decode("utf-8", errors="replace").splitlines()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    items = []
    malformed = False
    for line in lines:
        fields = line.split("\t")
        if len(fields) != (4 if manager == "dpkg" else 3):
            malformed = True
            continue
        if manager == "dpkg" and fields[3] != "installed":
            continue
        items.append({"name": fields[0], "version": fields[1], "architecture": fields[2]})
    status = "unavailable" if malformed else "truncated" if len(items) > MAX_ROWS else "complete"
    return {"status": status, "source": manager, "items": items[:MAX_ROWS]}


def collect(mode):
    if platform.system() != "Linux":
        raise RuntimeError("Unsupported operating system")
    release = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as stream:
            for line in stream.read(16384).splitlines():
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    release[key] = value.strip().strip("\"'")[:500]
    except OSError:
        pass
    return {
        "schema_version": 1,
        "os": {
            "family": "Linux",
            "name": release.get("PRETTY_NAME", "Linux"),
            "version": release.get("VERSION_ID", "unknown"),
            "kernel": platform.release()[:500],
            "architecture": platform.machine()[:500],
            "hostname": platform.node()[:500],
        },
        "packages": (
            packages()
            if mode == "inventory"
            else {"status": "not_requested", "source": "none", "items": []}
        ),
        "hotfixes": {"status": "not_applicable", "source": "none", "items": []},
    }


if __name__ == "__main__":
    print(json.dumps(collect(sys.argv[1]), ensure_ascii=True), flush=True)
