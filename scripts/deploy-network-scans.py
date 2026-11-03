#!/usr/bin/env python3
"""Activate the reviewed network scanner on Neptun and queue its first scoped scan.

Dry-run by default. --apply backs up the database and private configuration,
adds a separate Compose override, and starts the explicitly selected first scan.
"""

import argparse
import fcntl
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import types
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request

VERSION = "1.0.0"
BASE = "76609bb540cd6851a0cca0f761de37a6ade633c4"
FEATURE = "ff0db6c686f0bb0c7af3df9a4012acbc76a3a817"
BRANCH = "sprint-1.0.2-feature-architecture"
OLD_REVISION, REVISION = "d91e6a2f4c80", "f93b70a4e628"
CIDR, CUSTOMER, WORKER_IMAGE, BACKEND_IMAGE = None, None, None, None
ADDRESS_COUNT = None
OVERRIDE = "docker-compose.network.yml"
JOURNAL = "ccvm-network-deployment.json"
CONFIGS = (
    "docker-compose.yml",
    "docker-compose.override.yml",
    "docker-compose.screenshot.yml",
    "frontend/default.conf",
    ".env",
    "backend/.env",
)
PORT_FIELDS = {"state", "product", "version", "tunnel", "cpe"}
TOOLS = ("subfinder", "dnsx", "httpx", "naabu", "katana", "nuclei")
PAYLOAD = None

STATE_CODE = r"""
import hashlib, json
import sqlalchemy as sa
from app.database.session import engine
with engine.connect().execution_options(isolation_level='REPEATABLE READ') as connection:
    connection.exec_driver_sql('SET TRANSACTION READ ONLY')
    connection.exec_driver_sql("SET LOCAL statement_timeout = '60s'")
    identity = dict(connection.exec_driver_sql(
        "SELECT current_database() AS database, inet_server_addr()::text AS address, "
        "inet_server_port() AS port, current_setting('server_version_num')::int AS version"
    ).mappings().one())
    active = [dict(row) for row in connection.exec_driver_sql(
        "SELECT id, plugin, status FROM jobs WHERE status IN ('queued','running') ORDER BY id"
    ).mappings()]
    revision = connection.exec_driver_sql('SELECT version_num FROM alembic_version').scalar_one()
    customer = connection.exec_driver_sql(
        'SELECT id, uuid, name FROM customers WHERE id=:customer_id',
        {'customer_id': CUSTOMER_ID}
    ).mappings().one_or_none()
    indexes = [dict(row) for row in connection.exec_driver_sql(
        "SELECT c.relname AS name, i.indisunique AS unique, i.indisvalid AS valid, "
        "pg_get_indexdef(i.indexrelid) AS definition FROM pg_index i "
        "JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='urls'::regclass"
    ).mappings()]
    tables = {}
    for name in sa.inspect(connection).get_table_names():
        if name == 'alembic_version':
            continue
        table = sa.Table(name, sa.MetaData(), autoload_with=connection)
        columns = [column for column in table.c if name != 'ports' or column.name not in
                   {'state','product','version','tunnel','cpe'}]
        fingerprint, count = hashlib.sha256(), 0
        result = connection.execution_options(stream_results=True).execute(
            sa.select(*columns).order_by(*table.primary_key.columns))
        for row in result:
            encoded = json.dumps(dict(row._mapping), sort_keys=True, default=str).encode()
            fingerprint.update(len(encoded).to_bytes(8, 'big') + encoded)
            count += 1
        result.close()
        tables[name] = {'count': count, 'sha256': fingerprint.hexdigest()}
    port_evidence = None
    if revision == 'f93b70a4e628':
        port_evidence = connection.exec_driver_sql(
            "SELECT count(*) FROM ports WHERE state <> 'open' OR product IS NOT NULL "
            "OR version IS NOT NULL OR tunnel IS NOT NULL OR cpe IS NOT NULL"
        ).scalar_one()
    transactions = [dict(row) for row in connection.exec_driver_sql(
        "SELECT pid FROM pg_stat_activity WHERE datname=current_database() "
        "AND pid<>pg_backend_pid() AND backend_type='client backend' AND xact_start IS NOT NULL"
    ).mappings()]
    print(json.dumps({'identity': identity, 'active': active, 'revision': revision,
        'customer': dict(customer) if customer else None, 'indexes': indexes, 'tables': tables,
        'transactions': transactions, 'port_evidence': port_evidence}))
"""


SNAPSHOT_CODE = STATE_CODE
STATE_CODE = "CUSTOMER_ID = 1\n" + SNAPSHOT_CODE


def configure(customer, cidr, worker_image, backend_image):
    """Operational identities stay local; never embed private values in repository code."""
    global CUSTOMER, CIDR, WORKER_IMAGE, BACKEND_IMAGE, PAYLOAD, ADDRESS_COUNT, STATE_CODE
    if not isinstance(customer["id"], int) or customer["id"] <= 0 or not customer["name"].strip():
        raise ValueError("Use a positive customer ID and its confirmed name")
    uuid.UUID(customer["uuid"])
    net = ipaddress.ip_network(cidr, strict=True)
    count = net.num_addresses - (2 if net.prefixlen < 31 else 0)
    if (
        net.version != 4
        or net.is_multicast
        or net.network_address.is_unspecified
        or not 0 < count <= 4096
    ):
        raise ValueError("Use a bounded, literal IPv4 CIDR with at most 4096 host addresses")
    for image in (worker_image, backend_image):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise ValueError("Image pins must be confirmed immutable Docker image IDs")
    CUSTOMER, CIDR = dict(customer), str(net)
    WORKER_IMAGE, BACKEND_IMAGE = worker_image, backend_image
    ADDRESS_COUNT = count
    PAYLOAD = {
        "customer_id": customer["id"],
        "target": CIDR,
        "name": customer["name"] + " LAN",
        "profile": "fast",
        "ports": None,
        "exclusions": [],
        "rate": 100,
        "timeout_seconds": 28800,
    }
    STATE_CODE = f'CUSTOMER_ID = {customer["id"]!r}\n' + SNAPSHOT_CODE


def validate_state(state, *, expected=None):
    if state["active"]:
        raise RuntimeError("Active jobs exist; no scan is interrupted")
    if state["revision"] not in {OLD_REVISION, REVISION} or (
        expected and state["revision"] != expected
    ):
        raise RuntimeError("Unexpected database revision")
    if state["customer"] != CUSTOMER:
        raise RuntimeError("Customer identity does not match the confirmed local selection")
    indexes = {row["name"]: row for row in state["indexes"]}
    index = indexes.get("uq_urls_domain_url_sha256", {})
    if (
        not index.get("unique")
        or not index.get("valid")
        or "sha256(" not in index.get("definition", "")
        or "uq_urls_domain_url" in indexes
    ):
        raise RuntimeError("The URL identity index is not the reviewed SHA-256 index")


def assert_preserved(before, after):
    if before["identity"] != after["identity"] or before["customer"] != after["customer"]:
        raise RuntimeError("Database or customer identity changed")
    if any(after["tables"].get(name) != value for name, value in before["tables"].items()):
        raise RuntimeError("Existing database rows changed; preserve the private backup")
    if (
        any(
            after["tables"].get(name, {}).get("count") != 0
            for name in ("network_scans", "network_observations")
        )
        or after.get("port_evidence") != 0
    ):
        raise RuntimeError("Unexpected new network data before activation")


def load_maintenance(root):
    source = subprocess.check_output(
        ["git", "-C", str(root), "show", f"{BASE}:scripts/update-url-index.py"], timeout=15
    )
    module = types.ModuleType("reviewed_ccvm_network_maintenance")
    exec(compile(source, "<reviewed-maintenance>", "exec"), module.__dict__)
    module.OLD_REVISION, module.REVISION = OLD_REVISION, REVISION
    module.STATE_CODE, module.validate_state = STATE_CODE, validate_state
    module.SCANNERS = module.SCANNERS | {"nmap"}
    return module


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


def source_plan(module, root, target):
    def git(*args):
        return module.git(root, *args)

    if not re.fullmatch(r"[0-9a-f]{40}", target):
        raise RuntimeError("Target must be a full reviewed merge SHA")
    if (
        git("branch", "--show-current") != BRANCH
        or Path(git("rev-parse", "--show-toplevel")).resolve() != root
    ):
        raise RuntimeError("Unexpected deployment checkout")
    before = git("rev-parse", "HEAD")
    if before not in {BASE, target} or git("rev-parse", f"origin/{BRANCH}") != target:
        raise RuntimeError("Checkout or deployment target changed")
    git("merge-base", "--is-ancestor", FEATURE, target)
    directory = Path(git("rev-parse", "--absolute-git-dir"))
    for marker in ("index.lock", "MERGE_HEAD", "CHERRY_PICK_HEAD", "rebase-merge", "rebase-apply"):
        if (directory / marker).exists():
            raise RuntimeError("Another Git operation is unfinished")
    git("diff", "--cached", "--exit-code")
    dirty = set(git("diff", "--name-only").splitlines())
    if dirty - {"docker-compose.yml", "frontend/default.conf"}:
        raise RuntimeError("Additional tracked edits preserved; deployment refused")
    changes = git("diff", "--name-only", "--no-renames", BASE, target).splitlines()
    if any(
        name in CONFIGS
        or name.startswith("docker-compose")
        or "/.env" in name
        or not name.startswith(("backend/", "frontend/", "scripts/", "docs/", ".github/", "README"))
        for name in changes
    ):
        raise RuntimeError("Target changes protected configuration or unrelated files")
    if git("diff", "--name-only", "--diff-filter=D", BASE, target):
        raise RuntimeError("Target deletes source files")
    unknown = set(git("ls-files", "--others", "--exclude-standard").splitlines())
    if unknown & set(changes):
        raise RuntimeError("An untracked target file would be overwritten")
    for name in unknown:
        if name.startswith(("backend/app/", "backend/alembic/", "frontend/src/")) and Path(
            name
        ).suffix in {".py", ".ts", ".tsx", ".js", ".jsx"}:
            raise RuntimeError("Additional application source preserved")
    for name in set(changes) | set(CONFIGS) | {OVERRIDE, "frontend/dist"}:
        path = root / name
        while path != root:
            if path.is_symlink():
                raise RuntimeError("Symlink in deployment path")
            path = path.parent
    return before, changes


def env_map(entries):
    return dict(item.split("=", 1) for item in entries or [] if "=" in item)


def validate_service(config, service, container, image):
    """Refuse source/container drift instead of recreating with guessed settings."""
    spec, actual = config["services"][service], container["Config"]
    inherited = image["Config"]
    expected_env = env_map(inherited.get("Env"))
    expected_env.update({key: str(value) for key, value in spec.get("environment", {}).items()})
    checks = [
        expected_env == env_map(actual.get("Env")),
        spec.get("image") == actual.get("Image"),
        spec.get("command", inherited.get("Cmd")) == actual.get("Cmd"),
        spec.get("entrypoint", inherited.get("Entrypoint")) == actual.get("Entrypoint"),
        spec.get("working_dir", inherited.get("WorkingDir", "")) == actual.get("WorkingDir", ""),
        (spec.get("user", inherited.get("User")) or "root") == (actual.get("User") or "root"),
        bool(spec.get("privileged")) == container["HostConfig"]["Privileged"],
        bool(spec.get("read_only")) == container["HostConfig"]["ReadonlyRootfs"],
        spec.get("restart", "") == container["HostConfig"]["RestartPolicy"]["Name"],
    ]
    expected_mounts = set()
    for mount in spec.get("volumes", []):
        source = mount.get("source")
        if mount["type"] == "volume":
            source = config.get("volumes", {}).get(source, {}).get("name")
        if mount["type"] not in {"volume", "bind"} or not source:
            raise RuntimeError("Unreviewed anonymous or special mount")
        expected_mounts.add((source, mount["target"], not mount.get("read_only", False)))
    actual_mounts = {
        (m.get("Name") if m["Type"] == "volume" else m["Source"], m["Destination"], m["RW"])
        for m in container["Mounts"]
    }
    checks.append(expected_mounts == actual_mounts)
    expected_networks = {config["networks"][name]["name"] for name in spec.get("networks", {})}
    checks.append(expected_networks == set(container["NetworkSettings"]["Networks"]))
    expected_ports = {
        (
            str(p["target"]) + "/" + p.get("protocol", "tcp"),
            p.get("host_ip") or "",
            str(p.get("published", "")),
        )
        for p in spec.get("ports", [])
    }
    actual_ports = {
        (port, entry.get("HostIp") or "", entry["HostPort"])
        for port, entries in (container["HostConfig"].get("PortBindings") or {}).items()
        for entry in entries or []
    }
    checks.append(expected_ports == actual_ports)
    if not all(checks):
        raise RuntimeError(
            f"{service}: Compose/container configuration differs; originals preserved"
        )


def compose(runtime, root, *args, override=False):
    command = [
        "compose",
        "--project-directory",
        str(root),
        "--project-name",
        "ccvm",
        "--file",
        str(root / "docker-compose.yml"),
    ]
    if override:
        command += ["--file", str(root / OVERRIDE)]
    return runtime.docker(*command, *args)


def inspect(runtime, name):
    return json.loads(runtime.docker("inspect", "--format", "{{json .}}", name))


def build_override(backend_image, worker_image):
    return {
        "services": {
            name: {
                "image": image,
                "pull_policy": "never",
                "environment": {"CCVM_NETWORK_ALLOWED_CIDRS": CIDR},
            }
            for name, image in (("backend", backend_image), ("worker", worker_image))
        }
    }


def capture_config(root):
    return {
        name: (root / name).read_bytes() if (root / name).is_file() else None for name in CONFIGS
    }


def assert_config(root, captured):
    if capture_config(root) != captured:
        raise RuntimeError("Original private configuration changed")


def build_artifacts(module, runtime, root, target, backup):
    """Build before downtime; keep legacy scanner binaries and nginx's bind inode."""
    tag = "ccvm-network-worker:" + target[:12]
    base_tag = "ccvm-network-base:" + WORKER_IMAGE.split(":")[1][:12]
    runtime.docker("tag", WORKER_IMAGE, base_tag)
    context = backup / "image-build"
    context.mkdir()
    dockerfile = context / "Dockerfile.network-tools"
    dockerfile.write_bytes(
        module.run(["git", "-C", str(root), "show", f"{target}:backend/Dockerfile.network-tools"])
    )
    module.run(
        [
            *runtime.prefix,
            "build",
            "--file",
            str(dockerfile),
            "--tag",
            tag,
            "--build-arg",
            f"CCVM_WORKER_BASE={base_tag}",
            str(context),
        ],
        timeout=600,
    )
    fingerprint = (
        "import hashlib,json,shutil; "
        f"names={TOOLS!r}; "
        "print(json.dumps({name:hashlib.sha256(open(shutil.which(name),'rb').read()).hexdigest() "
        "for name in names}))"
    )
    old = runtime.docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--entrypoint",
        "python",
        WORKER_IMAGE,
        "-B",
        "-c",
        fingerprint,
    )
    new = runtime.docker(
        "run", "--rm", "--network", "none", "--entrypoint", "python", tag, "-B", "-c", fingerprint
    )
    if json.loads(old) != json.loads(new):
        raise RuntimeError("An existing scanner binary changed")
    version = runtime.docker(
        "run", "--rm", "--network", "none", "--entrypoint", "nmap", tag, "--version"
    )
    if "Nmap version" not in version:
        raise RuntimeError("Nmap executable verification failed")
    write_json(backup / "scanner-binaries.json", json.loads(new))
    (backup / "nmap-version.txt").write_text(version)
    archive = module.run(["git", "-C", str(root), "archive", target, "frontend"])
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(backup / "build", filter="data")
    frontend = backup / "build/frontend"
    module.run(
        [
            *runtime.prefix,
            "run",
            "--rm",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--mount",
            f"type=bind,src={frontend},dst=/work",
            "--workdir",
            "/work",
            "--env",
            "npm_config_cache=/tmp/ccvm-npm",
            "--entrypoint",
            "sh",
            "node:22-bookworm-slim",
            "-c",
            "npm ci --no-audit --no-fund && npm run build",
        ],
        timeout=600,
    )
    if not (frontend / "dist/index.html").is_file():
        raise RuntimeError("Frontend build did not produce index.html")
    return tag, frontend / "dist"


def install_frontend(source, destination):
    """Retain the existing bind-mounted directory and old hashed client assets."""
    for path in sorted(source.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(source)
        if relative.as_posix() == "index.html":
            continue
        target = destination / relative
        for parent in (target, *target.parents):
            if parent == destination:
                break
            if parent.is_symlink():
                raise RuntimeError("Symlink in frontend release path")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    descriptor, temporary = tempfile.mkstemp(prefix=".ccvm-index-", dir=destination)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write((source / "index.html").read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination / "index.html")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def publish_frontend(runtime, root, built):
    # Root-owned directories remain usable without recreating the bind-mounted nginx.
    runtime.docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--entrypoint",
        "python",
        "--mount",
        f"type=bind,src={root / 'scripts/deploy-network-scans.py'},dst=/operator.py,readonly",
        "--mount",
        f"type=bind,src={built},dst=/build,readonly",
        "--mount",
        f"type=bind,src={root / 'frontend/dist'},dst=/release",
        BACKEND_IMAGE,
        "-B",
        "-c",
        "import runpy; from pathlib import Path; "
        "runpy.run_path('/operator.py')['install_frontend'](Path('/build'), Path('/release'))",
    )


def verify_installed(runtime, root, operation):
    expected = build_override(BACKEND_IMAGE, operation["worker_tag"])
    if json.loads((root / OVERRIDE).read_text()) != expected:
        raise RuntimeError("Installed network override changed")
    for name, image in (("worker", operation["worker_image"]), ("backend", BACKEND_IMAGE)):
        info = inspect(runtime, "ccvm-" + name)
        if (
            info["Image"] != image
            or not info["State"]["Running"]
            or info["State"]["Paused"]
            or env_map(info["Config"].get("Env")).get("CCVM_NETWORK_ALLOWED_CIDRS") != CIDR
        ):
            raise RuntimeError("Installed network runtime changed")


def request(runtime, path, *, port=8088, payload=None):
    req = Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"},
    )
    with runtime.opener.open(req, timeout=15) as response:
        return json.load(response)


def verify_api(runtime):
    reloaded = False
    for attempt in range(60):
        try:
            for port in (8088, 8090):
                data = request(runtime, "/api/v1/network-scans/capabilities", port=port)
                if not data.get("enabled") or data.get("allowed_cidrs") != [CIDR]:
                    raise RuntimeError("API network policy does not match the selected CIDR")
            return
        except HTTPError as error:
            if error.code in {502, 503, 504} and not reloaded:
                runtime.docker("exec", "ccvm-frontend", "nginx", "-t")
                runtime.docker("exec", "ccvm-frontend", "nginx", "-s", "reload")
                reloaded = True
        except (OSError, ValueError):
            pass
        if attempt < 59:
            time.sleep(2)
    raise RuntimeError("Backend/frontend network API did not become ready; no scan submitted")


def matching_run(run):
    return (
        all(
            run.get(key) == PAYLOAD[key]
            for key in (
                "customer_id",
                "target",
                "profile",
                "ports",
                "exclusions",
                "rate",
                "timeout_seconds",
            )
        )
        and run.get("address_count") == ADDRESS_COUNT
    )


def start_once(runtime, marker, operation):
    """Record intent before POST; reconcile a lost response without a second scan."""
    verify_api(runtime)
    customer = request(runtime, "/api/v1/customers/" + CUSTOMER["uuid"])
    if {key: customer.get(key) for key in CUSTOMER} != CUSTOMER:
        raise RuntimeError("The confirmed customer identity changed; no scan submitted")
    if operation.get("scan_id"):
        scan = request(runtime, f"/api/v1/network-scans/{operation['scan_id']}")
        if not matching_run(scan) or scan["pipeline_id"] != operation["pipeline_id"]:
            raise RuntimeError("Recorded network scan identity changed")
    else:
        runs = request(runtime, f"/api/v1/network-scans?customer_id={CUSTOMER['id']}")
        matches = [run for run in runs if matching_run(run)]
        if operation["phase"] == "scan-intent":
            if len(matches) > 1 or len(runs) != len(matches):
                raise RuntimeError("Ambiguous scan submission; do not create another scan")
        elif runs:
            raise RuntimeError("Network runs already exist; first-run submission refused")
        if matches:
            scan = matches[0]
        else:
            preview = request(runtime, "/api/v1/network-scans/preview", payload=PAYLOAD)
            if preview.get("target") != CIDR or preview.get("address_count") != ADDRESS_COUNT:
                raise RuntimeError("Scope preview changed")
            operation["phase"] = "scan-intent"
            write_json(marker, operation)
            scan = request(runtime, "/api/v1/network-scans", payload=PAYLOAD)
        if not matching_run(scan):
            raise RuntimeError("Created scan differs from the reviewed scope")
        operation.update(scan_id=scan["id"], pipeline_id=scan["pipeline_id"], phase="submitted")
        write_json(marker, operation)
    print(
        f"VERIFIED: {CUSTOMER['name']} scan {scan['id']} · {CIDR} · "
        f"{ADDRESS_COUNT} addresses · top 100 TCP ports",
        flush=True,
    )
    for job in scan["jobs"]:
        print(f"Job {job['id']} {job['plugin']}: {job['status']} {job['progress']}%", flush=True)


def apply(module, runtime, root, target, plan):
    directory = Path(module.git(root, "rev-parse", "--absolute-git-dir"))
    marker = directory / JOURNAL
    if marker.exists():
        operation = json.loads(marker.read_text())
        if operation.get("target") != target or operation.get("payload") != PAYLOAD:
            raise RuntimeError("A different network deployment journal exists")
        if operation["phase"] in {"activated", "scan-intent", "submitted"}:
            if plan[0] != target:
                raise RuntimeError("Deployment journal and installed Git differ")
            verify_installed(runtime, root, operation)
            start_once(runtime, marker, operation)
            return
        raise RuntimeError("Previous deployment is incomplete; inspect its retained private backup")
    if plan[0] != BASE or (root / OVERRIDE).exists():
        raise RuntimeError("First activation requires the confirmed base and no existing override")
    initial = runtime.preflight(root)
    validate_state(initial, expected=OLD_REVISION)
    worker, backend = runtime.worker_info, inspect(runtime, "ccvm-backend")
    if worker["Image"] != WORKER_IMAGE or backend["Image"] != BACKEND_IMAGE:
        raise RuntimeError("A confirmed application image changed")
    for info in (worker, backend):
        labels = info["Config"].get("Labels", {})
        if (
            labels.get("com.docker.compose.project") != "ccvm"
            or labels.get("com.docker.compose.project.config_files")
            != str(root / "docker-compose.yml")
            or labels.get("com.docker.compose.project.working_dir") != str(root)
        ):
            raise RuntimeError("The confirmed Compose project changed")
        if env_map(info["Config"].get("Env")).get("CCVM_NETWORK_ALLOWED_CIDRS"):
            raise RuntimeError("An existing network policy is configured; preserved")
    config = json.loads(compose(runtime, root, "config", "--format", "json"))
    for name, info in (("worker", worker), ("backend", backend)):
        validate_service(config, name, info, inspect(runtime, info["Image"]))
    captured = capture_config(root)
    backup = Path(tempfile.mkdtemp(prefix="ccvm-network-before-", dir=directory))
    for name, content in captured.items():
        if content is not None:
            saved = backup / "config" / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(content)
    write_json(backup / "containers.json", {"worker": worker, "backend": backend})
    write_json(backup / "compose.json", config)
    operation = {
        "target": target,
        "before": BASE,
        "payload": PAYLOAD,
        "backup": str(backup),
        "phase": "prepared",
    }
    print(f"Private backup: {backup}", flush=True)
    tag, built = build_artifacts(module, runtime, root, target, backup)
    runtime.prepare_maintenance(backup)
    worker_image = json.loads(runtime.docker("image", "inspect", tag))[0]["Id"]
    operation.update(worker_image=worker_image, worker_tag=tag)
    new_override = build_override(BACKEND_IMAGE, tag)
    if any(path.is_symlink() for path in (root / "frontend/dist").rglob("*")):
        raise RuntimeError("Symlinks in the existing frontend build; originals preserved")
    shutil.copytree(root / "frontend/dist", backup / "frontend-dist", symlinks=False)
    api_stopped = frozen = mutated = False
    try:
        if source_plan(module, root, target) != plan:
            raise RuntimeError("Source changed during artifact builds")
        assert_config(root, captured)
        runtime.preflight(root)
        api_stopped = True
        runtime.docker("stop", "--time", "20", "ccvm-backend")
        for _ in range(5):
            frozen = True
            runtime.freeze()
            before = runtime.state()
            if not before["transactions"]:
                break
            runtime.resume()
            frozen = False
            time.sleep(0.3)
        else:
            raise RuntimeError("Open database transactions remained; migration refused")
        validate_state(before, expected=OLD_REVISION)
        write_json(backup / "before.json", before)
        runtime.database_backup(backup / "database.dump")
        if source_plan(module, root, target) != plan:
            raise RuntimeError("Source changed before migration")
        write_json(marker, operation)
        mutated = True
        module.git(root, "merge", "--ff-only", target)
        runtime.migrate()
        after = runtime.state()
        validate_state(after, expected=REVISION)
        assert_preserved(before, after)
        write_json(backup / "after.json", after)
        assert_config(root, captured)
        write_json(root / OVERRIDE, new_override)
        resolved = json.loads(compose(runtime, root, "config", "--format", "json", override=True))
        for name in config["services"]:
            expected = dict(config["services"][name])
            if name in {"backend", "worker"}:
                expected.update(image=new_override["services"][name]["image"], pull_policy="never")
                expected["environment"] = {
                    **expected.get("environment", {}),
                    "CCVM_NETWORK_ALLOWED_CIDRS": CIDR,
                }
            if resolved["services"][name] != expected:
                raise RuntimeError("Compose override changed an unrelated setting")
        runtime.resume()
        frozen = False
        compose(
            runtime,
            root,
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            "worker",
            override=True,
        )
        current = inspect(runtime, "ccvm-worker")
        if current["Image"] != worker_image or not current["State"]["Running"]:
            raise RuntimeError("Replacement worker was not confirmed")
        validate_service(resolved, "worker", current, inspect(runtime, worker_image))
        compose(
            runtime,
            root,
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            "backend",
            override=True,
        )
        api_stopped = False
        current = inspect(runtime, "ccvm-backend")
        validate_service(resolved, "backend", current, inspect(runtime, BACKEND_IMAGE))
        verify_api(runtime)
        publish_frontend(runtime, root, built)
        with runtime.opener.open("http://127.0.0.1:8090/", timeout=15) as response:
            if response.read() != (built / "index.html").read_bytes():
                raise RuntimeError("Served frontend does not match the new build")
        assert_config(root, captured)
        operation["phase"] = "activated"
        write_json(marker, operation)
    except BaseException:
        if mutated:
            runtime.docker("stop", "--time", "20", "ccvm-backend")
            if not frozen:
                runtime.freeze()
            print(
                f"Activation stopped; API stopped, worker paused. Inspect backup {backup}",
                flush=True,
            )
        else:
            if frozen:
                runtime.resume()
            if api_stopped:
                runtime.docker("start", "ccvm-backend")
        raise
    start_once(runtime, marker, operation)
    print(f"Deployment: {target}. Future Compose commands must include -f {OVERRIDE}.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--customer-id", required=True, type=int)
    parser.add_argument("--customer-uuid", required=True)
    parser.add_argument("--customer-name", required=True)
    parser.add_argument("--cidr", required=True)
    parser.add_argument("--worker-image", required=True)
    parser.add_argument("--backend-image", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    root = Path("/opt/ccvm").resolve()
    if socket.gethostname().split(".")[0] != "neptun":
        raise RuntimeError("This operation is restricted to Neptun")
    configure(
        {"id": args.customer_id, "uuid": args.customer_uuid, "name": args.customer_name},
        args.cidr,
        args.worker_image,
        args.backend_image,
    )
    module = load_maintenance(root)
    directory = Path(module.git(root, "rev-parse", "--absolute-git-dir"))
    with (directory / "ccvm-network-deployment.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan = source_plan(module, root, args.target)
        runtime = module.Runtime()
        print(f"CCVM network deployment {VERSION}; reviewed target {args.target}", flush=True)
        if args.apply:
            apply(module, runtime, root, args.target, plan)
        else:
            validate_state(runtime.preflight(root), expected=OLD_REVISION)
            print(
                f"Read-only preflight: customer {CUSTOMER['id']}, {CIDR}. "
                "Use --apply to activate.",
                flush=True,
            )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"STOPPED: {type(error).__name__}: {error}", flush=True)
        raise SystemExit(1) from error
