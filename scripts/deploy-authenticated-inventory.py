#!/usr/bin/env python3
"""Deploy reviewed authenticated inventory through an existing HAProxy SNI edge.

Read-only preflight by default. --apply is an explicitly scoped deployment;
--resume continues only its own retained journal. No scanner job is submitted.
"""

import argparse
import base64
import fcntl
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import types
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

VERSION = "1.0.0"
BASE = "06190ea161e68ffad6d9b653b2b3088fb194e056"
FEATURE = "a58ac2a5386bbb2ce854aad0878ffa9527ea1dd6"
BRANCH = "sprint-1.0.2-feature-architecture"
OLD_REVISION, REVISION = "f93b70a4e628", "c8f3a0e2b741"
OVERRIDE = "docker-compose.authenticated.yml"
JOURNAL = "ccvm-authenticated-deployment.json"
SECRET_DIRECTORY = "ccvm-audit-secrets"
TOOLS = ("subfinder", "dnsx", "httpx", "naabu", "katana", "nuclei", "nmap")
PROTECTED = (
    "docker-compose.yml",
    "docker-compose.network.yml",
    "docker-compose.override.yml",
    "docker-compose.screenshot.yml",
    "frontend/default.conf",
    ".env",
    "backend/.env",
)
AUDIT_KEYS = {"CCVM_AUDIT_VAULT_KEY", "CCVM_AUDIT_OPERATOR_TOKEN"}

STATE_CODE = r"""
import base64, hashlib, json, sqlalchemy as sa
from app.database.session import engine
def stable(value):
    if isinstance(value, (bytes,bytearray,memoryview)):
        return {'binary':base64.b64encode(value).decode()}
    raise TypeError('Unsupported database scalar')
with engine.connect().execution_options(isolation_level='REPEATABLE READ') as c:
    c.exec_driver_sql('SET TRANSACTION READ ONLY')
    c.exec_driver_sql("SET LOCAL statement_timeout='60s'")
    identity = dict(c.exec_driver_sql(
        "SELECT current_database() AS database, inet_server_addr()::text AS address, "
        "inet_server_port() AS port, current_setting('server_version_num')::int AS version"
    ).mappings().one())
    tables = {}
    for name in sa.inspect(c).get_table_names():
        if name == 'alembic_version': continue
        table = sa.Table(name,sa.MetaData(),autoload_with=c)
        digest,count = hashlib.sha256(),0
        rows = c.execution_options(stream_results=True).execute(
            sa.select(table).order_by(*table.primary_key.columns))
        for row in rows:
            # Datetimes are rendered consistently; bytea never uses a memory
            # address-dependent repr. Ciphertext is not included in output.
            def encode(value):
                if isinstance(value,(bytes,bytearray,memoryview)): return stable(value)
                return str(value)
            data=json.dumps(dict(row._mapping),sort_keys=True,default=encode).encode()
            digest.update(len(data).to_bytes(8,'big')+data)
            count += 1
        rows.close()
        tables[name]={'count':count,'sha256':digest.hexdigest()}
    print(json.dumps({'identity':identity,'tables':tables,
        'revision':c.exec_driver_sql('SELECT version_num FROM alembic_version').scalar_one(),
        'active':[dict(r) for r in c.exec_driver_sql(
            "SELECT id,plugin,status FROM jobs WHERE status IN ('queued','running') ORDER BY id"
        ).mappings()],
        'transactions':c.exec_driver_sql(
            "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
            "AND pid<>pg_backend_pid() AND backend_type='client backend' "
            "AND xact_start IS NOT NULL").scalar_one()}))
"""

FINGERPRINT_CODE = r"""
import hashlib,json,shutil
result={}
for name in NAMES:
    path=shutil.which(name)
    if not path: raise RuntimeError('Missing scanner executable')
    with open(path,'rb') as stream: result[name]=hashlib.file_digest(stream,'sha256').hexdigest()
print(json.dumps(result,sort_keys=True))
"""

TLS_PROBE = r"""
import http.client,ipaddress,json,socket,ssl,sys,time
p=json.load(sys.stdin)
context=ssl.create_default_context(cafile=p.get('ca_file'))
def request(port,client,path,token=None,spoof=False):
    raw=socket.create_connection(('127.0.0.1',port),timeout=8)
    if client:
        version='TCP6' if ':' in client else 'TCP4'
        destination='::1' if version=='TCP6' else '127.0.0.1'
        raw.sendall(f'PROXY {version} {client} {destination} 12345 {port}\r\n'.encode())
    with context.wrap_socket(raw,server_hostname=p['hostname']) as tls:
        headers=[f'GET {path} HTTP/1.1',f"Host: {p['hostname']}",'Connection: close']
        if token: headers.append('Authorization: Bearer '+token)
        if spoof: headers += ['X-Forwarded-For: '+p['allowed'],'X-Forwarded-Proto: https']
        tls.sendall(('\r\n'.join(headers)+'\r\n\r\n').encode())
        response=http.client.HTTPResponse(tls)
        response.begin()
        status=response.status
        marker=response.getheader('X-CCVM-Route')
        response.read(2*1024*1024)
        return status,marker
assert request(p['port'],p['allowed'],'/health')==(200,p['marker'])
assert request(p['port'],p['denied'],'/health',spoof=True)==(403,p['marker'])
path='/api/v1/host-audits?customer_id=1'
assert request(p['port'],p['allowed'],path)==(401,p['marker'])
assert request(p['port'],p['allowed'],path,'incorrect-operator-token')==(401,p['marker'])
assert request(p['port'],p['allowed'],path,p['token'])==(200,p['marker'])
assert request(443,None,'/health',spoof=True)==(403,p['marker'])
print(json.dumps({'tls':True,'sni':True,'allowed_client':True,'denied_client':True,
                  'header_spoof_denied':True,'operator_token':True}))
"""


def run(args, *, data=None, timeout=180, diagnostic=None):
    try:
        result = subprocess.run(
            args,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        if diagnostic:
            private_write(diagnostic, (error.stdout or b"") + b"\n" + (error.stderr or b""))
        raise RuntimeError("Command exceeded its time limit; inspect private diagnostics") from None
    if result.returncode:
        if diagnostic:
            private_write(diagnostic, result.stdout + b"\n" + result.stderr)
        # Docker/Compose/parser errors may echo env values or configuration.
        # Keep full diagnostics in the private backup, never in terminal output.
        raise RuntimeError(
            f"{Path(args[0]).name} exited {result.returncode}; "
            + (f"inspect {diagnostic}" if diagnostic else "command output withheld")
        )
    return result.stdout


def private_write(path, data):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".audit-write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    private_write(path, (json.dumps(value, indent=2) + "\n").encode())


def git(root, *args):
    return run(["git", "-C", str(root), *args]).decode().strip()


def load_helper(root, target, path, name):
    module = types.ModuleType(name)
    module.__file__ = f"<git:{path}>"
    sys.modules[name] = module
    source = run(["git", "-C", str(root), "show", f"{target}:{path}"])
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def source_plan(root, target, *, resume=False):
    if not re.fullmatch(r"[0-9a-f]{40}", target):
        raise RuntimeError("Use the full reviewed deployment merge SHA")
    if (
        Path(git(root, "rev-parse", "--show-toplevel")).resolve() != root
        or git(root, "branch", "--show-current") != BRANCH
    ):
        raise RuntimeError("Unexpected deployment checkout")
    before = git(root, "rev-parse", "HEAD")
    if before not in {BASE, target} or git(root, "rev-parse", f"origin/{BRANCH}") != target:
        raise RuntimeError("Source or reviewed deployment target changed")
    if before == target and not resume:
        raise RuntimeError("Installed target requires its retained deployment journal")
    git(root, "merge-base", "--is-ancestor", FEATURE, target)
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    for name in ("index.lock", "MERGE_HEAD", "CHERRY_PICK_HEAD", "rebase-merge", "rebase-apply"):
        if (directory / name).exists():
            raise RuntimeError("Another Git operation is unfinished")
    git(root, "diff", "--cached", "--exit-code")
    if set(git(root, "diff", "--name-only").splitlines()) - {
        "docker-compose.yml",
        "frontend/default.conf",
    }:
        raise RuntimeError("Additional tracked edits retained; deployment refused")
    changes = git(root, "diff", "--name-only", "--no-renames", BASE, target).splitlines()
    if any(
        name in PROTECTED
        or name.startswith("docker-compose")
        or not name.startswith(("backend/", "frontend/", "scripts/", "docs/", ".github/", "README"))
        for name in changes
    ):
        raise RuntimeError("Target modifies protected or unrelated files")
    if git(root, "diff", "--name-only", "--diff-filter=D", BASE, target):
        raise RuntimeError("Source deletion is outside this deployment")
    unknown = set(git(root, "ls-files", "--others", "--exclude-standard").splitlines())
    if unknown & set(changes):
        raise RuntimeError("Untracked target collision retained")
    if any(
        name.startswith(("backend/app/", "backend/alembic/", "frontend/src/"))
        and Path(name).suffix in {".py", ".ts", ".tsx", ".js", ".jsx"}
        for name in unknown
    ):
        raise RuntimeError("Additional application source retained")
    for name in set(changes) | set(PROTECTED) | {OVERRIDE, "frontend/dist"}:
        path = root / name
        while path != root:
            if path.is_symlink():
                raise RuntimeError("Symlink in deployment path")
            path = path.parent
    return before, changes


def env_map(info):
    return dict(
        value.split("=", 1) for value in info.get("Config", {}).get("Env", []) if "=" in value
    )


def validate_state(state, expected, *, idle=True):
    if state["revision"] != expected:
        raise RuntimeError("Unexpected application schema")
    if idle and state["active"]:
        raise RuntimeError("Active jobs retained; wait for an idle worker")


def assert_preserved(before, after):
    if before["identity"] != after["identity"]:
        raise RuntimeError("Database identity changed")
    if any(after["tables"].get(name) != value for name, value in before["tables"].items()):
        raise RuntimeError("Existing rows changed; retain the private database backup")
    extra = set(after["tables"]) - set(before["tables"])
    expected = {"audit_credentials", "host_audits"}
    if after.get("revision") == "c8f3a0e2b741":
        expected |= {"windows_patch_catalogs", "host_assessments"}
    if extra != expected or any(after["tables"][name]["count"] for name in extra):
        raise RuntimeError("Migration did not add exactly the expected empty inventory tables")


class Runtime:
    def __init__(self, root, target, ingress):
        self.root, self.target, self.ingress = root, target, ingress
        self.prefix = ["docker"]
        self.privileged = [] if os.geteuid() == 0 else ["sudo", "-n"]
        self.diagnostic = None
        try:
            run(["docker", "info", "--format", "{{.ServerVersion}}"])
        except RuntimeError:
            self.prefix = ["sudo", "-n", "docker"]
        self.opener = build_opener(ProxyHandler({}))

    def docker(self, *args, data=None, timeout=180):
        return (
            run([*self.prefix, *args], data=data, timeout=timeout, diagnostic=self.diagnostic)
            .decode()
            .strip()
        )

    def inspect(self, name):
        return json.loads(self.docker("inspect", "--format", "{{json .}}", name))

    def root_io(self, payload):
        raw = run(
            [*self.privileged, "python3", "-I", "-c", self.ingress.ROOT_IO],
            data=json.dumps(payload).encode(),
            diagnostic=self.diagnostic,
        )
        return json.loads(raw) if raw.strip() else None

    def compose(self, *args, extra=False):
        flags = [
            "compose",
            "--project-directory",
            str(self.root),
            "--project-name",
            "ccvm",
            "--file",
            str(self.root / "docker-compose.yml"),
            "--file",
            str(self.root / "docker-compose.network.yml"),
        ]
        if extra:
            flags += ["--file", str(self.root / OVERRIDE)]
        return self.docker(*flags, *args, timeout=600)

    def helper(self, operation, source, *, candidate=True, data=None, network=None):
        # Isolated Python avoids root-/operator.py and inherits no host secrets.
        backend = operation["backend_source"] if candidate else self.root / "backend"
        args = [
            "run",
            "--rm",
            "--pull=never",
            "--network",
            network or operation["network"],
            "--mount",
            f"type=bind,src={backend},dst=/app,readonly",
            "--env-file",
            str(Path(operation["backup"]) / "database.env"),
            "--env",
            "PGCONNECT_TIMEOUT=10",
            "--workdir",
            "/tmp",
            "--entrypoint",
            "python",
            operation["images"]["backend"],
            "-I",
            "-B",
            "-c",
            "import sys; sys.path.insert(0,'/app');\n" + source,
        ]
        if data is not None:
            args.insert(1, "-i")
        return self.docker(*args, data=data, timeout=180)

    def state(self, operation):
        return json.loads(self.helper(operation, STATE_CODE))

    def reload_edge(self):
        self.docker(
            "exec",
            "--user",
            "0",
            "haproxy-edge",
            "haproxy",
            "-c",
            "-f",
            "/usr/local/etc/haproxy/haproxy.cfg",
        )
        self.docker("exec", "--user", "0", "haproxy-edge", "kill", "-USR2", "1")

    def tls_probe(self, operation):
        private = Path(operation["private"])
        token = read_env(private / "operator.env")["CCVM_AUDIT_OPERATOR_TOKEN"]
        networks = [ipaddress.ip_network(value) for value in operation["clients"]]
        allowed = str(next(networks[0].hosts()))
        denied = next(
            value
            for value in ("203.0.113.19", "198.51.100.19", "2001:db8:ffff::19")
            if not any(
                ipaddress.ip_address(value).version == n.version
                and ipaddress.ip_address(value) in n
                for n in networks
            )
        )
        payload = {
            "hostname": operation["hostname"],
            "allowed": allowed,
            "denied": denied,
            "port": operation["tls_port"],
            "marker": operation["target"][:12],
            "token": token,
        }
        args = [
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
            operation["images"]["backend"],
            "-I",
            "-B",
            "-c",
            TLS_PROBE,
        ]
        return json.loads(self.docker(*args, data=json.dumps(payload).encode(), timeout=90))


def read_env(path):
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise RuntimeError("Private environment file permissions changed")
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if line)


def make_secrets(directory, operation):
    """Commit the complete secret directory together; never rotate existing keys."""
    if os.path.lexists(directory):
        validate_secrets(directory, operation)
        return
    temporary = Path(tempfile.mkdtemp(prefix=".audit-secrets-", dir=directory.parent))
    vault = base64.b64encode(secrets.token_bytes(32)).decode()
    token = secrets.token_urlsafe(32)
    private_write(temporary / "vault.env", f"CCVM_AUDIT_VAULT_KEY={vault}\n".encode())
    private_write(temporary / "operator.env", f"CCVM_AUDIT_OPERATOR_TOKEN={token}\n".encode())
    directory.parent.mkdir(exist_ok=True)
    os.rename(temporary, directory)
    validate_secrets(directory, operation)


def validate_secrets(directory, operation):
    if (
        directory.is_symlink()
        or directory.stat().st_mode & 0o077
        or directory.stat().st_uid != os.geteuid()
    ):
        raise RuntimeError("Private secret directory changed")
    vault = read_env(directory / "vault.env")
    token = read_env(directory / "operator.env")
    if (
        set(vault) != {"CCVM_AUDIT_VAULT_KEY"}
        or len(base64.b64decode(vault["CCVM_AUDIT_VAULT_KEY"], validate=True)) != 32
    ):
        raise RuntimeError("Invalid retained vault key")
    if set(token) != {"CCVM_AUDIT_OPERATOR_TOKEN"} or not re.fullmatch(
        r"[a-zA-Z0-9_-]{43}", token["CCVM_AUDIT_OPERATOR_TOKEN"]
    ):
        raise RuntimeError("Invalid retained operator token")
    combined = {**vault, **token}
    hashes = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in combined.items()}
    if operation.get("secret_hashes") and operation["secret_hashes"] != hashes:
        raise RuntimeError("Retained credential keys changed; no rotation performed")
    operation["secret_hashes"] = hashes


def capture_config(root):
    return {
        name: (root / name).read_bytes() if (root / name).is_file() else None for name in PROTECTED
    }


def assert_config(root, captured):
    if capture_config(root) != captured:
        raise RuntimeError("Original private Compose or nginx configuration changed")


def mounted_file(runtime, info, destination):
    mounts = [m for m in info["Mounts"] if m["Destination"] == destination and m["Type"] == "bind"]
    if len(mounts) != 1 or mounts[0]["RW"]:
        raise RuntimeError("Expected the existing read-only configuration bind")
    path = Path(mounts[0]["Source"])
    content = runtime.root_io({"action": "read", "path": str(path)})
    mounted = runtime.docker("exec", info["Id"], "sha256sum", destination).split()[0]
    if mounted != hashlib.sha256(base64.b64decode(content["data"])).hexdigest():
        raise RuntimeError("Host configuration and running bind differ")
    return path, content


def database_identity(state, postgres):
    settings = env_map(postgres)
    addresses = {
        ipaddress.ip_address(value)
        for net in postgres["NetworkSettings"]["Networks"].values()
        for key in ("IPAddress", "GlobalIPv6Address")
        if (value := net.get(key))
    }
    identity = state["identity"]
    if (
        identity["database"] != settings.get("POSTGRES_DB")
        or identity["port"] != 5432
        or identity["version"] // 10000 != 16
        or ipaddress.ip_interface(identity["address"]).ip not in addresses
    ):
        raise RuntimeError("Application database does not match the PostgreSQL 16 backup target")


def worker_identity(runtime, worker):
    argv = worker["Config"].get("Cmd", [])
    if not isinstance(argv, list) or len(argv) != 3 or argv[1:] != ["-m", "app.worker.main"]:
        raise RuntimeError("Worker command is not the confirmed module")
    actual = json.loads(
        runtime.docker(
            "exec",
            worker["Id"],
            "python",
            "-I",
            "-c",
            "import json;data=open('/proc/1/cmdline','rb').read().decode();"
            "print(json.dumps(data.strip(chr(0)).split(chr(0))))",
        )
    )
    if len(actual) != 3 or actual[1:] != ["-m", "app.worker.main"]:
        raise RuntimeError("Worker PID 1 differs from its configured module")
    # Docker needs a PID column even when only command names are being checked.
    lines = runtime.docker("top", worker["Id"], "-eo", "pid,comm").splitlines()[1:]
    names = [line.split()[-1] for line in lines]
    if sum(bool(re.fullmatch(r"python(?:3(?:\.\d+)?)?", n)) for n in names) != 1 or set(
        names
    ) & set(TOOLS):
        raise RuntimeError("A scanner or an additional Python process is active")


def validate_service(legacy, config, name, container, image):
    # Compose null inherits the image value; [] explicitly clears it. Retain
    # that distinction while reusing the historical deployment's drift checks.
    spec = dict(config["services"][name])
    for key in ("command", "entrypoint"):
        if spec.get(key) is None:
            spec.pop(key, None)
    normalized = {**config, "services": {**config["services"], name: spec}}
    legacy.validate_service(normalized, name, container, image)


def preflight(runtime, args, legacy):
    version = runtime.docker("compose", "version", "--short")
    numbers = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
    if not numbers or tuple(map(int, numbers.groups())) < (2, 24, 4):
        raise RuntimeError("Compose 2.24.4 or newer is required for safe port replacement")
    infos = {
        name: runtime.inspect("ccvm-" + name)
        for name in ("backend", "worker", "frontend", "postgres")
    }
    infos["edge"] = runtime.inspect("haproxy-edge")
    for name, expected in (
        ("backend", args.backend_image),
        ("worker", args.worker_image),
        ("frontend", args.frontend_image),
        ("edge", args.edge_image),
    ):
        info = infos[name]
        if info["Image"] != expected or not info["State"]["Running"] or info["State"]["Paused"]:
            raise RuntimeError(f"Confirmed {name} image/container state changed")
        if name != "edge":
            labels = info["Config"].get("Labels", {})
            if labels.get("com.docker.compose.project") != "ccvm" or labels.get(
                "com.docker.compose.project.working_dir"
            ) != str(runtime.root):
                raise RuntimeError("Application Compose project identity changed")
    for name in ("backend", "worker"):
        binds = [m["Source"] for m in infos[name]["Mounts"] if m["Destination"] == "/app"]
        if binds != [str(runtime.root / "backend")]:
            raise RuntimeError("Application source bind changed")
        if any(env_map(infos[name]).get(key) for key in AUDIT_KEYS):
            raise RuntimeError("An existing audit credential configuration is retained")
    policy = env_map(infos["worker"]).get("CCVM_NETWORK_ALLOWED_CIDRS")
    if not policy or env_map(infos["backend"]).get("CCVM_NETWORK_ALLOWED_CIDRS") != policy:
        raise RuntimeError("Backend/worker scanner scope is absent or differs")
    worker_identity(runtime, infos["worker"])
    workers = runtime.docker("ps", "--format", "{{.Names}}").splitlines()
    if [n for n in workers if n.startswith("ccvm-worker")] != ["ccvm-worker"]:
        raise RuntimeError("Expected exactly the confirmed worker")
    if "ccvm-audit-gateway" in runtime.docker("ps", "-a", "--format", "{{.Names}}").splitlines():
        raise RuntimeError("An existing audit gateway is retained")
    current = json.loads(
        runtime.docker(
            "exec", "--workdir", "/app", infos["worker"]["Id"], "python", "-c", STATE_CODE
        )
    )
    validate_state(current, OLD_REVISION)
    database_identity(current, infos["postgres"])
    config = json.loads(runtime.compose("config", "--format", "json"))
    if "audit-gateway" in config["services"]:
        raise RuntimeError("An existing audit gateway service is retained")
    for name in ("backend", "worker", "frontend"):
        validate_service(legacy, config, name, infos[name], runtime.inspect(infos[name]["Image"]))
    names = set(infos["worker"]["NetworkSettings"]["Networks"]) & set(
        infos["postgres"]["NetworkSettings"]["Networks"]
    )
    if len(names) != 1:
        raise RuntimeError("Expected one application/PostgreSQL network")
    network = next(iter(names))
    if {config["networks"][n]["name"] for n in config["services"]["backend"]["networks"]} != {
        network
    }:
        raise RuntimeError("Backend network differs from the verified database network")
    net = runtime.inspect(network)
    address = runtime.ingress.gateway_address(net)
    path, edge_file = mounted_file(runtime, infos["edge"], "/usr/local/etc/haproxy/haproxy.cfg")
    _, frontend_file = mounted_file(runtime, infos["frontend"], "/etc/nginx/conf.d/default.conf")
    edge_source = base64.b64decode(edge_file["data"]).decode()
    runtime.ingress.ingress_frontends(edge_source)
    master = runtime.docker(
        "exec", infos["edge"]["Id"], "sh", "-c", "tr '\\0' ' ' </proc/1/cmdline"
    )
    if not re.search(r"(?:^|\s)-W(?:s)?(?:\s|$)", master) and not re.search(
        r"^\s*master-worker\b", edge_source, re.M
    ):
        raise RuntimeError("HAProxy is not in master-worker reload mode")
    certs = [
        m
        for m in infos["edge"]["Mounts"]
        if m["Destination"] == "/usr/local/etc/haproxy/certs"
        and m["Type"] == "bind"
        and not m["RW"]
    ]
    if len(certs) != 1:
        raise RuntimeError("Expected the existing read-only certificate directory")
    certificate = str(Path(certs[0]["Source"]) / args.certificate)
    for flags in (("-checkhost", args.hostname), ("-checkend", "86400")):
        run([*runtime.privileged, "openssl", "x509", "-in", certificate, "-noout", *flags])
    port = runtime.ingress.free_tls_port(edge_source)
    if not port:
        raise RuntimeError("No unused internal TLS listener in the reviewed range")
    identities = runtime.docker("top", infos["edge"]["Id"], "-eo", "pid,uid,gid,comm").splitlines()[
        1:
    ]
    pairs = {
        tuple(map(int, line.split()[1:3])) for line in identities if line.split()[-1] == "haproxy"
    }
    nonroot = {pair for pair in pairs if pair[0] != 0}
    if len(nonroot) > 1 or not pairs:
        raise RuntimeError("HAProxy worker identity is ambiguous")
    uid, gid = next(iter(nonroot or pairs))
    runtime.docker(
        "exec",
        "--user",
        f"{uid}:{gid}",
        infos["edge"]["Id"],
        "test",
        "-x",
        "/usr/local/etc/haproxy/certs",
    )
    socket_dir = str(Path(certs[0]["Source"]) / runtime.ingress.SOCKET_DIRECTORY)
    if inspect_optional(runtime, socket_dir):
        # Reaching this branch means an unrelated directory already exists.
        raise RuntimeError("Existing audit socket directory is retained")
    return {
        "originals": infos,
        "compose": config,
        "network": network,
        "gateway_address": address,
        "edge_path": str(path),
        "edge_original": edge_file,
        "frontend_original": frontend_file,
        "certificate_dir": certs[0]["Source"],
        "socket_dir": socket_dir,
        "tls_port": port,
        "socket_gid": gid,
        "scanner_policy": policy,
    }


def inspect_optional(runtime, path):
    result = subprocess.run(
        [*runtime.privileged, "test", "-e", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError("Could not inspect deployment path")
    if result.returncode == 0:
        return True
    # A dangling symlink must also be retained, not replaced by our socket path.
    result = subprocess.run([*runtime.privileged, "test", "-L", str(path)], check=False)
    return result.returncode == 0


def build_artifacts(runtime, operation):
    backup = Path(operation["backup"])
    archive = run(
        ["git", "-C", str(runtime.root), "archive", runtime.target, "backend", "frontend"]
    )
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(backup / "release", filter="data")
    backend = backup / "release/backend"
    operation["backend_source"] = str(backend)
    images = {"frontend": operation["originals"]["frontend"]["Image"]}
    for name in ("backend", "worker"):
        base = operation["originals"][name]["Image"]
        print(f"Building {name} dependencies on the confirmed image...", flush=True)
        base_tag = f"ccvm-audit-base-{name}:" + base.split(":")[1][:12]
        tag = f"ccvm-audit-{name}:" + runtime.target[:12]
        runtime.docker("tag", base, base_tag)
        runtime.docker(
            "build",
            "--pull=false",
            "--file",
            str(backend / "Dockerfile.authenticated-runtime"),
            "--build-arg",
            f"CCVM_RUNTIME_BASE={base_tag}",
            "--tag",
            tag,
            str(backend),
            timeout=600,
        )
        images[name] = runtime.inspect(tag)["Id"]
    code = "NAMES=" + repr(TOOLS) + "\n" + FINGERPRINT_CODE
    original = runtime.docker(
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--workdir",
        "/tmp",
        "--entrypoint",
        "python",
        operation["originals"]["worker"]["Image"],
        "-I",
        "-c",
        code,
    )
    upgraded = runtime.docker(
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--workdir",
        "/tmp",
        "--entrypoint",
        "python",
        images["worker"],
        "-I",
        "-c",
        code,
    )
    if json.loads(original) != json.loads(upgraded):
        raise RuntimeError("A confirmed scanner binary changed")
    operation["scanner_hashes"] = json.loads(upgraded)
    frontend = backup / "release/frontend"
    print("Building the reviewed frontend...", flush=True)
    runtime.docker(
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
        "umask 022; npm ci --no-fund && npm audit --audit-level=high && "
        "npm run build && node tests/check-build.mjs dist /api/v1",
        timeout=600,
    )
    if not (frontend / "dist/index.html").is_file():
        raise RuntimeError("Frontend build is incomplete")
    operation["images"] = images
    operation["built_frontend"] = str(frontend / "dist")


def database_environment(operation):
    values = env_map(operation["originals"]["worker"])
    allowed = {"DATABASE_URL", "DB_HOST", "DB_NAME", "DB_USER", "DB_PASS", "DB_PORT"}
    entries = [
        f"{name}={value}"
        for name, value in values.items()
        if name in allowed or name.startswith("PG")
    ]
    if any(any(char in entry for char in "\r\n\0") for entry in entries):
        raise RuntimeError("Database environment is not representable as a private env-file")
    private_write(Path(operation["backup"]) / "database.env", ("\n".join(entries) + "\n").encode())


def backup_database(runtime, operation):
    print("Saving and checking the private PostgreSQL backup...", flush=True)
    destination = Path(operation["attempt_dir"]) / "database.dump"
    with destination.open("xb") as output:
        result = subprocess.run(
            [
                *runtime.prefix,
                "exec",
                "ccvm-postgres",
                "sh",
                "-c",
                'exec pg_dump --format=custom --no-password -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
            ],
            stdout=output,
            stderr=subprocess.PIPE,
            timeout=600,
            check=False,
        )
        output.flush()
        os.fsync(output.fileno())
    if result.returncode or destination.stat().st_size < 100:
        raise RuntimeError("PostgreSQL backup did not complete; original services retained")
    with destination.open("rb") as stream:
        checked = subprocess.run(
            [*runtime.prefix, "exec", "-i", "ccvm-postgres", "pg_restore", "--list"],
            stdin=stream,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    if checked.returncode or not checked.stdout.strip():
        raise RuntimeError("PostgreSQL backup could not be inspected")


def verify_resolved(runtime, operation, legacy):
    resolved = json.loads(runtime.compose("config", "--format", "json", extra=True))
    before = operation["compose"]
    if set(resolved["services"]) != set(before["services"]) | {"audit-gateway"}:
        raise RuntimeError("An unrelated Compose service was added or removed")
    private = Path(operation["private"])
    vault = read_env(private / "vault.env")
    operator = read_env(private / "operator.env")
    for name, spec in before["services"].items():
        expected = dict(spec)
        if name in {"backend", "worker", "frontend"}:
            expected.update(image=operation["images"][name], pull_policy="never")
        if name in {"backend", "worker"}:
            expected["environment"] = {
                **expected.get("environment", {}),
                **vault,
                **(operator if name == "backend" else {}),
            }
        if name in {"backend", "frontend"}:
            target, port = (8000, "8088") if name == "backend" else (80, "8090")
            expected["ports"] = [
                {
                    "target": target,
                    "published": port,
                    "host_ip": "127.0.0.1",
                    "protocol": "tcp",
                    "mode": "ingress",
                }
            ]
        if name == "backend":
            expected["command"] = [
                "uvicorn",
                "app.main:app",
                "--host",
                "0.0.0.0",
                "--port",
                "8000",
                "--proxy-headers",
                "--forwarded-allow-ips",
                operation["gateway_address"],
            ]
        if resolved["services"][name] != expected:
            raise RuntimeError(f"{name}: resolved override changed an unrelated setting")
    # Configuration source and static mounts must remain exactly the originals.
    return resolved


def wait_application(runtime, operation):
    for attempt in range(60):
        try:
            for port in (8088, 8090):
                with runtime.opener.open(
                    f"http://127.0.0.1:{port}/api/v1/network-scans/capabilities", timeout=5
                ) as response:
                    data = json.load(response)
                expected = [
                    str(ipaddress.ip_network(n.strip()))
                    for n in operation["scanner_policy"].split(",")
                ]
                if not data["enabled"] or data["allowed_cidrs"] != expected:
                    raise RuntimeError("Scanner policy changed")
            return
        except (OSError, ValueError):
            if attempt == 10:
                runtime.docker("exec", "ccvm-frontend", "nginx", "-s", "reload")
            time.sleep(1)
    raise RuntimeError("Application API/proxy did not become healthy")


def verify_runtime(runtime, operation, legacy):
    validate_secrets(Path(operation["private"]), operation)
    resolved = verify_resolved(runtime, operation, legacy)
    for name in ("backend", "worker", "frontend", "audit-gateway"):
        container = runtime.inspect("ccvm-" + name)
        image = operation["images"]["frontend" if name == "audit-gateway" else name]
        if (
            container["Image"] != image
            or not container["State"]["Running"]
            or container["State"]["Paused"]
            or container["State"].get("Restarting", False)
        ):
            raise RuntimeError(
                f"{name}: replacement container is not healthy; inspect startup logs"
            )
        if name == "audit-gateway":
            if set(container["HostConfig"].get("Tmpfs", {})) != {
                "/var/cache/nginx",
                "/var/run",
                "/tmp",
            }:
                raise RuntimeError("Gateway temporary mounts changed")
            container = {
                **container,
                "Mounts": [m for m in container["Mounts"] if m["Type"] != "tmpfs"],
            }
        validate_service(legacy, resolved, name, container, runtime.inspect(image))
    for name in ("backend", "worker"):
        values = env_map(runtime.inspect("ccvm-" + name))
        expected = read_env(Path(operation["private"]) / "vault.env")["CCVM_AUDIT_VAULT_KEY"]
        if (
            values.get("CCVM_AUDIT_VAULT_KEY") != expected
            or values.get("CCVM_NETWORK_ALLOWED_CIDRS") != operation["scanner_policy"]
        ):
            raise RuntimeError("Runtime vault key or scanner policy differs")
        if name == "worker" and values.get("CCVM_AUDIT_OPERATOR_TOKEN"):
            raise RuntimeError("Operator token must not be passed to the worker")
    wait_application(runtime, operation)
    request = Request(
        "http://127.0.0.1:8088/api/v1/host-audits?customer_id=1",
        headers={"X-Forwarded-Proto": "https"},
    )
    try:
        with runtime.opener.open(request, timeout=5):
            raise RuntimeError("Direct HTTP spoof unexpectedly reached authenticated endpoints")
    except HTTPError as error:
        if error.code != 403:
            raise RuntimeError("Direct HTTP proxy-header guard failed") from None
    gateway = runtime.inspect("ccvm-audit-gateway")
    if (
        gateway["NetworkSettings"]["Networks"][operation["network"]]["IPAddress"]
        != operation["gateway_address"]
    ):
        raise RuntimeError("Trusted gateway address changed")
    observed = json.loads(
        runtime.docker(
            "exec",
            "--workdir",
            "/tmp",
            "ccvm-worker",
            "python",
            "-I",
            "-c",
            "NAMES=" + repr(TOOLS) + "\n" + FINGERPRINT_CODE,
        )
    )
    if observed != operation["scanner_hashes"]:
        raise RuntimeError("A scanner executable changed")


def edge_install(runtime, operation, desired):
    current = runtime.root_io({"action": "read", "path": operation["edge_path"]})
    content = base64.b64decode(current["data"])
    original = base64.b64decode(operation["edge_original"]["data"])
    proposed = Path(operation["backup"]) / "haproxy.proposed.cfg"
    valid = {original, proposed.read_bytes()}
    if content not in valid:
        raise RuntimeError("HAProxy configuration changed outside this deployment")
    if content != desired:
        runtime.root_io(
            {
                "action": "inplace",
                "path": operation["edge_path"],
                "ino": operation["edge_original"]["ino"],
                "dev": operation["edge_original"]["dev"],
                "before": hashlib.sha256(content).hexdigest(),
                "data": base64.b64encode(desired).decode(),
            }
        )
    mounted = runtime.docker(
        "exec", "haproxy-edge", "sha256sum", "/usr/local/etc/haproxy/haproxy.cfg"
    ).split()[0]
    if mounted != hashlib.sha256(desired).hexdigest():
        raise RuntimeError("HAProxy bind did not observe the new configuration")
    runtime.reload_edge()


def candidate_edge(runtime, operation):
    """Validate with the actual edge image, mounts and environment before downtime."""
    candidate = Path(operation["backup"]) / "haproxy.proposed.cfg"
    path = "/tmp/ccvm-audit-" + operation["target"][:12] + ".cfg"
    runtime.docker(
        "exec",
        "-i",
        "--user",
        "0",
        "haproxy-edge",
        "sh",
        "-c",
        'umask 077; cat > "$1"',
        "sh",
        path,
        data=candidate.read_bytes(),
    )
    try:
        runtime.docker("exec", "--user", "0", "haproxy-edge", "haproxy", "-c", "-f", path)
    finally:
        runtime.docker("exec", "--user", "0", "haproxy-edge", "rm", "-f", path)


def retained_config(operation):
    return {
        name: base64.b64decode(value) if value is not None else None
        for name, value in operation["configs"].items()
    }


def assert_retained(runtime, operation):
    assert_config(runtime.root, retained_config(operation))
    current = json.loads(runtime.compose("config", "--format", "json"))
    if current != operation["compose"]:
        raise RuntimeError("Resolved original Compose configuration changed")
    for name in ("postgres", "edge"):
        actual = runtime.inspect("ccvm-postgres" if name == "postgres" else "haproxy-edge")
        if (
            actual["Id"] != operation["originals"][name]["Id"]
            or actual["Image"] != operation["originals"][name]["Image"]
        ):
            raise RuntimeError("A retained database/edge container was replaced")
    for name, identity in operation["unrelated"].items():
        if runtime.inspect(name)["Id"] != identity:
            raise RuntimeError("An unrelated container changed during deployment")


def write_phase(marker, operation, phase):
    operation["phase"] = phase
    write_json(marker, operation)


def restore_original_services(runtime, operation):
    # Used only before any migration attempt; never recreate or downgrade data.
    for name in ("worker", "backend"):
        info = runtime.inspect("ccvm-" + name)
        if info["Id"] != operation["originals"][name]["Id"]:
            raise RuntimeError("Original application container changed")
        if info["State"]["Paused"]:
            runtime.docker("unpause", info["Id"])
        if not info["State"]["Running"]:
            runtime.docker("start", info["Id"])


def close_application(runtime):
    backend = runtime.inspect("ccvm-backend")
    if backend["State"]["Running"]:
        runtime.docker("stop", "--time", "20", backend["Id"])
    worker = runtime.inspect("ccvm-worker")
    if worker["State"]["Paused"]:
        runtime.docker("unpause", worker["Id"])
    if worker["State"]["Running"]:
        runtime.docker("stop", "--time", "20", worker["Id"])
    if any(runtime.inspect("ccvm-" + name)["State"]["Running"] for name in ("backend", "worker")):
        raise RuntimeError("Application did not stop; migration refused")


def quiesce(runtime, operation, marker):
    print("Closing API submissions and quiescing the idle worker...", flush=True)
    worker = runtime.inspect("ccvm-worker")
    if worker["State"]["Running"] and not worker["State"]["Paused"]:
        runtime.docker("pause", worker["Id"])
    # API closes before the idle worker is allowed to stop. A job admitted during
    # preflight is preserved and makes this operation fail without migrating.
    backend = runtime.inspect("ccvm-backend")
    if backend["State"]["Running"]:
        runtime.docker("stop", "--time", "20", backend["Id"])
    for attempt in range(5):
        before = runtime.state(operation)
        validate_state(before, OLD_REVISION)
        if not before["transactions"]:
            break
        # A pause can catch an idle worker between its SELECT and session close.
        # With the API closed and no queued work, let that transaction finish.
        if attempt == 4:
            raise RuntimeError("Open database transactions retained")
        runtime.docker("unpause", worker["Id"])
        time.sleep(0.3)
        runtime.docker("pause", worker["Id"])
    close_application(runtime)
    stopped = runtime.state(operation)
    validate_state(stopped, OLD_REVISION)
    if stopped["transactions"] or stopped["tables"] != before["tables"]:
        raise RuntimeError("Database changed while quiescing")
    attempt = Path(tempfile.mkdtemp(prefix="attempt-", dir=operation["backup"]))
    operation["attempt_dir"] = str(attempt)
    operation["before"] = stopped
    write_json(attempt / "before.json", stopped)
    backup_database(runtime, operation)
    write_phase(marker, operation, "quiesced")


def recover_failure(runtime, operation, marker):
    """Never roll back migrated data or overwrite a concurrent edge edit."""
    phase = operation["phase"]
    if phase in {"prepared", "built", "quiesced"}:
        restore_original_services(runtime, operation)
        if phase == "quiesced":
            write_phase(marker, operation, "built")
        return
    try:
        original = base64.b64decode(operation["edge_original"]["data"])
        current = runtime.root_io({"action": "read", "path": operation["edge_path"]})
        proposed = (Path(operation["backup"]) / "haproxy.proposed.cfg").read_bytes()
        if base64.b64decode(current["data"]) == proposed:
            edge_install(runtime, operation, original)
    finally:
        close_application(runtime)


def new_operation(runtime, args, legacy, marker):
    if os.path.lexists(runtime.root / OVERRIDE):
        raise RuntimeError("Existing authenticated override retained")
    initial = preflight(runtime, args, legacy)
    backup = Path(tempfile.mkdtemp(prefix="ccvm-authenticated-before-", dir=marker.parent))
    configs = capture_config(runtime.root)
    operation = {
        **initial,
        "target": runtime.target,
        "hostname": args.hostname,
        "clients": args.clients,
        "certificate": args.certificate,
        "host": args.host,
        "backup": str(backup),
        "private": str(marker.parent / SECRET_DIRECTORY),
        "phase": "prepared",
        "pins": {
            name: getattr(args, name + "_image")
            for name in ("backend", "worker", "frontend", "edge")
        },
        "configs": {
            name: base64.b64encode(value).decode() if value is not None else None
            for name, value in configs.items()
        },
    }
    names = runtime.docker("ps", "-a", "--format", "{{.Names}}").splitlines()
    related = {"ccvm-backend", "ccvm-worker", "ccvm-frontend", "haproxy-edge"}
    operation["unrelated"] = {
        name: runtime.inspect(name)["Id"] for name in names if name not in related
    }
    private_write(
        backup / "haproxy.original.cfg", base64.b64decode(operation["edge_original"]["data"])
    )
    source = runtime.ingress.render_haproxy(
        base64.b64decode(operation["edge_original"]["data"]).decode(),
        args.hostname,
        args.clients,
        "/usr/local/etc/haproxy/certs/" + args.certificate,
        "/usr/local/etc/haproxy/certs/" + runtime.ingress.SOCKET_DIRECTORY + "/gateway.sock",
        operation["tls_port"],
        runtime.target[:12],
    )
    private_write(backup / "haproxy.proposed.cfg", source.encode())
    database_environment(operation)
    write_json(marker, operation)
    return operation


def validate_journal(runtime, args, operation, marker):
    expected = {
        "target": runtime.target,
        "hostname": args.hostname,
        "clients": args.clients,
        "certificate": args.certificate,
        "host": args.host,
        "pins": {
            name: getattr(args, name + "_image")
            for name in ("backend", "worker", "frontend", "edge")
        },
    }
    if any(operation.get(k) != v for k, v in expected.items()):
        raise RuntimeError("Retained deployment parameters differ; no changes performed")
    backup = Path(operation["backup"])
    if backup.parent != marker.parent or not backup.name.startswith("ccvm-authenticated-before-"):
        raise RuntimeError("Unexpected retained backup path")
    for path in (backup, Path(operation["private"]), marker):
        if path.is_symlink() or (
            path.exists() and (path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077)
        ):
            raise RuntimeError("Retained private deployment permissions changed")
    if Path(operation["private"]) != marker.parent / SECRET_DIRECTORY:
        raise RuntimeError("Unexpected retained secret path")
    assert_retained(runtime, operation)


def activate(runtime, args, legacy, marker, operation):
    backup = Path(operation["backup"])
    runtime.diagnostic = backup / "last-command.log"
    private = Path(operation["private"])
    if operation["phase"] == "verified":
        verify_runtime(runtime, operation, legacy)
        if runtime.state(operation)["revision"] != REVISION:
            raise RuntimeError("Installed schema changed")
        desired = (backup / "haproxy.proposed.cfg").read_bytes()
        if (
            base64.b64decode(
                runtime.root_io({"action": "read", "path": operation["edge_path"]})["data"]
            )
            != desired
        ):
            raise RuntimeError("Installed edge configuration changed")
        runtime.tls_probe(operation)
        print("VERIFIED: authenticated inventory already deployed; existing jobs retained.")
        return
    if operation["phase"] == "prepared":
        build_artifacts(runtime, operation)
        make_secrets(private, operation)
        private_write(
            private / "gateway.conf",
            runtime.ingress.render_gateway(args.hostname, args.clients).encode(),
        )
        operation["gateway_hash"] = hashlib.sha256(
            (private / "gateway.conf").read_bytes()
        ).hexdigest()
        candidate_edge(runtime, operation)
        write_phase(marker, operation, "built")
    validate_secrets(private, operation)
    if (
        hashlib.sha256((private / "gateway.conf").read_bytes()).hexdigest()
        != operation["gateway_hash"]
    ):
        raise RuntimeError("Retained gateway configuration changed")
    if operation["phase"] == "built":
        source_plan(runtime.root, runtime.target, resume=True)
        assert_retained(runtime, operation)
        for name in ("backend", "worker", "frontend"):
            if runtime.inspect("ccvm-" + name)["Id"] != operation["originals"][name]["Id"]:
                raise RuntimeError("Original application container changed before migration")
        quiesce(runtime, operation, marker)
    if operation["phase"] in {"quiesced", "migrating"}:
        close_application(runtime)
        state = runtime.state(operation)
        if state["revision"] == OLD_REVISION:
            validate_state(state, OLD_REVISION)
            if state["tables"] != operation["before"]["tables"] or state["transactions"]:
                raise RuntimeError("Quiesced database changed; migration refused")
            write_phase(marker, operation, "migrating")
            print("Applying the additive inventory migration...", flush=True)
            runtime.helper(
                operation,
                "from alembic import command\nfrom alembic.config import Config\n"
                "config=Config('/app/alembic.ini')\nconfig.set_main_option('script_location','/app/alembic')\n"
                f"command.upgrade(config,{REVISION!r})",
            )
            state = runtime.state(operation)
        validate_state(state, REVISION)
        assert_preserved(operation["before"], state)
        write_json(Path(operation["attempt_dir"]) / "after.json", state)
        write_phase(marker, operation, "migrated")
    if operation["phase"] == "migrated":
        close_application(runtime)
        source_plan(runtime.root, runtime.target, resume=True)
        if git(runtime.root, "rev-parse", "HEAD") != runtime.target:
            git(runtime.root, "merge", "--ff-only", runtime.target)
        write_phase(marker, operation, "source")
    if operation["phase"] == "source":
        print("Publishing reviewed source, frontend and private runtime settings...", flush=True)
        close_application(runtime)
        override = runtime.ingress.render_override(
            operation["images"],
            str(private),
            operation["socket_dir"],
            operation["gateway_address"],
            str(runtime.root / "frontend/dist"),
        )
        if (
            os.path.lexists(runtime.root / OVERRIDE)
            and (runtime.root / OVERRIDE).read_text() != override
        ):
            raise RuntimeError("Authenticated override changed during recovery")
        private_write(runtime.root / OVERRIDE, override.encode())
        verify_resolved(runtime, operation, legacy)
        runtime.root_io(
            {
                "action": "socket-dir",
                "path": operation["socket_dir"],
                "gid": operation["socket_gid"],
            }
        )
        legacy.BACKEND_IMAGE = operation["images"]["backend"]
        legacy.publish_frontend(runtime, runtime.root, Path(operation["built_frontend"]))
        write_phase(marker, operation, "published")
    if operation["phase"] == "published":
        print("Starting the prepared application containers...", flush=True)
        runtime.compose(
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            "backend",
            "worker",
            "frontend",
            "audit-gateway",
            extra=True,
        )
        write_phase(marker, operation, "services")
    if operation["phase"] in {"services", "edge"}:
        print("Verifying application, TLS, client allowlist and operator access...", flush=True)
        # A prior failure closed these same new containers. Reconcile, never
        # submit a scan or touch database rows during recovery.
        runtime.compose(
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            "backend",
            "worker",
            "frontend",
            "audit-gateway",
            extra=True,
        )
        verify_runtime(runtime, operation, legacy)
        assert_retained(runtime, operation)
        edge_install(runtime, operation, (backup / "haproxy.proposed.cfg").read_bytes())
        write_phase(marker, operation, "edge")
        runtime.tls_probe(operation)
        with runtime.opener.open("http://127.0.0.1:8090/", timeout=5) as response:
            if response.read() != (Path(operation["built_frontend"]) / "index.html").read_bytes():
                raise RuntimeError("Published frontend does not match the reviewed build")
        write_phase(marker, operation, "verified")
    if operation["phase"] != "verified":
        raise RuntimeError("Unknown retained deployment phase")
    print(
        "VERIFIED: HTTPS, client allowlist, operator access, migration and scanner policy "
        f"at {runtime.target}"
    )
    print(f"Private recovery material: {backup}")
    print(f"Operator token file (local access only): {private/'operator.env'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--client-cidrs", required=True)
    parser.add_argument(
        "--certificate",
        required=True,
        help="Existing certificate basename, not private key contents",
    )
    for name in ("backend", "worker", "frontend", "edge"):
        parser.add_argument("--" + name + "-image", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if socket.gethostname().split(".")[0] != args.host:
        raise RuntimeError("Unexpected deployment host")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+\.pem", args.certificate) or args.certificate.startswith(
        "."
    ):
        raise RuntimeError("Select one existing certificate basename")
    if any(
        not re.fullmatch(r"sha256:[a-f0-9]{64}", getattr(args, n + "_image"))
        for n in ("backend", "worker", "frontend", "edge")
    ):
        raise RuntimeError("Use the confirmed immutable container image IDs")
    root = Path.cwd().resolve()
    source_plan(root, args.target, resume=args.resume)
    ingress = load_helper(
        root, args.target, "scripts/authenticated_ingress.py", "ccvm_auth_ingress"
    )
    legacy = load_helper(
        root, args.target, "scripts/deploy-network-scans.py", "ccvm_deployment_legacy"
    )
    args.hostname, args.clients = ingress.selection(args.hostname, args.client_cidrs.split(","))
    runtime = Runtime(root, args.target, ingress)
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    runtime.diagnostic = directory / "ccvm-authenticated-preflight.log"
    descriptor = os.open(
        directory / "ccvm-authenticated.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = directory / JOURNAL
        print(
            f"CCVM authenticated inventory deployment {VERSION}; reviewed target {args.target}",
            flush=True,
        )
        if not args.apply:
            preflight(runtime, args, legacy)
            print("PREFLIGHT OK; no changes performed.")
            return
        if os.path.lexists(marker):
            if marker.is_symlink():
                raise RuntimeError("Deployment journal is a symlink")
            operation = json.loads(marker.read_text())
            validate_journal(runtime, args, operation, marker)
            if operation["phase"] != "verified" and not args.resume:
                raise RuntimeError("Retained incomplete deployment requires --resume")
        else:
            operation = new_operation(runtime, args, legacy, marker)
        print(f"Private backup: {operation['backup']}", flush=True)
        try:
            activate(runtime, args, legacy, marker, operation)
        except BaseException:
            if operation["phase"] != "verified":
                try:
                    recover_failure(runtime, operation, marker)
                except BaseException:
                    print(
                        "Recovery requires inspection of the retained private journal.", flush=True
                    )
            print(
                f"Deployment stopped at {operation['phase']}; "
                f"retain {operation['backup']}; rerun with --resume.",
                flush=True,
            )
            raise


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(f"STOPPED: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from None
