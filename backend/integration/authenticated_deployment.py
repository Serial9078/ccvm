"""Deploy the real operator against disposable Docker services in GitHub Actions.

This job has its own runner and PostgreSQL container. It never accepts a database
URL, target hostname, image pin, credential or network from a production system.
"""

import contextlib
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent
HOSTNAME = "ccvm.example.test"
CLIENTS = "192.0.2.0/24,198.51.100.0/24"
TOKEN_NAMES = ("CCVM_AUDIT_OPERATOR_TOKEN", "CCVM_AUDIT_VAULT_KEY")


def run(*args, cwd=None, data=None, timeout=600, success=True):
    result = subprocess.run(
        args, cwd=cwd, input=data, capture_output=True, timeout=timeout, check=False
    )
    if success and result.returncode:
        raise AssertionError(
            f"Fixture command {args[:2]} failed: " + result.stderr.decode(errors="replace")[-3000:]
        )
    return result


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs).stdout.decode().strip()


def load_operator():
    spec = importlib.util.spec_from_file_location(
        "authenticated_deployment", REPOSITORY / "scripts/deploy-authenticated-inventory.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect(name):
    return json.loads(docker("inspect", "--format", "{{json .}}", name))


def execute(source, target, pins, *, apply=False):
    argv = [
        sys.executable,
        "-",
        "--target",
        target,
        "--host",
        socket.gethostname().split(".")[0],
        "--hostname",
        HOSTNAME,
        "--client-cidrs",
        CLIENTS,
        "--certificate",
        "test.pem",
        "--resume",
    ]
    for name, image in pins.items():
        argv.extend(["--" + name + "-image", image])
    if apply:
        argv.append("--apply")
    result = run(
        *argv,
        cwd=source,
        data=(REPOSITORY / "scripts/deploy-authenticated-inventory.py").read_bytes(),
        success=False,
        timeout=900,
    )
    print(result.stdout.decode(), flush=True)
    print(result.stderr.decode(), flush=True)
    return result


def fixture_compose(source, image, nginx):
    def service(name, command):
        return {
            "image": image,
            "container_name": "ccvm-" + name,
            "working_dir": "/app",
            "restart": "unless-stopped",
            "command": command,
            "environment": {
                "DB_HOST": "postgres",
                "DB_USER": "ccvm_ci",
                "DB_NAME": "ccvm_ci",
                "DB_PASS": "synthetic_ci_password",
                "CCVM_NETWORK_ALLOWED_CIDRS": "192.0.2.0/24",
            },
            "volumes": [str(source / "backend") + ":/app"],
        }

    backend = service("backend", ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"])
    backend["ports"] = ["8088:8000"]
    worker = service("worker", ["python", "-m", "app.worker.main"])
    # Exercise append semantics: a retained private env_file must survive.
    worker["env_file"] = [str(source / "fixture.env")]
    frontend = {
        "image": nginx,
        "container_name": "ccvm-frontend",
        "restart": "unless-stopped",
        "ports": ["8090:80"],
        "volumes": [
            str(source / "frontend/default.conf") + ":/etc/nginx/conf.d/default.conf:ro",
            str(source / "frontend/dist") + ":/usr/share/nginx/html:ro",
        ],
    }
    return {
        "services": {
            "backend": backend,
            "worker": worker,
            "frontend": frontend,
            "postgres": {
                "image": "postgres:16-alpine",
                "container_name": "ccvm-postgres",
                "environment": {
                    "POSTGRES_DB": "ccvm_ci",
                    "POSTGRES_USER": "ccvm_ci",
                    "POSTGRES_PASSWORD": "synthetic_ci_password",
                },
            },
        }
    }


def compose(source, *args, extra=False):
    argv = [
        "compose",
        "--project-directory",
        str(source),
        "--project-name",
        "ccvm",
        "--file",
        str(source / "docker-compose.yml"),
        "--file",
        str(source / "docker-compose.network.yml"),
    ]
    if extra:
        argv.extend(["--file", str(source / "docker-compose.authenticated.yml")])
    return docker(*argv, *args)


def certificate(directory):
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "7",
        "-subj",
        "/CN=Disposable CCVM CI CA",
        "-keyout",
        str(directory / "ca.key"),
        "-out",
        str(directory / "ca.crt"),
    )
    run(
        "openssl",
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=" + HOSTNAME,
        "-keyout",
        str(directory / "leaf.key"),
        "-out",
        str(directory / "leaf.csr"),
    )
    (directory / "ext.cnf").write_text(
        "subjectAltName=DNS:ccvm.example.test,DNS:old.example.test\n"
    )
    run(
        "openssl",
        "x509",
        "-req",
        "-in",
        str(directory / "leaf.csr"),
        "-CA",
        str(directory / "ca.crt"),
        "-CAkey",
        str(directory / "ca.key"),
        "-CAcreateserial",
        "-days",
        "7",
        "-extfile",
        str(directory / "ext.cnf"),
        "-out",
        str(directory / "leaf.crt"),
    )
    certs = directory / "certs"
    certs.mkdir()
    (certs / "test.pem").write_bytes(
        (directory / "leaf.key").read_bytes() + (directory / "leaf.crt").read_bytes()
    )
    return certs


def legacy_edge():
    return """global
    master-worker
    user haproxy
    group haproxy
defaults
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s
frontend fe_http
    bind *:80
    mode http
    http-request return status 200 content-type text/plain string old-http
frontend fe_tls
    bind *:443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend old_app if { req.ssl_sni -i old.example.test }
    default_backend old_app
backend old_app
    mode tcp
    server old 127.0.0.1:4447
frontend old_https
    bind 127.0.0.1:4447 ssl crt /usr/local/etc/haproxy/certs/test.pem
    mode http
    http-request return status 200 content-type text/plain string old-application
"""


def old_application(image):
    code = """import http.client,socket,ssl
context=ssl.create_default_context()
raw=socket.create_connection(('127.0.0.1',443))
with context.wrap_socket(raw,server_hostname='old.example.test') as s:
    s.sendall(b'GET / HTTP/1.1\\r\\nHost: old.example.test\\r\\nConnection: close\\r\\n\\r\\n')
    r=http.client.HTTPResponse(s);r.begin();assert r.status==200
    assert r.read()==b'old-application'
print('Unrelated HTTPS application retained')
"""
    print(
        docker(
            "run",
            "--rm",
            "--network",
            "container:haproxy-edge",
            "--entrypoint",
            "python",
            image,
            "-I",
            "-c",
            code,
        ),
        flush=True,
    )


def diagnostics(source):
    journal = source / ".git/ccvm-authenticated-deployment.json"
    preflight = source / ".git/ccvm-authenticated-preflight.log"
    if preflight.is_file():
        print(preflight.read_text(errors="replace")[-12000:], flush=True)
    if not journal.is_file():
        return
    state = json.loads(journal.read_text())
    private = Path(state["private"])
    output = Path(state["backup"]) / "last-command.log"
    if output.is_file():
        content = output.read_text(errors="replace")[-12000:]
        for name in ("operator.env", "vault.env"):
            if (private / name).is_file():
                for line in (private / name).read_text().splitlines():
                    if line.split("=", 1)[0] in TOKEN_NAMES:
                        content = content.replace(line.split("=", 1)[1], "[redacted]")
        print(content, flush=True)


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or not re.fullmatch(
        r"[1-9][0-9]+", os.environ.get("GITHUB_RUN_ID", "")
    ):
        raise RuntimeError("Disposable deployment integration is restricted to GitHub Actions")
    if docker("ps", "-a", "--format", "{{.Names}}").splitlines():
        raise RuntimeError("This integration requires its own empty Docker runner")
    target = run("git", "rev-parse", "HEAD", cwd=REPOSITORY).stdout.decode().strip()
    operator = load_operator()
    with tempfile.TemporaryDirectory(prefix="ccvm-auth-deploy-") as temporary:
        directory = Path(temporary)
        source = directory / "checkout"
        run("git", "clone", "--no-hardlinks", "--no-checkout", str(REPOSITORY), str(source))
        run("git", "checkout", "-B", operator.BRANCH, operator.BASE, cwd=source)
        run("git", "update-ref", "refs/remotes/origin/" + operator.BRANCH, target, cwd=source)
        certs = certificate(directory)
        # CI's private CA exists only in this disposable base image. The real
        # operator has no certificate-validation bypass or CA injection switch.
        (directory / "legacy-requirements.txt").write_bytes(
            run("git", "show", operator.BASE + ":backend/requirements.txt", cwd=source).stdout
        )
        (directory / "Dockerfile").write_text("""FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
COPY ca.crt /usr/local/share/ca-certificates/ccvm-ci.crt
RUN update-ca-certificates
COPY legacy-requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt
RUN for tool in subfinder dnsx httpx naabu katana nuclei; do \\
    printf '#!/bin/sh\\nexit 0\\n' > /usr/local/bin/$tool; \\
    chmod 755 /usr/local/bin/$tool; done
""")
        base_tag = "ccvm-ci-legacy:runtime"
        docker("build", "--tag", base_tag, str(directory))
        base = inspect(base_tag)["Id"]
        docker("pull", "nginx:alpine")
        nginx = inspect("nginx:alpine")["Id"]
        docker("pull", "haproxy:3.1-alpine")
        edge = inspect("haproxy:3.1-alpine")["Id"]
        (source / "frontend/dist").mkdir(exist_ok=True)
        (source / "frontend/dist/index.html").write_text("retained static frontend")
        (source / "frontend/default.conf").write_text("""server {
    listen 80;
    location /api/ {
        proxy_pass http://backend:8000/api/;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location /health { proxy_pass http://backend:8000/health; }
    root /usr/share/nginx/html;
}
""")
        (source / "fixture.env").write_text("CCVM_RETAINED_PRIVATE_SETTING=synthetic-env-file\n")
        (source / "docker-compose.yml").write_text(json.dumps(fixture_compose(source, base, nginx)))
        (source / "docker-compose.network.yml").write_text('{"services":{}}\n')
        edge_file = directory / "haproxy.cfg"
        edge_file.write_text(legacy_edge())
        try:
            compose(source, "up", "-d", "postgres")
            for _ in range(60):
                ready = run(
                    "docker", "exec", "ccvm-postgres", "pg_isready", "-U", "ccvm_ci", success=False
                )
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise AssertionError("Disposable PostgreSQL did not start")
            migrate = (
                "from alembic import command;from alembic.config import Config;"
                "command.upgrade(Config('/app/alembic.ini'),'" + operator.OLD_REVISION + "')"
            )
            compose(source, "run", "--rm", "--no-deps", "backend", "python", "-c", migrate)
            compose(source, "up", "-d", "--no-deps", "backend", "worker", "frontend")
            docker(
                "run",
                "-d",
                "--name",
                "haproxy-edge",
                "--user",
                "root",
                "--mount",
                f"type=bind,src={edge_file},dst=/usr/local/etc/haproxy/haproxy.cfg,readonly",
                "--mount",
                f"type=bind,src={certs},dst=/usr/local/etc/haproxy/certs,readonly",
                edge,
                "haproxy",
                "-W",
                "-db",
                "-f",
                "/usr/local/etc/haproxy/haproxy.cfg",
            )
            old_application(base)
            pins = {"backend": base, "worker": base, "frontend": nginx, "edge": edge}
            ids = {
                n: inspect(n)["Id"]
                for n in (
                    "ccvm-backend",
                    "ccvm-worker",
                    "ccvm-frontend",
                    "ccvm-postgres",
                    "haproxy-edge",
                )
            }
            bad = execute(source, target, {**pins, "worker": "sha256:" + "0" * 64}, apply=True)
            assert bad.returncode != 0
            assert not (source / ".git/ccvm-authenticated-deployment.json").exists()
            assert ids == {n: inspect(n)["Id"] for n in ids}
            checked = execute(source, target, pins)
            if checked.returncode:
                diagnostics(source)
                front = inspect("ccvm-frontend")["Config"]
                image = inspect(nginx)["Config"]
                spec = json.loads(compose(source, "config", "--format", "json"))["services"][
                    "frontend"
                ]
                print(
                    json.dumps(
                        {
                            "fixture_command_contract": {
                                "container": {k: front.get(k) for k in ("Cmd", "Entrypoint")},
                                "image": {k: image.get(k) for k in ("Cmd", "Entrypoint")},
                                "compose": {
                                    k: spec.get(k, "inherited") for k in ("command", "entrypoint")
                                },
                            }
                        }
                    ),
                    flush=True,
                )
            assert checked.returncode == 0
            original_stat = edge_file.stat()
            applied = execute(source, target, pins, apply=True)
            if applied.returncode:
                diagnostics(source)
            assert applied.returncode == 0
            assert edge_file.stat().st_ino == original_stat.st_ino
            assert edge_file.stat().st_mode == original_stat.st_mode
            assert inspect("haproxy-edge")["Id"] == ids["haproxy-edge"]
            assert inspect("ccvm-postgres")["Id"] == ids["ccvm-postgres"]
            old_application(base)
            journal = source / ".git/ccvm-authenticated-deployment.json"
            operation = json.loads(journal.read_text())
            private = Path(operation["private"])
            secrets_before = {n: (private / n).read_bytes() for n in ("vault.env", "operator.env")}
            assert (
                "CCVM_RETAINED_PRIVATE_SETTING=synthetic-env-file"
                in inspect("ccvm-worker")["Config"]["Env"]
            )
            # A local unprivileged process cannot traverse the socket directory.
            denied = run(
                "docker",
                "run",
                "--rm",
                "--user",
                "65534:65534",
                "--network",
                "none",
                "--mount",
                f"type=bind,src={operation['socket_dir']},dst=/socket,readonly",
                "--entrypoint",
                "python",
                base,
                "-I",
                "-c",
                "import socket;s=socket.socket(socket.AF_UNIX);s.connect('/socket/gateway.sock')",
                success=False,
            )
            assert denied.returncode != 0 and b"PermissionError" in denied.stderr
            # Exercise a retained post-migration interruption with real stopped
            # containers. No second schema migration or secret generation occurs.
            operation["phase"] = "services"
            operator.write_json(journal, operation)
            docker("stop", "--time", "20", "ccvm-backend", "ccvm-worker")
            resumed = execute(source, target, pins, apply=True)
            if resumed.returncode:
                diagnostics(source)
            assert resumed.returncode == 0
            assert secrets_before == {n: (private / n).read_bytes() for n in secrets_before}
            before_ids = {n: inspect(n)["Id"] for n in ids if n != "haproxy-edge"}
            assert execute(source, target, pins, apply=True).returncode == 0
            assert before_ids == {n: inspect(n)["Id"] for n in before_ids}
            assert edge_file.read_text().count("frontend ccvm_audit_https") == 1
            old_application(base)
            print(
                "VERIFIED: full deploy, real TLS/PROXY chain, ACLs, spoof rejection, "
                "loopback ports, retained services, immutable scanners, resume and idempotency",
                flush=True,
            )
        finally:
            with contextlib.suppress(Exception):
                compose(
                    source,
                    "down",
                    "--volumes",
                    "--remove-orphans",
                    extra=(source / "docker-compose.authenticated.yml").exists(),
                )
            with contextlib.suppress(Exception):
                docker("rm", "-f", "haproxy-edge")
            # Native containers legitimately create root-owned socket/tmp files.
            run(
                "sudo",
                "-n",
                "chown",
                "-R",
                f"{os.getuid()}:{os.getgid()}",
                str(directory),
                success=False,
            )
            shutil.rmtree(source / ".git/ccvm-audit-secrets", ignore_errors=True)


if __name__ == "__main__":
    main()
