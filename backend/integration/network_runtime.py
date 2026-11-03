"""Real Nmap discovery + NSE audit on an isolated SSH fixture and excluded canary."""

import ipaddress
import json
import os
import textwrap
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
SSH_SERVER = r"""
import os, socketserver, struct
def string(value):
    value = value.encode()
    return struct.pack('>I', len(value)) + value
names = ['diffie-hellman-group1-sha1', 'ssh-rsa', 'aes128-ctr', 'aes128-ctr',
         'hmac-sha1', 'hmac-sha1', 'none', 'none', '', '']
payload = b'\x14' + os.urandom(16) + b''.join(string(value) for value in names) + b'\0' * 5
padding = 8 - ((len(payload) + 5) % 8)
if padding < 4:
    padding += 8
packet = (struct.pack('>I', len(payload) + padding + 1)
          + bytes([padding]) + payload + b'\0' * padding)
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        print('accepted', flush=True)
        self.request.settimeout(3)
        try:
            self.request.sendall(b'SSH-2.0-OpenSSH_8.2\r\n')
            line = b''
            while not line.endswith(b'\n') and len(line) < 512:
                chunk = self.request.recv(1)
                if not chunk:
                    return
                line += chunk
            self.request.sendall(packet)
            self.request.recv(4096)
        except OSError:
            pass
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
with Server(('0.0.0.0', 22222), Handler) as server:
    print('ready', flush=True)
    server.serve_forever()
"""


def assert_network_runtime(command, base_image, root):
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    suffix = f"{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    image, network = f"ccvm-network-ci:{suffix}", f"ccvm-network-ci-{suffix}"
    server, canary = f"ccvm-network-ssh-{suffix}", f"ccvm-network-excluded-{suffix}"
    fixture, data = root / "network-fixture", root / "network-data"
    fixture.mkdir()
    data.mkdir()
    (fixture / "server.py").write_text(SSH_SERVER)
    command(
        "docker",
        "build",
        "--tag",
        image,
        "--file",
        str(BACKEND / "Dockerfile.network-tools"),
        "--build-arg",
        f"CCVM_WORKER_BASE={base_image}",
        str(BACKEND),
        timeout=240,
    )
    command("docker", "network", "create", "--internal", network)
    try:
        from integration.network_deployment import assert_network_deployment

        assert_network_deployment(command, image, network, root)
        for name in (server, canary):
            command(
                "docker",
                "run",
                "--detach",
                "--rm",
                "--name",
                name,
                "--network",
                network,
                "--mount",
                f"type=bind,src={fixture},dst=/fixture,readonly",
                "--entrypoint",
                "python",
                image,
                "/fixture/server.py",
            )
        for _ in range(30):
            if all("ready" in command("docker", "logs", name) for name in (server, canary)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Isolated network fixtures did not start")
        address = command(
            "docker",
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            server,
        )
        excluded = command(
            "docker",
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            canary,
        )
        scope = ipaddress.ip_network(address + "/24", strict=False)
        assert ipaddress.ip_address(excluded) in scope
        exclusions = [str(value) for value in scope.hosts() if str(value) != address]
        source = r"""
import hashlib, json, os
from sqlalchemy import event
from sqlalchemy.orm import Session
import app.models
from app.database.session import Base, engine
from app.api.v1.network_scans import start_scan, get_scan
from app.models.customer import Customer
from app.models.finding import Finding
from app.models.job import Job
from app.schemas.network_scan import NetworkScanCreate
from app.worker.main import claim_next_job, process_job
@event.listens_for(engine, 'connect')
def sha(connection, record):
    connection.create_function('sha256', 1, lambda value: hashlib.sha256(value).digest(),
                               deterministic=True)
Base.metadata.create_all(engine)
with Session(engine, autoflush=False) as db:
    customer = Customer(name='Isolated Network CI')
    db.add(customer)
    db.commit()
    payload = NetworkScanCreate(customer_id=customer.id, target=os.environ['CI_TARGET'],
        exclusions=json.loads(os.environ['CI_EXCLUSIONS']), profile='custom', ports='22222',
        rate=50, timeout_seconds=60)
    scan = start_scan(payload, db)
    assert scan['address_count'] == 1
    for index in range(2):
        job = claim_next_job(db)
        assert job is not None
        process_job(db, job)
        assert job.status == 'finished', job.message
    result = get_scan(scan['id'], db)
    assert result['status'] == 'finished' and result['open_services'] == 1
    assert result['observations'][0]['ip_address'] == os.environ['CI_ADDRESS']
    assert result['observations'][0]['services'][0]['audit_coverage'] == 'completed'
    finding = db.query(Finding).one()
    assert finding.template_id == 'nmap:ssh-legacy-kex' and finding.cve is None
    assert finding.scanner == 'network-audit' and 'diffie-hellman-group1-sha1' in finding.raw_json
    assert all(job.status == 'finished' for job in db.query(Job))
    print(json.dumps({'status': 'finished', 'network_findings': 1}), flush=True)
"""
        wrapped = (
            "import os\ntry:\n" + textwrap.indent(source, "    ") + "\nfinally:\n"
            "    for directory, subdirs, files in os.walk('/network-data'):\n"
            "        for path in [directory, *(os.path.join(directory, f) for f in files)]:\n"
            f"            os.chown(path, {os.getuid()}, {os.getgid()}, follow_symlinks=False)\n"
        )
        result = command(
            "docker",
            "run",
            "--rm",
            "--network",
            network,
            "--mount",
            f"type=bind,src={BACKEND},dst=/app,readonly",
            "--mount",
            f"type=bind,src={data},dst=/network-data",
            "--env",
            "DATABASE_URL=sqlite://",
            "--env",
            "CCVM_NETWORK_LOG_DIR=/network-data",
            "--env",
            f"CCVM_NETWORK_ALLOWED_CIDRS={scope}",
            "--env",
            f"CI_TARGET={scope}",
            "--env",
            f"CI_ADDRESS={address}",
            "--env",
            f"CI_EXCLUSIONS={json.dumps(exclusions)}",
            "--entrypoint",
            "python",
            image,
            "-B",
            "-c",
            wrapped,
            timeout=180,
        )
        assert '"network_findings": 1' in result, result[-3000:]
        assert "accepted" in command("docker", "logs", server)
        assert "accepted" not in command("docker", "logs", canary)
        attempts = list(data.glob("scan-*-job-*"))
        assert len(attempts) == 2
        assert all(
            (attempt / "targets.txt").read_text().splitlines() == [address] for attempt in attempts
        )
        print(
            "Real Nmap network pipeline: native TCP service discovery and SSH NSE finding "
            "finished; excluded canary received no connections; no external route",
            flush=True,
        )
    finally:
        for name in (server, canary):
            command("docker", "rm", "--force", name, check=False)
        command("docker", "network", "rm", network, check=False)
        command("docker", "image", "rm", image, check=False)
