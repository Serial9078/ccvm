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
import types
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent
HOSTNAME = "ccvm.example.test"
CLIENTS = "192.0.2.0/24,198.51.100.0/24"
TOKEN_NAMES = ("CCVM_AUDIT_OPERATOR_TOKEN", "CCVM_AUDIT_VAULT_KEY")
PRE_TRANSPORT_RELEASE = "cb3b1486b3077fe1fac96925a7971235c07de7f0"
HTTP_INVENTORY_RELEASE = "2d4c31446303c3851b9ebacb55c143596faef0dd"
WINDOWS_PATCH_RELEASE = "f3c546e5200b9d7379e0981abef132ecda1e2b6a"
SOFTWARE_RELEASE = "69706bff65dad6436af59aceec45fa325f01630e"
OVERVIEW_RELEASE = "6c6474e27179998fe2d82815c0a826ca6de0a2e9"


def run(*args, cwd=None, data=None, timeout=600, success=True, stream=False):
    result = subprocess.run(
        args, cwd=cwd, input=data, capture_output=not stream, timeout=timeout, check=False
    )
    if success and result.returncode:
        raise AssertionError(
            f"Fixture command {args[:2]} failed: " + result.stderr.decode(errors="replace")[-3000:]
        )
    return result


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs).stdout.decode().strip()


def load_operator(source=None):
    if source is not None:
        module = types.ModuleType("authenticated_deployment")
        exec(compile(source, "<reviewed-deployment>", "exec"), module.__dict__)
        return module
    spec = importlib.util.spec_from_file_location(
        "authenticated_deployment", REPOSITORY / "scripts/deploy-authenticated-inventory.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect(name):
    return json.loads(docker("inspect", "--format", "{{json .}}", name))


def execute(source, target, pins, *, apply=False, operator_source=None):
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
        data=operator_source
        or (REPOSITORY / "scripts/deploy-authenticated-inventory.py").read_bytes(),
        success=False,
        timeout=900,
        stream=True,
    )
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


def seed_inventory(code):
    # start_audit() commits a queued row before this fixture marks it complete.
    # Pause the real worker so synthetic retained evidence never triggers a
    # target connection during setup. The backend has the same DB/vault scope.
    docker("pause", "ccvm-worker")
    try:
        return docker("exec", "ccvm-backend", "python", "-c", code)
    finally:
        docker("unpause", "ccvm-worker")


def verify_inventory_update(source, target, operation):
    """Exercise the actual reviewed updater against a populated old schema."""
    seed = """from datetime import UTC, datetime
from app.database.session import SessionLocal
from app.models.customer import Customer
from app.api.v1.host_audits import create_credential, start_audit
from app.schemas.host_audit import CredentialCreate, HostAuditCreate
with SessionLocal() as db:
    customer=Customer(name='Synthetic retained inventory customer')
    db.add(customer);db.commit()
    credential=create_credential(CredentialCreate(customer_id=customer.id,
        name='Synthetic retained account',kind='winrm',username='fixture',
        allowed_cidrs=['192.0.2.0/24'],password='synthetic-update-fixture'),db)
    audit=start_audit(HostAuditCreate(customer_id=customer.id,credential_id=credential.id,
        target='192.0.2.11',mode='connection'),db)
    audit.inventory={'schema_version':1,
        'os':{'family':'Windows','name':'Synthetic retained evidence'}}
    audit.job.status='finished';audit.job.progress=100
    audit.job.message='Retained synthetic connection evidence'
    audit.completed_at=datetime.now(UTC);db.commit()
print('Seeded encrypted credential and completed HTTPS inventory before update')
"""
    print(seed_inventory(seed), flush=True)
    private = Path(operation["private"])
    retained_files = [
        source / "docker-compose.yml",
        source / "docker-compose.network.yml",
        source / "docker-compose.authenticated.yml",
        source / "frontend/default.conf",
        source / ".git/ccvm-authenticated-deployment.json",
        *(private / name for name in ("vault.env", "operator.env", "gateway.conf")),
    ]
    retained = {path: path.read_bytes() for path in retained_files}
    stable = {
        name: inspect(name)["Id"]
        for name in ("ccvm-postgres", "haproxy-edge", "ccvm-audit-gateway")
    }
    run("git", "update-ref", "refs/remotes/origin/" + load_operator().BRANCH, target, cwd=source)
    script = (REPOSITORY / "scripts/update-host-inventory.py").read_bytes()

    def update(*flags):
        result = run(
            sys.executable,
            "-",
            "--target",
            target,
            "--host",
            socket.gethostname().split(".")[0],
            *flags,
            data=script,
            cwd=source,
            timeout=900,
            success=False,
            stream=True,
        )
        if result.returncode:
            marker = source / ".git/ccvm-host-inventory-update.json"
            if marker.is_file():
                log = Path(json.loads(marker.read_text())["backup"]) / "last-command.log"
                if log.is_file():
                    print(log.read_text(errors="replace")[-10000:], flush=True)
        assert result.returncode == 0

    update()
    assert not (source / ".git/ccvm-host-inventory-update.json").exists()
    update("--apply")
    assert stable == {name: inspect(name)["Id"] for name in stable}
    assert retained == {path: path.read_bytes() for path in retained}
    verify = """from app.database.session import SessionLocal
from app.models.host_audit import AuditCredential, HostAudit
from app.services.audit_vault import decrypt, audit_hash
with SessionLocal() as db:
    audit=db.query(HostAudit).one();credential=db.get(AuditCredential,audit.credential_id)
    assert audit.winrm_transport=='https'
    assert audit.scope_sha256==audit_hash(audit,credential)
    assert decrypt(credential)=={'password':'synthetic-update-fixture'}
    assert audit.inventory['os']['name']=='Synthetic retained evidence'
    assert audit.job.status=='finished' and audit.job.progress==100
print('Retained HTTPS request hash, encrypted credential and inventory evidence verified')
"""
    print(docker("exec", "ccvm-worker", "python", "-c", verify), flush=True)
    ids = {name: inspect("ccvm-" + name)["Id"] for name in ("backend", "worker", "frontend")}
    marker = source / ".git/ccvm-host-inventory-update.json"
    saved_update = json.loads(marker.read_text())
    saved_update["phase"] = "services"
    load_operator().write_json(marker, saved_update)
    docker("stop", "--time", "20", "ccvm-backend", "ccvm-worker")
    update("--apply", "--resume")
    assert ids == {name: inspect("ccvm-" + name)["Id"] for name in ids}
    update("--apply", "--resume")
    assert ids == {name: inspect("ccvm-" + name)["Id"] for name in ids}
    assert retained == {path: path.read_bytes() for path in retained}
    old_application(operation["images"]["backend"])
    print(
        "VERIFIED: old populated inventory schema update, retained credentials/evidence, "
        "unchanged TLS gateway/keys/scanners, stopped-service resume and idempotent verification",
        flush=True,
    )


def verify_windows_patch_update(source, target, operation):
    """Migrate a retained deployment and exercise assessment over actual TLS."""
    seed = """import hashlib,json
from datetime import UTC,datetime
from app.database.session import SessionLocal
from app.models.host_audit import AuditCredential
from app.models.job import Job
from app.models.finding import Finding
from app.api.v1.host_audits import start_audit
from app.schemas.host_audit import HostAuditCreate
with SessionLocal() as db:
    credential=db.query(AuditCredential).one()
    audit=start_audit(HostAuditCreate(customer_id=credential.customer_id,
        credential_id=credential.id,target='192.0.2.11',winrm_transport='http_ntlm'),db)
    audit.inventory={'schema_version':1,'os':{
        'family':'Windows','name':'Microsoft Windows Server 2022 Standard',
        'version':'10.0.20348','kernel':'20348.1000','architecture':'64-bit',
        'hostname':'SYNTHETIC-WINDOWS','product_type':'3','sku':'7',
        'installation_type':'Server','edition_id':'ServerStandard',
        'native_architecture':'AMD64','display_version':'21H2'},
        'packages':{'status':'complete','source':'registry-uninstall','items':[]},
        'hotfixes':{'status':'complete','source':'Get-HotFix','items':[]}}
    audit.completed_at=datetime.now(UTC);audit.job.status='finished';audit.job.progress=100
    audit.job.message='Previously collected synthetic Windows inventory';db.commit()
    print(json.dumps({'audit':audit.id,'jobs':db.query(Job).count(),
        'findings':db.query(Finding).count(),'hash':audit.scope_sha256,
        'inventory':hashlib.sha256(json.dumps(audit.inventory,sort_keys=True).encode()).hexdigest()}))
"""
    saved = json.loads(seed_inventory(seed))
    paths = [
        source / "docker-compose.yml",
        source / "docker-compose.authenticated.yml",
        source / "frontend/default.conf",
        source / ".git/ccvm-authenticated-deployment.json",
        source / ".git/ccvm-host-inventory-update.json",
        *(
            Path(operation["private"]) / name
            for name in ("vault.env", "operator.env", "gateway.conf")
        ),
    ]
    retained = {path: path.read_bytes() for path in paths}
    names = (
        "ccvm-backend",
        "ccvm-worker",
        "ccvm-frontend",
        "ccvm-postgres",
        "ccvm-audit-gateway",
        "haproxy-edge",
    )
    ids = {name: inspect(name)["Id"] for name in names}
    run("git", "update-ref", "refs/remotes/origin/" + load_operator().BRANCH, target, cwd=source)
    script = run(
        "git", "show", f"{target}:scripts/update-windows-patch-assessment.py", cwd=REPOSITORY
    ).stdout

    def update(*flags):
        result = run(
            sys.executable,
            "-",
            "--target",
            target,
            "--host",
            socket.gethostname().split(".")[0],
            *flags,
            data=script,
            cwd=source,
            timeout=900,
            success=False,
            stream=True,
        )
        if result.returncode:
            marker = source / ".git/ccvm-windows-patch-deployment.json"
            if marker.is_file():
                log = Path(json.loads(marker.read_text())["backup"]) / "last-command.log"
                if log.is_file():
                    print(log.read_text(errors="replace")[-10000:], flush=True)
        assert result.returncode == 0

    update()
    assert not (source / ".git/ccvm-windows-patch-deployment.json").exists()
    update("--apply")
    assert ids == {name: inspect(name)["Id"] for name in names}
    assert retained == {path: path.read_bytes() for path in paths}
    # Import a deliberately synthetic catalog directly in the disposable DB.
    # Live Microsoft downloads have separate parser/network checks and are not
    # a prerequisite for a reproducible deployment regression.
    catalog = """from datetime import UTC,datetime
from app.database.session import SessionLocal
from app.services.windows_patch_sync import store_catalog
now=datetime.now(UTC);month=('Jan','Feb','Mar','Apr','May','Jun',
    'Jul','Aug','Sep','Oct','Nov','Dec')[now.month-1]
document=f'{now.year}-{month}';release=now.replace(hour=0,minute=0,second=0,microsecond=0)
data={'schema_version':1,'source':'msrc-cvrf','retrieved_at':now.isoformat(),
    'coverage_start':now.replace(day=1).date().isoformat(),'coverage_end':now.date().isoformat(),
    'documents':[{'id':document,'url':f'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{document}',
        'sha256':'a'*64,'initial_release_date':release.isoformat(),
        'current_release_date':release.isoformat()}],
    'entries':[{'product_id':'11923','product_name':'Windows Server 2022',
        'cve':'CVE-2026-00001','title':'Synthetic Windows update advisory',
        'severity':'high','cvss_score':'7.5','kb':'KB5010000','fixed_build':'10.0.20348.2000',
        'document_id':document,
        'source_url':'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-00001',
        'subtype':'Security Update'}]}
with SessionLocal() as db:
    first=store_catalog(db,data);assert store_catalog(db,data).id==first.id
print('Synthetic immutable catalog imported idempotently')
"""
    print(docker("exec", "ccvm-worker", "python", "-c", catalog), flush=True)
    token = load_operator().read_env(Path(operation["private"]) / "operator.env")[
        "CCVM_AUDIT_OPERATOR_TOKEN"
    ]
    client = """import http.client,json,socket,ssl,sys
p=json.load(sys.stdin);context=ssl.create_default_context()
def request(path,*,method='GET',body=None,token=True):
    raw=socket.create_connection(('127.0.0.1',p['port']),timeout=10)
    raw.sendall(b'PROXY TCP4 192.0.2.1 127.0.0.1 12345 '+str(p['port']).encode()+b'\\r\\n')
    with context.wrap_socket(raw,server_hostname=p['hostname']) as tls:
        data=json.dumps(body).encode() if body is not None else b''
        headers=[f'{method} {path} HTTP/1.1',f"Host: {p['hostname']}",
            'Content-Type: application/json',f'Content-Length: {len(data)}','Connection: close']
        if token:headers.append('Authorization: Bearer '+p['token'])
        tls.sendall(('\\r\\n'.join(headers)+'\\r\\n\\r\\n').encode()+data)
        response=http.client.HTTPResponse(tls);response.begin()
        assert response.getheader('Cache-Control')=='no-store'
        return response.status,json.loads(response.read())
base='/api/v1/host-audits';path=f"{base}/{p['audit']}/assess"
assert request(path,method='POST',body={},token=False)[0]==401
status,catalog=request(base+'/patch-catalog');assert status==200 and catalog['entry_count']==1
status,first=request(path,method='POST',body={});assert status==200 and first['status']=='build_gap'
assert first['result']['installed_build']=='10.0.20348.1000'
assert first['result']['baseline_build']=='10.0.20348.2000'
assert first['result']['baseline_kbs']==['KB5010000']
status,second=request(path,method='POST',body={});assert status==200 and second['id']==first['id']
status,history=request(f"{base}/{p['audit']}/assessments")
assert status==200 and len(history)==1 and history[0]['id']==first['id']
print('Real TLS/operator assessment API: protected, exact build baseline, immutable and idempotent')
"""
    print(
        docker(
            "run",
            "--rm",
            "-i",
            "--network",
            "container:haproxy-edge",
            "--entrypoint",
            "python",
            operation["images"]["backend"],
            "-I",
            "-c",
            client,
            data=json.dumps(
                {
                    "port": operation["tls_port"],
                    "hostname": operation["hostname"],
                    "token": token,
                    "audit": saved["audit"],
                }
            ).encode(),
        ),
        flush=True,
    )
    verify = """import hashlib,json,sys
from app.database.session import SessionLocal
from app.models.host_audit import HostAudit
from app.models.host_assessment import HostAssessment
from app.models.job import Job
from app.models.finding import Finding
p=json.load(sys.stdin)
with SessionLocal() as db:
    audit=db.get(HostAudit,p['audit'])
    assert audit.scope_sha256==p['hash']
    evidence=json.dumps(audit.inventory,sort_keys=True).encode()
    assert hashlib.sha256(evidence).hexdigest()==p['inventory']
    assert db.query(Job).count()==p['jobs'] and db.query(Finding).count()==p['findings']
    assert db.query(HostAssessment).count()==1
print('Stored inventory and jobs/findings unchanged by operator-only assessment')
"""
    print(
        docker(
            "exec", "-i", "ccvm-worker", "python", "-c", verify, data=json.dumps(saved).encode()
        ),
        flush=True,
    )
    marker = source / ".git/ccvm-windows-patch-deployment.json"
    record = json.loads(marker.read_text())
    record["phase"] = "services"
    load_operator().write_json(marker, record)
    docker("stop", "--time", "20", "ccvm-backend", "ccvm-worker")
    update("--apply", "--resume")
    update("--apply", "--resume")
    assert ids == {name: inspect(name)["Id"] for name in names}
    assert retained == {path: path.read_bytes() for path in paths}
    print(
        "VERIFIED: retained Windows patch deployment, private assessment API, resume and history",
        flush=True,
    )


def verify_software_update(source, target, operation):
    """Migrate a retained deployment and exercise assessment over actual TLS."""
    seed = """import hashlib,json
from datetime import UTC,datetime
from app.database.session import SessionLocal
from app.models.host_audit import AuditCredential
from app.models.job import Job
from app.models.finding import Finding
from app.api.v1.host_audits import start_audit
from app.schemas.host_audit import HostAuditCreate
with SessionLocal() as db:
    credential=db.query(AuditCredential).one()
    audit=start_audit(HostAuditCreate(customer_id=credential.customer_id,
        credential_id=credential.id,target='192.0.2.11',winrm_transport='http_ntlm'),db)
    audit.inventory={'schema_version':1,'os':{
        'family':'Windows','name':'Microsoft Windows Server 2022 Standard',
        'version':'10.0.20348','kernel':'20348.1000','architecture':'64-bit',
        'hostname':'SYNTHETIC-WINDOWS','product_type':'3','sku':'7',
        'installation_type':'Server','edition_id':'ServerStandard',
        'native_architecture':'AMD64','display_version':'21H2'},
        'packages':{'status':'complete','source':'registry-uninstall','items':[
            {'name':'Microsoft Edge','version':'150.0.1.2','architecture':'unknown',
             'publisher':'Microsoft Corporation','registry_key':'Microsoft Edge',
             'registry_view':'wow6432','install_scope':'machine'},
            {'name':'Synthetic application','version':'1.0','architecture':'unknown',
             'publisher':'Synthetic publisher','registry_key':'Synthetic',
             'registry_view':'native','install_scope':'machine'}]},
        'hotfixes':{'status':'complete','source':'Get-HotFix','items':[]}}
    audit.completed_at=datetime.now(UTC);audit.job.status='finished';audit.job.progress=100
    audit.job.message='Previously collected synthetic Windows inventory';db.commit()
    print(json.dumps({'audit':audit.id,'jobs':db.query(Job).count(),
        'findings':db.query(Finding).count(),'hash':audit.scope_sha256,
        'inventory':hashlib.sha256(json.dumps(audit.inventory,sort_keys=True).encode()).hexdigest()}))
"""
    saved = json.loads(seed_inventory(seed))
    paths = [
        source / "docker-compose.yml",
        source / "docker-compose.authenticated.yml",
        source / "frontend/default.conf",
        source / ".git/ccvm-authenticated-deployment.json",
        source / ".git/ccvm-host-inventory-update.json",
        source / ".git/ccvm-windows-patch-deployment.json",
        *(
            Path(operation["private"]) / name
            for name in ("vault.env", "operator.env", "gateway.conf")
        ),
    ]
    retained = {path: path.read_bytes() for path in paths}
    names = (
        "ccvm-backend",
        "ccvm-worker",
        "ccvm-frontend",
        "ccvm-postgres",
        "ccvm-audit-gateway",
        "haproxy-edge",
    )
    ids = {name: inspect(name)["Id"] for name in names}
    run("git", "update-ref", "refs/remotes/origin/" + load_operator().BRANCH, target, cwd=source)
    script = run(
        "git", "show", f"{target}:scripts/update-software-assessment.py", cwd=REPOSITORY
    ).stdout

    def update(*flags):
        result = run(
            sys.executable,
            "-",
            "--target",
            target,
            "--host",
            socket.gethostname().split(".")[0],
            *flags,
            data=script,
            cwd=source,
            timeout=900,
            success=False,
            stream=True,
        )
        if result.returncode:
            marker = source / ".git/ccvm-software-assessment-deployment.json"
            if marker.is_file():
                log = Path(json.loads(marker.read_text())["backup"]) / "last-command.log"
                if log.is_file():
                    print(log.read_text(errors="replace")[-10000:], flush=True)
        assert result.returncode == 0

    update()
    assert not (source / ".git/ccvm-software-assessment-deployment.json").exists()
    update("--apply")
    assert ids == {name: inspect(name)["Id"] for name in names}
    assert retained == {path: path.read_bytes() for path in paths}
    # Import a deliberately synthetic catalog directly in the disposable DB.
    # Live Microsoft downloads have separate parser/network checks and are not
    # a prerequisite for a reproducible deployment regression.
    # Embed only the pure synthetic snapshot builder, without importing pytest
    # or adding development dependencies to the retained application image.
    import ast

    module = ast.parse((BACKEND / "integration/host_software_postgres.py").read_text())
    builder = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "catalog_fixture"
    )
    catalog = (
        "from datetime import UTC,datetime\n"
        + ast.unparse(builder)
        + "\nfrom app.database.session import SessionLocal\n"
        "from app.services.software_catalog_sync import store_catalog\n"
        "with SessionLocal() as db:\n"
        "    data=catalog_fixture();first=store_catalog(db,data)\n"
        "    assert store_catalog(db,data).id==first.id\n"
        "print('Synthetic immutable software catalog imported idempotently')\n"
    )
    print(docker("exec", "ccvm-worker", "python", "-c", catalog), flush=True)
    token = load_operator().read_env(Path(operation["private"]) / "operator.env")[
        "CCVM_AUDIT_OPERATOR_TOKEN"
    ]
    client = """import http.client,json,socket,ssl,sys
p=json.load(sys.stdin);context=ssl.create_default_context()
def request(path,*,method='GET',body=None,token=True):
    raw=socket.create_connection(('127.0.0.1',p['port']),timeout=10)
    raw.sendall(b'PROXY TCP4 192.0.2.1 127.0.0.1 12345 '+str(p['port']).encode()+b'\\r\\n')
    with context.wrap_socket(raw,server_hostname=p['hostname']) as tls:
        data=json.dumps(body).encode() if body is not None else b''
        headers=[f'{method} {path} HTTP/1.1',f"Host: {p['hostname']}",
            'Content-Type: application/json',f'Content-Length: {len(data)}','Connection: close']
        if token:headers.append('Authorization: Bearer '+p['token'])
        tls.sendall(('\\r\\n'.join(headers)+'\\r\\n\\r\\n').encode()+data)
        response=http.client.HTTPResponse(tls);response.begin()
        assert response.getheader('Cache-Control')=='no-store'
        return response.status,json.loads(response.read())
base='/api/v1/host-audits';path=f"{base}/{p['audit']}/assess-software"
assert request(path,method='POST',body={},token=False)[0]==401
status,catalog=request(base+'/software-catalog');assert status==200 and catalog['entry_count']==1
status,first=request(path,method='POST',body={})
assert status==200 and first['status']=='version_matches_found'
assert first['result']['summary']['inventory_entries']==2
assert first['result']['summary']['unassessed_entries']==1
assert first['result']['products'][0]['matches'][0]['cve']=='CVE-2026-0001'
status,second=request(path,method='POST',body={});assert status==200 and second['id']==first['id']
status,history=request(f"{base}/{p['audit']}/software-assessments")
assert status==200 and len(history)==1 and history[0]['id']==first['id']
print('Real TLS/operator software API: protected, exact ranges, immutable and idempotent')
"""
    print(
        docker(
            "run",
            "--rm",
            "-i",
            "--network",
            "container:haproxy-edge",
            "--entrypoint",
            "python",
            operation["images"]["backend"],
            "-I",
            "-c",
            client,
            data=json.dumps(
                {
                    "port": operation["tls_port"],
                    "hostname": operation["hostname"],
                    "token": token,
                    "audit": saved["audit"],
                }
            ).encode(),
        ),
        flush=True,
    )
    verify = """import hashlib,json,sys
from app.database.session import SessionLocal
from app.models.host_audit import HostAudit
from app.models.host_assessment import HostAssessment
from app.models.software_assessment import SoftwareAssessment
from app.models.job import Job
from app.models.finding import Finding
p=json.load(sys.stdin)
with SessionLocal() as db:
    audit=db.get(HostAudit,p['audit'])
    assert audit.scope_sha256==p['hash']
    evidence=json.dumps(audit.inventory,sort_keys=True).encode()
    assert hashlib.sha256(evidence).hexdigest()==p['inventory']
    assert db.query(Job).count()==p['jobs'] and db.query(Finding).count()==p['findings']
    assert db.query(HostAssessment).count()==1
    assert db.query(SoftwareAssessment).count()==1
print('Stored inventory and jobs/findings unchanged by operator-only assessment')
"""
    print(
        docker(
            "exec", "-i", "ccvm-worker", "python", "-c", verify, data=json.dumps(saved).encode()
        ),
        flush=True,
    )
    marker = source / ".git/ccvm-software-assessment-deployment.json"
    record = json.loads(marker.read_text())
    record["phase"] = "services"
    load_operator().write_json(marker, record)
    docker("stop", "--time", "20", "ccvm-backend", "ccvm-worker")
    update("--apply", "--resume")
    update("--apply", "--resume")
    assert ids == {name: inspect(name)["Id"] for name in names}
    assert retained == {path: path.read_bytes() for path in paths}
    print(
        "VERIFIED: retained software update, private API, resume and history",
        flush=True,
    )


def verify_overview_update(source, target, operation):
    """Keep populated histories intact and read the overview over actual TLS."""
    snapshot = """import hashlib,json
from sqlalchemy import inspect
from app.database.session import engine
def stable(value):
    if isinstance(value,(memoryview,bytes,bytearray)):
        return {'bytes_hex':bytes(value).hex()}
    return str(value)
with engine.connect() as connection:
    connection.exec_driver_sql('SET TRANSACTION READ ONLY')
    result={}
    for name in sorted(inspect(connection).get_table_names()):
        quoted=engine.dialect.identifier_preparer.quote(name)
        rows=[dict(row) for row in connection.exec_driver_sql('SELECT * FROM '+quoted).mappings()]
        encoded=sorted(json.dumps(row,sort_keys=True,default=stable) for row in rows)
        result[name]={'count':len(rows),'sha256':hashlib.sha256(
            json.dumps(encoded,sort_keys=True).encode()).hexdigest()}
    credential=connection.exec_driver_sql('SELECT customer_id FROM audit_credentials').one()
    print(json.dumps({'tables':result,'customer':credential[0]}))
"""
    before = json.loads(docker("exec", "ccvm-worker", "python", "-c", snapshot))
    assert before["tables"]["software_assessments"]["count"] == 1
    assert before["tables"]["host_assessments"]["count"] == 1
    paths = [
        source / name
        for name in (
            "docker-compose.yml",
            "docker-compose.authenticated.yml",
            "frontend/default.conf",
            ".git/ccvm-authenticated-deployment.json",
            ".git/ccvm-host-inventory-update.json",
            ".git/ccvm-windows-patch-deployment.json",
            ".git/ccvm-software-assessment-deployment.json",
        )
    ]
    paths += [
        Path(operation["private"]) / name for name in ("vault.env", "operator.env", "gateway.conf")
    ]
    retained = {path: path.read_bytes() for path in paths}
    names = (
        "ccvm-backend",
        "ccvm-worker",
        "ccvm-frontend",
        "ccvm-postgres",
        "ccvm-audit-gateway",
        "haproxy-edge",
    )
    identities = {name: inspect(name)["Id"] for name in names}
    run("git", "update-ref", "refs/remotes/origin/" + load_operator().BRANCH, target, cwd=source)
    script = run(
        "git", "show", f"{target}:scripts/update-inventory-overview.py", cwd=REPOSITORY
    ).stdout
    marker = source / ".git/ccvm-inventory-overview-deployment.json"

    def update(*flags):
        result = run(
            sys.executable,
            "-",
            "--target",
            target,
            "--host",
            socket.gethostname().split(".")[0],
            *flags,
            data=script,
            cwd=source,
            timeout=900,
            success=False,
            stream=True,
        )
        if result.returncode and marker.is_file():
            log = Path(json.loads(marker.read_text())["backup"]) / "last-command.log"
            if log.is_file():
                print(log.read_text(errors="replace")[-10000:], flush=True)
        assert result.returncode == 0

    update()
    assert not marker.exists()
    update("--apply")
    assert json.loads(docker("exec", "ccvm-worker", "python", "-c", snapshot)) == before
    assert retained == {path: path.read_bytes() for path in paths}
    assert identities == {name: inspect(name)["Id"] for name in names}
    token = load_operator().read_env(Path(operation["private"]) / "operator.env")[
        "CCVM_AUDIT_OPERATOR_TOKEN"
    ]
    client = """import http.client,json,socket,ssl,sys
p=json.load(sys.stdin);context=ssl.create_default_context()
def request(token=True):
    raw=socket.create_connection(('127.0.0.1',p['port']),timeout=10)
    raw.sendall(b'PROXY TCP4 192.0.2.1 127.0.0.1 12345 '+str(p['port']).encode()+b'\\r\\n')
    with context.wrap_socket(raw,server_hostname=p['hostname']) as tls:
        path='/api/v1/host-audits/overview?customer_id='+str(p['customer'])
        headers=[f'GET {path} HTTP/1.1',f"Host: {p['hostname']}",'Connection: close']
        if token:headers.append('Authorization: Bearer '+p['token'])
        tls.sendall(('\\r\\n'.join(headers)+'\\r\\n\\r\\n').encode())
        response=http.client.HTTPResponse(tls);response.begin()
        assert response.getheader('Cache-Control')=='no-store'
        return response.status,json.loads(response.read())
assert request(False)[0]==401
status,data=request();assert status==200 and data['customer_id']==p['customer']
assert len(data['hosts'])==1
host=data['hosts'][0]
assert host['platform']=='windows_server' and host['target']=='192.0.2.11'
assert host['inventory']['package_count']==2
assert host['software_assessment']['status']=='version_matches_found'
# The older OS assessment belongs to another inventory and cannot bless this one.
assert host['windows_assessment'] is None
print('Real TLS overview: operator guard, exact inventory basis, actionable software match')
"""
    print(
        docker(
            "run",
            "--rm",
            "-i",
            "--network",
            "container:haproxy-edge",
            "--entrypoint",
            "python",
            operation["images"]["backend"],
            "-I",
            "-c",
            client,
            data=json.dumps(
                {
                    "port": operation["tls_port"],
                    "hostname": operation["hostname"],
                    "token": token,
                    "customer": before["customer"],
                }
            ).encode(),
        ),
        flush=True,
    )
    assert json.loads(docker("exec", "ccvm-worker", "python", "-c", snapshot)) == before
    record = json.loads(marker.read_text())
    record["phase"] = "services"
    load_operator().write_json(marker, record)
    docker("stop", "--time", "20", "ccvm-backend", "ccvm-worker")
    update("--apply", "--resume")
    update("--apply", "--resume")
    assert json.loads(docker("exec", "ccvm-worker", "python", "-c", snapshot)) == before
    assert retained == {path: path.read_bytes() for path in paths}
    assert identities == {name: inspect(name)["Id"] for name in names}
    print(
        "VERIFIED: overview update, populated histories unchanged, no migration, resume and repeat",
        flush=True,
    )


def verify_windows_clients_update(source, target, operation):
    """Publish without migration, then assess synthetic offers over actual TLS.

    No Windows target, WinRM connection or live update-source query participates
    in this fixture. The only new inventory is committed while the worker is
    paused, using the normal scoped audit helper and deliberately synthetic data.
    """
    snapshot = """import hashlib,json,sys
from sqlalchemy import inspect
from app.database.session import engine
def stable(value):
    if isinstance(value,(memoryview,bytes,bytearray)):
        return {'bytes_hex':bytes(value).hex()}
    return str(value)
excluded=int(sys.argv[1]) if len(sys.argv)>1 else None
with engine.connect() as connection:
    connection.exec_driver_sql('SET TRANSACTION READ ONLY')
    result={}
    for name in sorted(inspect(connection).get_table_names()):
        quoted=engine.dialect.identifier_preparer.quote(name)
        statement='SELECT * FROM '+quoted
        if name=='host_assessments' and excluded is not None:
            statement+=' WHERE id <> '+str(excluded)
        rows=[dict(row) for row in connection.exec_driver_sql(statement).mappings()]
        encoded=sorted(json.dumps(row,sort_keys=True,default=stable) for row in rows)
        result[name]={'count':len(rows),'sha256':hashlib.sha256(
            json.dumps(encoded,sort_keys=True).encode()).hexdigest()}
    credential=connection.exec_driver_sql('SELECT customer_id FROM audit_credentials').one()
    revision=connection.exec_driver_sql('SELECT version_num FROM alembic_version').scalar_one()
    print(json.dumps({'tables':result,'customer':credential[0],'revision':revision}))
"""

    def capture(excluded_assessment=None):
        arguments = () if excluded_assessment is None else (str(excluded_assessment),)
        return json.loads(docker("exec", "ccvm-worker", "python", "-c", snapshot, *arguments))

    before = capture()
    assert before["revision"] == "d6a4b8e2f901"
    assert before["tables"]["host_assessments"]["count"] == 1
    assert before["tables"]["software_assessments"]["count"] == 1
    assert before["tables"]["windows_patch_catalogs"]["count"] == 1
    assert before["tables"]["software_advisory_catalogs"]["count"] == 1
    paths = [
        source / name
        for name in (
            "docker-compose.yml",
            "docker-compose.network.yml",
            "docker-compose.authenticated.yml",
            "fixture.env",
            "frontend/default.conf",
            ".git/ccvm-authenticated-deployment.json",
            ".git/ccvm-host-inventory-update.json",
            ".git/ccvm-windows-patch-deployment.json",
            ".git/ccvm-software-assessment-deployment.json",
            ".git/ccvm-inventory-overview-deployment.json",
        )
    ]
    paths += [
        Path(operation["private"]) / name for name in ("vault.env", "operator.env", "gateway.conf")
    ]
    paths += [Path(operation["edge_path"])]
    paths += sorted(Path(operation["certificate_dir"]).glob("*.pem"))
    retained = {path: path.read_bytes() for path in paths}
    names = (
        "ccvm-backend",
        "ccvm-worker",
        "ccvm-frontend",
        "ccvm-postgres",
        "ccvm-audit-gateway",
        "haproxy-edge",
    )
    identities = {name: inspect(name)["Id"] for name in names}
    previous_head = run("git", "rev-parse", "HEAD", cwd=source).stdout.decode().strip()
    assert previous_head == OVERVIEW_RELEASE
    run("git", "update-ref", "refs/remotes/origin/" + load_operator().BRANCH, target, cwd=source)
    script = run(
        "git", "show", f"{target}:scripts/update-windows-clients.py", cwd=REPOSITORY
    ).stdout
    marker = source / ".git/ccvm-windows-clients-deployment.json"

    def update(*flags):
        result = run(
            sys.executable,
            "-",
            "--target",
            target,
            "--host",
            socket.gethostname().split(".")[0],
            *flags,
            data=script,
            cwd=source,
            timeout=900,
            success=False,
            stream=True,
        )
        if result.returncode and marker.is_file():
            log = Path(json.loads(marker.read_text())["backup"]) / "last-command.log"
            if log.is_file():
                print(log.read_text(errors="replace")[-10000:], flush=True)
        assert result.returncode == 0

    def unchanged():
        assert capture() == before
        assert retained == {path: path.read_bytes() for path in paths}
        assert identities == {name: inspect(name)["Id"] for name in names}

    update()
    assert not marker.exists()
    assert run("git", "rev-parse", "HEAD", cwd=source).stdout.decode().strip() == previous_head
    unchanged()
    update("--apply")
    unchanged()
    record = json.loads(marker.read_text())
    assert record["version"] == "1.0.0" and record["phase"] == "verified"
    assert record["target"] == target
    record["phase"] = "services"
    load_operator().write_json(marker, record)
    docker("stop", "--time", "20", "ccvm-backend", "ccvm-worker")
    update("--apply", "--resume")
    unchanged()
    verified_journal = marker.read_bytes()
    update("--apply", "--resume")
    unchanged()
    assert marker.read_bytes() == verified_journal
    old_application(operation["images"]["backend"])

    seed = """import json
from datetime import UTC,datetime,timedelta
from app.database.session import SessionLocal
from app.models.asset import Asset
from app.models.host import Host
from app.models.host_audit import AuditCredential
from app.models.network_scan import NetworkObservation,NetworkScan
from app.api.v1.host_audits import start_audit
from app.api.v1.network_scans import start_scan
from app.schemas.host_audit import HostAuditCreate
from app.schemas.network_scan import NetworkScanCreate
with SessionLocal() as db:
    credential=db.query(AuditCredential).one()
    audit=start_audit(HostAuditCreate(customer_id=credential.customer_id,
        credential_id=credential.id,target='192.0.2.12',mode='windows_updates',
        winrm_transport='http_ntlm'),db)
    now=datetime.now(UTC)
    audit.inventory={'schema_version':1,'os':{
        'family':'Windows','name':'Microsoft Windows 11 Pro','product_type':'1',
        'hostname':'SYNTHETIC-CLIENT','architecture':'64-bit','native_architecture':'AMD64'},
        'packages':{'status':'complete','source':'registry-uninstall','items':[]},
        'hotfixes':{'status':'complete','source':'Get-HotFix','items':[]},
        'windows_updates':{'schema_version':1,'source':'windows-update-agent',
            'mode':'online','server_selection':'default',
            'queried_at':(now-timedelta(minutes=1)).isoformat(),
            'status':'complete','result_code':2,'total':1,'truncated':False,
            'hidden_updates':'not_assessed','drivers':'not_assessed','superseded':'excluded',
            'reboot_required':False,'items':[{
                'update_id':'00000000-0000-4000-8000-000000000101','revision':200,
                'title':'Synthetic retained client security offer','kbs':['KB5100001'],
                'categories':[{'id':'0fa1201d-4330-4fa8-8ae9-b877473b6441',
                    'type':'UpdateClassification','name':'Synthetic security classification'}],
                'msrc_severity':'Critical','is_hidden':False,'is_installed':False,
                'is_optional':False,'is_mandatory':False}]}}
    audit.completed_at=now;audit.job.status='finished';audit.job.progress=100
    audit.job.message='Completed synthetic inventory fixture';db.commit()
    # Scope/jobs are made by the real helper, but the paused worker never probes.
    created=start_scan(NetworkScanCreate(customer_id=credential.customer_id,
        target='192.0.2.8/29',profile='fast'),db)
    network=db.get(NetworkScan,created['id'])
    for job in (network.discovery_job,network.audit_job):
        job.status='finished';job.progress=100;job.message='Completed synthetic network fixture'
    for address,services in (
        ('192.0.2.12',[{'port':5985,'protocol':'tcp','state':'open','service':'http',
            'product':'Synthetic reported service','version':'1.2.3',
            'method':'probed','checks':[]}]),
        ('192.0.2.13',[{'port':443,'protocol':'tcp','state':'open','service':'https',
            'product':'Synthetic reported appliance','version':'4.5.6',
            'method':'probed','checks':[]}]),
        ('192.0.2.14',[]),
    ):
        asset=db.get(Asset,audit.asset_id) if address==audit.target else Asset(
            customer_id=credential.customer_id,type='ip',target=address,ip_address=address)
        host=Host(customer_id=credential.customer_id,hostname=address,ip_address=address,
            source='nmap-network',alive=bool(services))
        db.add_all([asset,host]);db.flush()
        db.add(NetworkObservation(scan_id=network.id,host_id=host.id,asset_id=asset.id,
            ip_address=address,services=services))
    db.commit()
    print(json.dumps({'audit':audit.id,'customer':credential.customer_id,'scan':network.id}))
"""
    saved = json.loads(seed_inventory(seed))
    seeded = capture()
    assert seeded["revision"] == before["revision"]
    token = load_operator().read_env(Path(operation["private"]) / "operator.env")[
        "CCVM_AUDIT_OPERATOR_TOKEN"
    ]
    client = """import http.client,json,socket,ssl,sys
p=json.load(sys.stdin);context=ssl.create_default_context()
def request(path,*,method='GET',body=None,token=True,private=True):
    raw=socket.create_connection(('127.0.0.1',p['port']),timeout=10)
    raw.sendall(b'PROXY TCP4 192.0.2.1 127.0.0.1 12345 '+str(p['port']).encode()+b'\\r\\n')
    with context.wrap_socket(raw,server_hostname=p['hostname']) as tls:
        data=json.dumps(body).encode() if body is not None else b''
        headers=[f'{method} {path} HTTP/1.1',f"Host: {p['hostname']}",
            'Content-Type: application/json',f'Content-Length: {len(data)}','Connection: close']
        if token:headers.append('Authorization: Bearer '+p['token'])
        tls.sendall(('\\r\\n'.join(headers)+'\\r\\n\\r\\n').encode()+data)
        response=http.client.HTTPResponse(tls);response.begin()
        if private:assert response.getheader('Cache-Control')=='no-store'
        return response.status,json.loads(response.read())
base='/api/v1/host-audits'
capabilities=base+'/capabilities'
discovered=base+'/discovered?customer_id='+str(p['customer'])+'&limit=200&offset=0'
for path in (capabilities,discovered):
    assert request(path,token=False)[0]==401
status,matrix=request(capabilities)
assert status==200 and matrix['version']=='scanner-capabilities-v1'
assert {stage['id'] for stage in matrix['stage_labels']}=={
    'discovery','inventory','configuration','os_baseline','software_checks','offered_updates'}
platforms={platform['id']:platform for platform in matrix['platforms']}
assert len(platforms)==8
assert platforms['windows_client']['stages']['offered_updates']['status']=='limited'
assert platforms['windows_client']['stages']['os_baseline']['status']=='unavailable'
assert platforms['vmware']['stages']['inventory']['status']=='unavailable'
assert platforms['linux']['stages']['os_baseline']['status']=='unavailable'
status,queue=request(discovered)
assert status==200 and queue['customer_id']==p['customer']
assert queue['total']==2 and queue['has_more'] is False
devices={device['ip_address']:device for device in queue['items']}
assert set(devices)=={'192.0.2.12','192.0.2.13'}
assert devices['192.0.2.12']['inventory_status']=='inventoried'
assert devices['192.0.2.13']['inventory_status']=='not_inventoried'
assert devices['192.0.2.12']['services'][0]['port']==5985
assert devices['192.0.2.13']['services'][0]['product']=='Synthetic reported appliance'
assert all(device['scan_id']==p['scan'] for device in devices.values())
assert all('platform' not in device and 'os' not in device for device in devices.values())
status,page=request(discovered.replace('limit=200','limit=1'))
assert status==200 and len(page['items'])==1 and page['has_more'] is True
status,next_page=request(discovered.replace('limit=200','limit=1').replace('offset=0','offset=1'))
assert status==200 and len(next_page['items'])==1 and next_page['has_more'] is False
assert page['items'][0]['ip_address']!=next_page['items'][0]['ip_address']
assert request(discovered.replace('limit=200','limit=201'))[0]==422
public={}
for name in ('jobs','findings'):
    status,data=request('/api/v1/'+name,token=False,private=False)
    assert status==200;public[name]=data
path=f"{base}/{p['audit']}/assess"
assert request(path,method='POST',body={},token=False)[0]==401
status,first=request(path,method='POST',body={})
assert status==200 and first['status']=='updates_offered'
assert first['engine_version']=='windows-client-wua-v1'
assert first['catalog_id'] is None and first['catalog_applicable'] is False
assert first['provider']=='windows-update-agent'
assert first['result']['windows_updates']['mode']=='online'
assert first['result']['windows_updates']['summary']['security']==1
assert first['result']['windows_updates']['summary']['actionable']==1
assert first['result']['windows_updates']['items'][0]['title']==p['private_offer']
assert 'baseline_build' not in first['result']
status,second=request(path,method='POST',body={})
assert status==200 and second['id']==first['id']
status,history=request(f"{base}/{p['audit']}/assessments")
assert status==200 and len(history)==1 and history[0]['id']==first['id']
status,overview=request(base+'/overview?customer_id='+str(p['customer']))
assert status==200
host=next(host for host in overview['hosts'] if host['target']=='192.0.2.12')
assert host['platform']=='windows_client'
assert host['windows_assessment']['status']=='updates_offered'
for name in ('jobs','findings'):
    status,data=request('/api/v1/'+name,token=False,private=False)
    assert status==200 and data==public[name]
    encoded=json.dumps(data)
    for secret in (p['private_offer'],p['update_id'],p['token'],'KB5100001'):
        assert secret not in encoded
print(json.dumps({'assessment':first['id']}))
"""
    assessed = json.loads(
        docker(
            "run",
            "--rm",
            "-i",
            "--network",
            "container:haproxy-edge",
            "--entrypoint",
            "python",
            operation["images"]["backend"],
            "-I",
            "-c",
            client,
            data=json.dumps(
                {
                    "port": operation["tls_port"],
                    "hostname": operation["hostname"],
                    "token": token,
                    **saved,
                    "private_offer": "Synthetic retained client security offer",
                    "update_id": "00000000-0000-4000-8000-000000000101",
                }
            ).encode(),
        )
    )
    after = capture()
    assert after["tables"]["host_assessments"]["count"] == (
        seeded["tables"]["host_assessments"]["count"] + 1
    )
    assert capture(assessed["assessment"]) == seeded
    assert retained == {path: path.read_bytes() for path in paths}
    assert identities == {name: inspect(name)["Id"] for name in names}
    assert marker.read_bytes() == verified_journal
    print(
        "VERIFIED: migration-free Windows client update, all retained rows/journals/ingress, "
        "stopped-service resume, private TLS capability/discovery APIs and synthetic local WUA "
        "assessment without a catalog or public jobs/findings leakage",
        flush=True,
    )


def main():
    if sys.argv[1:] not in (
        [],
        ["--host-inventory-update"],
        ["--windows-patch-update"],
        ["--software-assessment-update"],
        ["--inventory-overview-update"],
        ["--windows-clients-update"],
    ):
        raise RuntimeError("Unknown disposable deployment fixture mode")
    update_mode = bool(sys.argv[1:])
    patch_mode = sys.argv[1:] in (
        ["--windows-patch-update"],
        ["--software-assessment-update"],
        ["--inventory-overview-update"],
        ["--windows-clients-update"],
    )
    software_mode = sys.argv[1:] in (
        ["--software-assessment-update"],
        ["--inventory-overview-update"],
        ["--windows-clients-update"],
    )
    overview_mode = sys.argv[1:] in (
        ["--inventory-overview-update"],
        ["--windows-clients-update"],
    )
    windows_clients_mode = sys.argv[1:] == ["--windows-clients-update"]
    if os.environ.get("GITHUB_ACTIONS") != "true" or not re.fullmatch(
        r"[1-9][0-9]+", os.environ.get("GITHUB_RUN_ID", "")
    ):
        raise RuntimeError("Disposable deployment integration is restricted to GitHub Actions")
    if docker("ps", "-a", "--format", "{{.Names}}").splitlines():
        raise RuntimeError("This integration requires its own empty Docker runner")
    reviewed_target = run("git", "rev-parse", "HEAD", cwd=REPOSITORY).stdout.decode().strip()
    target = PRE_TRANSPORT_RELEASE if update_mode else reviewed_target
    operator_source = (
        run(
            "git", "show", target + ":scripts/deploy-authenticated-inventory.py", cwd=REPOSITORY
        ).stdout
        if update_mode
        else None
    )
    operator = load_operator(operator_source)

    def deploy(source, target, pins, *, apply=False):
        return execute(source, target, pins, apply=apply, operator_source=operator_source)

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
            bad = deploy(source, target, {**pins, "worker": "sha256:" + "0" * 64}, apply=True)
            assert bad.returncode != 0
            assert not (source / ".git/ccvm-authenticated-deployment.json").exists()
            assert ids == {n: inspect(n)["Id"] for n in ids}
            checked = deploy(source, target, pins)
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
            applied = deploy(source, target, pins, apply=True)
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
            resumed = deploy(source, target, pins, apply=True)
            if resumed.returncode:
                diagnostics(source)
            assert resumed.returncode == 0
            assert secrets_before == {n: (private / n).read_bytes() for n in secrets_before}
            before_ids = {n: inspect(n)["Id"] for n in ids if n != "haproxy-edge"}
            assert deploy(source, target, pins, apply=True).returncode == 0
            assert before_ids == {n: inspect(n)["Id"] for n in before_ids}
            assert edge_file.read_text().count("frontend ccvm_audit_https") == 1
            old_application(base)
            print(
                "VERIFIED: full deploy, real TLS/PROXY chain, ACLs, spoof rejection, "
                "loopback ports, retained services, immutable scanners, resume and idempotency",
                flush=True,
            )
            if update_mode:
                verify_inventory_update(
                    source, HTTP_INVENTORY_RELEASE, json.loads(journal.read_text())
                )
            if patch_mode:
                verify_windows_patch_update(
                    source, WINDOWS_PATCH_RELEASE, json.loads(journal.read_text())
                )
            if software_mode:
                verify_software_update(source, SOFTWARE_RELEASE, json.loads(journal.read_text()))
            if overview_mode:
                verify_overview_update(
                    source,
                    OVERVIEW_RELEASE if windows_clients_mode else reviewed_target,
                    json.loads(journal.read_text()),
                )
            if windows_clients_mode:
                verify_windows_clients_update(
                    source, reviewed_target, json.loads(journal.read_text())
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
