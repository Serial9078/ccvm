"""Verify the CLI-only updater against a disposable released backend and PG16.

This intentionally excludes scanners, frontend builds and ingress changes: the
enrollment patch must preserve the running application and every stored row.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import select
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
BASE = "51c9e544102900c0efb5070358c1c9da2f9942db"
BRANCH = "sprint-1.0.2-feature-architecture"
BACKEND_NAME = "ccvm-backend"
JOURNAL = "ccvm-auth-enrollment-update.json"


def run(*args, cwd=None, data=None, timeout=300, success=True):
    result = subprocess.run(
        args, cwd=cwd, input=data, capture_output=True, timeout=timeout, check=False
    )
    if success and result.returncode:
        # Fixture payloads go through stdin/private env files, never arguments.
        raise AssertionError(
            f"Fixture command {args[:2]} failed: " + result.stderr.decode(errors="replace")[-4000:]
        )
    return result


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs).stdout.decode().strip()


def inspect(name):
    return json.loads(docker("inspect", "--format", "{{json .}}", name))


def backend_python(code, payload=None):
    return docker(
        "exec",
        "-i",
        "--workdir",
        "/app",
        BACKEND_NAME,
        "python",
        "-c",
        code,
        data=None if payload is None else json.dumps(payload).encode(),
    )


SEED = """
import json,sys
from datetime import timedelta
from app.database.session import SessionLocal
from app.models.auth import AuthSession
from app.models.customer import Customer
from app.models.host_audit import AuditCredential
from app.services import auth_session as auth
from app.services.audit_vault import encrypt,decrypt
from app.auth_admin import admin_lock,write_policy
p=json.load(sys.stdin)
with SessionLocal() as db:
 user=auth.create_operator(db,'retained-operator',p['password'],p['totp'])
 customer=Customer(name='Retained enrollment fixture',company='Synthetic CI only')
 db.add(customer);db.flush()
 credential=AuditCredential(customer_id=customer.id,name='Retained vault fixture',
  kind='winrm',username='EXAMPLE\\\\inventory',allowed_cidrs=['192.0.2.0/24'])
 db.add(credential);db.flush()
 credential.ciphertext=encrypt(credential,{'password':p['vault_password']})
 assert decrypt(credential)=={'password':p['vault_password']}
 moment=auth.now();token=p['session']
 db.add(AuthSession(token_hash=auth.digest(token),user_id=user.id,
  csrf_hash=auth.digest(auth.csrf_token(token)),created_at=moment,
  last_seen_at=moment,expires_at=moment+timedelta(hours=8)))
 db.commit()
with admin_lock():write_policy('https://ccvm.example.test')
print('Synthetic account, active session, customer and encrypted credential prepared')
"""

SNAPSHOT = """
import hashlib,json
from datetime import date,datetime
import sqlalchemy as sa
from app.database.session import engine,SessionLocal
from app.models.host_audit import AuditCredential
from app.services.audit_vault import decrypt
def canonical(value):
 if isinstance(value,(bytes,memoryview)):return bytes(value).hex()
 if isinstance(value,(date,datetime)):return value.isoformat()
 raise TypeError(type(value).__name__)
result={}
with engine.connect() as c:
 c.exec_driver_sql('SET TRANSACTION READ ONLY')
 c.exec_driver_sql("SET LOCAL statement_timeout='5s'")
 for name in sa.inspect(c).get_table_names():
  table=sa.Table(name,sa.MetaData(),autoload_with=c)
  statement=sa.select(table).order_by(*table.primary_key.columns)
  rows=[dict(row._mapping) for row in c.execute(statement)]
  serialized=json.dumps(rows,sort_keys=True,separators=(',',':'),default=canonical).encode()
  result[name]={'count':len(rows),'sha256':hashlib.sha256(serialized).hexdigest()}
with SessionLocal() as db:
 credential=db.query(AuditCredential).one()
 assert set(decrypt(credential))=={'password'}
print(json.dumps(result,sort_keys=True))
"""

POLICY = """
import hashlib,json,os,stat,sys
from pathlib import Path
p=Path(sys.argv[1])
assert not p.is_symlink()
s=p.stat()
assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
print(json.dumps({'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode)}))
"""


def runtime_identity():
    info = inspect(BACKEND_NAME)
    return {
        "id": info["Id"],
        "pid": info["State"]["Pid"],
        "started": info["State"]["StartedAt"],
        "restarts": info["RestartCount"],
        "image": info["Image"],
        "command": info["Config"]["Cmd"],
    }


def assert_health():
    assert (
        backend_python(
            "import json,urllib.request;"
            "r=urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3);"
            "assert r.status==200;assert json.load(r)['status']=='ok';print('healthy')"
        )
        == "healthy"
    )


def main():
    run_id, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id)
        or not re.fullmatch(r"[1-9][0-9]{0,9}", attempt)
    ):
        raise RuntimeError("Enrollment deployment integration requires a disposable GitHub runner")
    if docker("ps", "--all", "--format", "{{.Names}}").splitlines():
        raise RuntimeError("Enrollment deployment integration requires an empty Docker runner")
    target = run("git", "rev-parse", "HEAD", cwd=REPOSITORY).stdout.decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", target):
        raise RuntimeError("Invalid reviewed fixture source")
    script = run(
        "git", "show", target + ":scripts/update-auth-enrollment.py", cwd=REPOSITORY
    ).stdout
    network = f"ccvm-enrollment-{run_id}-{attempt}"
    postgres_name = network + "-postgres"
    image = network + ":runtime"
    backend_created = postgres_created = network_created = image_created = False
    with tempfile.TemporaryDirectory(prefix="ccvm-enrollment-deploy-") as temporary:
        directory = Path(temporary)
        source = directory / "checkout"
        try:
            run("git", "clone", "--no-hardlinks", "--no-checkout", str(REPOSITORY), str(source))
            run("git", "checkout", "-B", BRANCH, BASE, cwd=source)
            run("git", "update-ref", "refs/remotes/origin/" + BRANCH, target, cwd=source)
            # Production's retained local configuration remains deliberately dirty.
            for name in ("docker-compose.yml", "frontend/default.conf"):
                path = source / name
                path.write_text(path.read_text() + "\n# retained enrollment fixture\n")
            protected = {
                name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                for name in ("docker-compose.yml", "frontend/default.conf")
            }
            build = directory / "image"
            build.mkdir()
            (build / "requirements.txt").write_bytes(
                run("git", "show", BASE + ":backend/requirements.txt", cwd=source).stdout
            )
            (build / "Dockerfile").write_text(
                "FROM python:3.12-slim\n"
                "COPY requirements.txt /tmp/requirements.txt\n"
                "RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt\n"
                "WORKDIR /app\n"
            )
            docker("build", "--tag", image, str(build), timeout=360)
            image_created = True
            docker("network", "create", network)
            network_created = True
            database_password = secrets.token_urlsafe(24)
            postgres_env = directory / "postgres.env"
            postgres_env.write_text(
                "POSTGRES_DB=ccvm_enrollment_ci\nPOSTGRES_USER=ccvm_ci\n"
                f"POSTGRES_PASSWORD={database_password}\n"
            )
            postgres_env.chmod(0o600)
            runtime_env = directory / "runtime.env"
            runtime_env.write_text(
                f"DB_HOST={postgres_name}\nDB_NAME=ccvm_enrollment_ci\nDB_USER=ccvm_ci\n"
                f"DB_PASS={database_password}\n"
                "CCVM_AUDIT_VAULT_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode() + "\n"
                "CCVM_AUDIT_OPERATOR_TOKEN=" + secrets.token_urlsafe(32) + "\n"
                "CCVM_NETWORK_ALLOWED_CIDRS=192.0.2.0/24\n"
            )
            runtime_env.chmod(0o600)
            docker(
                "run",
                "--detach",
                "--name",
                postgres_name,
                "--network",
                network,
                "--env-file",
                str(postgres_env),
                "postgres:16-alpine",
            )
            postgres_created = True
            for _ in range(60):
                ready = run(
                    "docker", "exec", postgres_name, "pg_isready", "-U", "ccvm_ci", success=False
                )
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise AssertionError("Disposable enrollment PostgreSQL did not start")
            mount = f"type=bind,src={source / 'backend'},dst=/app"
            docker(
                "run",
                "--rm",
                "--network",
                network,
                "--env-file",
                str(runtime_env),
                "--mount",
                mount,
                image,
                "python",
                "-c",
                "from alembic import command;from alembic.config import Config;"
                "command.upgrade(Config('/app/alembic.ini'),'e7b5c9d2a401')",
            )
            docker(
                "run",
                "--detach",
                "--init",
                "--name",
                BACKEND_NAME,
                "--network",
                network,
                "--env-file",
                str(runtime_env),
                "--mount",
                mount,
                image,
                "uvicorn",
                "app.main:app",
                "--host",
                "0.0.0.0",
                "--port",
                "8000",
            )
            backend_created = True
            for _ in range(30):
                try:
                    assert_health()
                    break
                except AssertionError:
                    time.sleep(1)
            else:
                raise AssertionError("Disposable released backend did not become healthy")
            backend_python(
                SEED,
                {
                    "password": secrets.token_urlsafe(32),
                    "totp": base64.b32encode(secrets.token_bytes(20)).decode(),
                    "vault_password": secrets.token_urlsafe(32),
                    "session": secrets.token_urlsafe(32),
                },
            )
            marker = source / ".git" / JOURNAL
            policy = source / "backend/.ccvm-auth/auth-policy.json"

            def snapshot():
                return json.loads(backend_python(SNAPSHOT))

            def private_policy():
                return run("sudo", "-n", "python3", "-I", "-c", POLICY, str(policy)).stdout

            def update(*flags, success=True):
                result = run(
                    sys.executable,
                    "-",
                    "--target",
                    target,
                    "--host",
                    socket.gethostname().split(".")[0],
                    *flags,
                    cwd=source,
                    data=script,
                    timeout=120,
                    success=False,
                )
                # The updater prints hashes/paths/statuses only, never runtime env values.
                print(result.stdout.decode(errors="replace"), flush=True)
                if success and result.returncode:
                    print(result.stderr.decode(errors="replace")[-4000:], flush=True)
                    raise AssertionError("Reviewed CLI-only enrollment update failed")
                return result

            before, identity, policy_before = snapshot(), runtime_identity(), private_policy()
            assert before["auth_users"]["count"] == before["auth_sessions"]["count"] == 1
            assert before["audit_credentials"]["count"] == 1
            update()
            assert not marker.exists()
            assert run("git", "rev-parse", "HEAD", cwd=source).stdout.decode().strip() == BASE
            assert snapshot() == before and runtime_identity() == identity
            # A real old root CLI process holds exactly the bind-mounted admin lock.
            holding = subprocess.Popen(
                [
                    "docker",
                    "exec",
                    "-i",
                    "--workdir",
                    "/app",
                    BACKEND_NAME,
                    "python",
                    "-c",
                    "import sys;from app.auth_admin import admin_lock\n"
                    "with admin_lock():\n print('locked',flush=True);sys.stdin.readline()",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                assert select.select([holding.stdout], [], [], 15)[
                    0
                ], "Admin lock holder did not start"
                assert holding.stdout.readline() == b"locked\n"
                refused = update("--apply", success=False)
                assert refused.returncode != 0
                assert not marker.exists()
                assert run("git", "rev-parse", "HEAD", cwd=source).stdout.decode().strip() == BASE
            finally:
                holding.communicate(b"release\n", timeout=10)
                assert holding.returncode == 0
            update("--apply")
            record = json.loads(marker.read_text())
            assert record["phase"] == "verified" and record["target"] == target
            assert run("git", "rev-parse", "HEAD", cwd=source).stdout.decode().strip() == target
            assert (
                backend_python(
                    "from app.auth_admin import ENROLLMENT_UI_VERSION;"
                    "assert ENROLLMENT_UI_VERSION==2;print('reviewed enrollment UI 2')"
                )
                == "reviewed enrollment UI 2"
            )
            assert snapshot() == before and runtime_identity() == identity
            assert private_policy() == policy_before
            assert_health()
            verified_marker = marker.read_bytes()
            update("--apply", "--resume")
            update()
            assert marker.read_bytes() == verified_marker
            record["phase"] = "published"
            marker.write_text(json.dumps(record))
            marker.chmod(0o600)
            update("--apply", "--resume")
            assert json.loads(marker.read_text())["phase"] == "verified"
            assert snapshot() == before and runtime_identity() == identity
            assert private_policy() == policy_before
            assert protected == {
                name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in protected
            }
            assert_health()
            print(
                "VERIFIED: CLI-only enrollment publication, busy-lock refusal, "
                "active account/session "
                "and encrypted credentials preserved, unchanged backend PID/container, resume and "
                "idempotence; no migration, image replacement or restart",
                flush=True,
            )
        finally:
            if backend_created:
                docker("rm", "--force", "--volumes", BACKEND_NAME, success=False)
            if postgres_created:
                docker("rm", "--force", "--volumes", postgres_name, success=False)
            if network_created:
                docker("network", "rm", network, success=False)
            if image_created:
                docker("image", "rm", image, success=False)
            if source.exists():
                run(
                    "sudo",
                    "-n",
                    "chown",
                    "--recursive",
                    "--no-dereference",
                    f"{os.getuid()}:{os.getgid()}",
                    str(source),
                    success=False,
                )


if __name__ == "__main__":
    main()
