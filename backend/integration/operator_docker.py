"""Exercise actual Docker pause + one-shot Alembic maintenance only in isolated CI."""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def command(*args, data=None, check=True, timeout=240):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace")[-3000:])
    return result.stdout.decode().strip()


def assert_paused_worker_maintenance(url):
    # The caller already validates ci_database_url before opening the isolated DB.
    expected = f"ccvm_ci_{os.environ.get('GITHUB_RUN_ID')}_{os.environ.get('GITHUB_RUN_ATTEMPT')}"
    assert os.environ.get("GITHUB_ACTIONS") == "true" and url.database == expected
    assert url.host == "127.0.0.1" and url.username == "ccvm_ci"
    candidates = command(
        "docker", "ps", "--filter", "ancestor=postgres:16-alpine", "--format", "{{.ID}}"
    ).splitlines()
    selected = []
    for identifier in candidates:
        info = json.loads(command("docker", "inspect", "--format", "{{json .}}", identifier))
        settings = dict(item.split("=", 1) for item in info["Config"]["Env"] if "=" in item)
        ports = info["NetworkSettings"]["Ports"].get("5432/tcp") or []
        if settings.get("POSTGRES_DB") == expected and any(
            str(port["HostPort"]) == str(url.port) for port in ports
        ):
            selected.append(info)
    assert len(selected) == 1, "Expected exactly the disposable CI PostgreSQL service"
    postgres = selected[0]
    networks = postgres["NetworkSettings"]["Networks"]
    assert len(networks) == 1
    network, details = next(iter(networks.items()))
    container_url = url.set(host=details["IPAddress"], port=5432, query={"connect_timeout": "5"})
    suffix = f"{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    worker = f"ccvm-url-maint-ci-{suffix}"
    image = f"ccvm-url-maint-ci:{suffix}"
    spec = importlib.util.spec_from_file_location(
        "update_url_index_docker", BACKEND.parent / "scripts/update-url-index.py"
    )
    operator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(operator)
    runtime = object.__new__(operator.Runtime)
    runtime.prefix = ["docker"]
    runtime.worker_name = worker
    runtime.worker_paused = False
    runtime.maintenance_args = None
    created = False
    try:
        with tempfile.TemporaryDirectory(prefix="ccvm-operator-docker-ci-") as directory:
            root = Path(directory)
            shutil.copy2(BACKEND / "requirements.txt", root / "requirements.txt")
            (root / "Dockerfile").write_text(
                "FROM python:3.12-slim\n"
                "COPY requirements.txt /tmp/requirements.txt\n"
                "RUN pip install --no-cache-dir -r /tmp/requirements.txt\n"
                "WORKDIR /app\n"
            )
            command("docker", "build", "--tag", image, str(root), timeout=360)
            environment = root / "database.env"
            environment.write_text(
                "DATABASE_URL=" + container_url.render_as_string(hide_password=False) + "\n"
            )
            environment.chmod(0o600)
            command(
                "docker",
                "run",
                "--detach",
                "--rm",
                "--name",
                worker,
                "--network",
                network,
                "--env-file",
                str(environment),
                "--mount",
                f"type=bind,src={BACKEND},dst=/app,readonly",
                "--entrypoint",
                "python",
                image,
                "-c",
                "import time; time.sleep(300)",
            )
            created = True
            runtime.worker_info = json.loads(
                command("docker", "inspect", "--format", "{{json .}}", worker)
            )
            runtime.postgres_info = postgres
            backup = root / "backup"
            backup.mkdir(mode=0o700)
            runtime.prepare_maintenance(backup)
            before = runtime.state()
            operator.validate_state(before, expected=operator.REVISION)
            runtime.freeze()
            try:
                # No docker exec is possible while paused; all these calls use
                # the real same-image maintenance helper and read-only app mount.
                runtime.maintenance_python(
                    "from alembic import command; from alembic.config import Config; "
                    f"command.downgrade(Config('/app/alembic.ini'), {operator.OLD_REVISION!r})"
                )
                operator.validate_state(runtime.state(), expected=operator.OLD_REVISION)
                runtime.migrate()
                after = runtime.state()
                operator.validate_state(after, expected=operator.REVISION)
                assert before["tables"] == after["tables"], "Maintenance changed existing rows"
            finally:
                runtime.resume()
            assert runtime.worker_paused is False
            print(
                "Real Docker pause: same-image helper migrated PostgreSQL while worker stayed "
                "paused; rows preserved and unpause passed",
                flush=True,
            )
    finally:
        if created:
            command("docker", "unpause", worker, check=False)
            # Only the uniquely named disposable CI worker is removed.
            command("docker", "rm", "--force", worker, check=False)
        command("docker", "image", "rm", image, check=False)
