"""Verify the legacy Docker 24 socket mount through a disposable nested daemon."""

import contextlib
import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

NGINX = "nginx:1.27.5-alpine"
DIND = "docker:24.0.5-dind"


def command(*args, success=True, timeout=120):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if success and result.returncode:
        raise AssertionError(f"Fixture command failed: {args[:3]}\n{result.stderr[-5000:]}")
    return result


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or not re.fullmatch(
        r"[1-9][0-9]+", os.environ.get("GITHUB_RUN_ID", "")
    ):
        raise RuntimeError("Nested Docker regression is restricted to GitHub Actions")
    identity = "ccvm-mount-ci-" + uuid.uuid4().hex[:12]
    volume = identity + "-data"
    # The DinD wrapper mounts its own /tmp; keep the shared fixture outside it.
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    if not runner_temp.is_dir() or runner_temp.is_relative_to(Path("/tmp")):
        raise RuntimeError("Expected the runner's shared temporary directory outside /tmp")
    with tempfile.TemporaryDirectory(prefix=identity + "-", dir=runner_temp) as temporary:
        root = Path(temporary)
        directory = root / "socket"
        directory.mkdir()
        config = root / "gateway.conf"
        config.write_text("""server {
    listen unix:/run/ccvm/gateway.sock;
    location / { return 200 'mount fixture'; }
}
""")

        def docker(*args, **kwargs):
            return command("docker", *args, **kwargs)

        def inner(*args, **kwargs):
            return docker("exec", identity, "docker", *args, **kwargs)

        def state():
            return json.loads(inner("inspect", "--format", "{{json .}}", "gateway").stdout)

        def remove_gateway():
            inner("rm", "-f", "gateway", success=False)
            docker("exec", identity, "rm", "-f", str(directory / "gateway.sock"))

        def start(destination):
            inner(
                "run",
                "-d",
                "--name",
                "gateway",
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/var/cache/nginx",
                "--tmpfs",
                "/var/run",
                "--tmpfs",
                "/tmp",
                "--mount",
                f"type=bind,src={config},dst=/etc/nginx/conf.d/default.conf,readonly",
                "--mount",
                f"type=bind,src={directory},dst={destination}",
                NGINX,
            )

        try:
            docker("volume", "create", volume)
            # Nested dockerd has its own data/socket and exposes no TCP ports or host socket.
            docker(
                "run",
                "-d",
                "--privileged",
                "--name",
                identity,
                "--mount",
                f"type=volume,src={volume},dst=/var/lib/docker",
                "--mount",
                f"type=bind,src={root},dst={root}",
                "--env",
                "DOCKER_TLS_CERTDIR=",
                DIND,
                "dockerd",
                "--host=unix:///var/run/docker.sock",
                "--storage-driver=vfs",
                "--iptables=false",
                "--bridge=none",
            )
            for _ in range(60):
                ready = inner("version", "--format", "{{.Server.Version}}", success=False)
                if ready.returncode == 0:
                    assert ready.stdout.strip() == "24.0.5", ready.stdout
                    break
                time.sleep(1)
            else:
                raise AssertionError("Disposable Docker 24 daemon did not start")
            docker("exec", identity, "test", "-f", str(config))
            inner("pull", NGINX, timeout=180)
            alias = inner(
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "readlink",
                NGINX,
                "-f",
                "/var/run",
            ).stdout.strip()
            assert alias == "/run", alias
            docker("exec", identity, "chown", "0:0", str(directory))
            docker("exec", identity, "chmod", "2750", str(directory))

            start("/run/ccvm")
            for _ in range(30):
                old = state()
                if old["State"]["Status"] == "exited":
                    break
                time.sleep(0.2)
            logged = inner("logs", "gateway")
            old_logs = logged.stdout + logged.stderr
            print("Legacy layout state:", old["State"]["Status"], flush=True)
            print(old_logs[-3000:], flush=True)
            # Record platform-dependent legacy behavior; the corrected layout must always work.
            remove_gateway()
            start("/var/run/ccvm")
            for _ in range(60):
                fixed = state()
                socket_exists = command(
                    "sudo", "-n", "test", "-S", str(directory / "gateway.sock"), success=False
                )
                if fixed["State"]["Running"] and socket_exists.returncode == 0:
                    break
                if fixed["State"]["Status"] == "exited":
                    raise AssertionError("Corrected gateway exited before creating its socket")
                time.sleep(0.2)
            else:
                raise AssertionError("Corrected gateway did not create its host Unix socket")
            started = fixed["State"]["StartedAt"]
            time.sleep(2)
            stable = state()
            assert stable["State"]["Running"] and not stable["State"]["Restarting"]
            assert stable["State"]["StartedAt"] == started and stable["RestartCount"] == 0
            socket_mode = command("sudo", "-n", "stat", "-c", "%u:%g %a", str(directory)).stdout
            assert socket_mode.strip() == "0:0 2750", socket_mode
            response = command(
                "sudo",
                "-n",
                "curl",
                "-fsS",
                "--max-time=5",
                "--noproxy",
                "*",
                "--unix-socket",
                str(directory / "gateway.sock"),
                "http://localhost/",
            )
            assert response.stdout == "mount fixture", response.stdout
            print(
                "VERIFIED: Docker 24, readonly nginx, /var/run alias and protected host socket",
                flush=True,
            )
        except BaseException:
            for args in (
                ("logs", "--tail", "50", identity),
                ("exec", identity, "docker", "logs", "--tail", "50", "gateway"),
            ):
                result = docker(*args, success=False)
                print(result.stdout + result.stderr, flush=True)
            raise
        finally:
            command(
                "sudo",
                "-n",
                "chown",
                "-R",
                f"{os.getuid()}:{os.getgid()}",
                str(root),
                success=False,
            )
            for cleanup in (
                ("stop", "--time", "10", identity),
                ("rm", "-f", "--volumes", identity),
                ("volume", "rm", volume),
            ):
                with contextlib.suppress(Exception):
                    docker(*cleanup, timeout=30, success=False)


if __name__ == "__main__":
    main()
