"""Real Compose recreation and in-place static publication, on CI's internal network."""

import importlib.util
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace


def assert_network_deployment(command, image, network, root):
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    script = Path(__file__).resolve().parents[2] / "scripts/deploy-network-scans.py"
    spec = importlib.util.spec_from_file_location("network_deploy_ci", script)
    operator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(operator)
    project = f"ccvm-deploy-ci-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    directory = root / "deployment"
    directory.mkdir()
    (directory / "scripts").mkdir()
    shutil.copy2(script, directory / "scripts/deploy-network-scans.py")
    release, build = directory / "frontend/dist", directory / "built"
    release.mkdir(parents=True)
    build.mkdir()
    (release / "index.html").write_text("original frontend")
    (release / "old.js").write_text("previous client")
    (build / "index.html").write_text("network frontend")
    (build / "new.js").write_text("network client")
    config = {
        "services": {
            name: {
                "image": image,
                "command": ["python", "-c", "import time; time.sleep(300)"],
                "environment": {"KEEP_PRIVATE_SETTING": "ci-only"},
            }
            for name in ("backend", "worker", "keep")
        },
        "networks": {"default": {"external": True, "name": network}},
    }
    config["services"]["keep"]["volumes"] = [
        {
            "type": "bind",
            "source": str(release),
            "target": "/public",
            "read_only": True,
        }
    ]
    base = directory / "docker-compose.yml"
    base.write_text(json.dumps(config))
    before_config = base.read_bytes()
    runtime = SimpleNamespace(docker=lambda *args: command("docker", *args))
    helper_image = project + "-root-helper:latest"

    def compose(*args, override=False):
        flags = [
            "docker",
            "compose",
            "--project-name",
            project,
            "--project-directory",
            str(directory),
            "--file",
            str(base),
        ]
        if override:
            flags += ["--file", str(directory / operator.OVERRIDE)]
        return command(*flags, *args)

    def container(name):
        return json.loads(command("docker", "inspect", compose("ps", "--quiet", name)))[0]

    try:
        compose("up", "-d", "--no-deps", "--no-build", "--pull", "never")
        old = {name: container(name) for name in config["services"]}
        original_image = json.loads(command("docker", "image", "inspect", image))[0]
        resolved = json.loads(compose("config", "--format", "json"))
        for name in ("backend", "worker"):
            operator.validate_service(resolved, name, old[name], original_image)
        pinned = original_image["Id"]
        operator.configure(
            {"id": 1, "uuid": "11111111-1111-4111-8111-111111111111", "name": "CI Customer"},
            "192.0.2.0/24",
            pinned,
            pinned,
        )
        operator.write_json(directory / operator.OVERRIDE, operator.build_override(pinned, image))
        for name in ("worker", "backend"):
            compose("up", "-d", "--no-deps", "--no-build", "--pull", "never", name, override=True)
        resolved = json.loads(compose("config", "--format", "json", override=True))
        for name in ("backend", "worker"):
            current = container(name)
            assert current["Id"] != old[name]["Id"] and current["Image"] == pinned
            operator.validate_service(resolved, name, current, original_image)
            assert operator.env_map(current["Config"]["Env"])["KEEP_PRIVATE_SETTING"] == "ci-only"
            assert (
                operator.env_map(current["Config"]["Env"])["CCVM_NETWORK_ALLOWED_CIDRS"]
                == operator.CIDR
            )
        keep = container("keep")
        assert keep["Id"] == old["keep"]["Id"]
        # Use the production publishing function through a real helper, against
        # the directory that the untouched container already mounted read-only.
        # Neptun's python image has an empty WorkingDir, which runs Python in /.
        # Reproduce that import environment instead of the worker image's /app.
        helper_context = directory / "helper-image"
        helper_context.mkdir()
        (helper_context / "Dockerfile").write_text(f"FROM {image}\nWORKDIR /\n")
        command("docker", "build", "--tag", helper_image, str(helper_context))
        operator.BACKEND_IMAGE = helper_image
        inode = release.stat().st_ino
        operator.publish_frontend(runtime, directory, build)
        assert release.stat().st_ino == inode
        assert (
            command("docker", "exec", keep["Id"], "cat", "/public/index.html") == "network frontend"
        )
        assert command("docker", "exec", keep["Id"], "cat", "/public/old.js") == "previous client"
        assert base.read_bytes() == before_config
        print(
            "Network deployment: real Compose replaced only backend/worker, kept private settings "
            "and the third container, and published through the existing read-only bind "
            "using a helper image with root WorkingDir",
            flush=True,
        )
    finally:
        # Remove only this unique disposable project; never address a production project.
        compose("down", "--timeout", "3", override=(directory / operator.OVERRIDE).exists())
        command("docker", "image", "rm", helper_image, check=False)
        # The root helper creates static files with nginx-readable modes.
        command(
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "python",
            "--mount",
            f"type=bind,src={directory},dst=/cleanup",
            image,
            "-B",
            "-c",
            "import os; "
            f"[os.chown(os.path.join(p,n),{os.getuid()},{os.getgid()}) "
            "for p,ds,fs in os.walk('/cleanup') for n in ds+fs]",
        )
