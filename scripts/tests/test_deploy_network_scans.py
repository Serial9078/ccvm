"""Guard the pinned Neptun rollout and single, explicitly scoped first submission."""

import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / "deploy-network-scans.py"
spec = importlib.util.spec_from_file_location("network_deploy_operator", SCRIPT)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)
operator.configure(
    {"id": 1, "uuid": "11111111-1111-4111-8111-111111111111", "name": "CI Customer"},
    "192.0.2.0/24",
    "sha256:" + "a" * 64,
    "sha256:" + "b" * 64,
)


def snapshot():
    return {
        "identity": {"database": "disposable"},
        "revision": operator.OLD_REVISION,
        "customer": dict(operator.CUSTOMER),
        "active": [],
        "transactions": [],
        "indexes": [
            {
                "name": "uq_urls_domain_url_sha256",
                "unique": True,
                "valid": True,
                "definition": "CREATE INDEX ... sha256(...)",
            }
        ],
        "tables": {
            "ports": {"count": 1, "sha256": "old columns unchanged"},
            "jobs": {"count": 2, "sha256": "old jobs unchanged"},
        },
    }


def migrated(before):
    after = copy.deepcopy(before)
    after["revision"] = operator.REVISION
    after["port_evidence"] = 0
    for name in ("network_scans", "network_observations"):
        after["tables"][name] = {"count": 0, "sha256": "empty"}
    return after


def service_fixture():
    image = {
        "Config": {
            "Env": ["LANG=C.UTF-8"],
            "Cmd": ["python"],
            "Entrypoint": None,
            "WorkingDir": "/app",
            "User": "",
        }
    }
    config = {
        "services": {
            "worker": {
                "image": "old-worker:local",
                "command": ["python", "worker.py"],
                "environment": {"DB_PASS": "private-test-value"},
                "restart": "unless-stopped",
                "networks": {"default": None},
                "volumes": [{"type": "bind", "source": "/private/backend", "target": "/app"}],
            }
        },
        "networks": {"default": {"name": "private_network"}},
    }
    container = {
        "Config": {
            "Env": ["LANG=C.UTF-8", "DB_PASS=private-test-value"],
            "Image": "old-worker:local",
            "Cmd": ["python", "worker.py"],
            "Entrypoint": None,
            "WorkingDir": "/app",
            "User": "",
        },
        "HostConfig": {
            "Privileged": False,
            "ReadonlyRootfs": False,
            "PortBindings": {},
            "RestartPolicy": {"Name": "unless-stopped"},
        },
        "Mounts": [
            {"Type": "bind", "Source": "/private/backend", "Destination": "/app", "RW": True}
        ],
        "NetworkSettings": {"Networks": {"private_network": {}}},
    }
    return config, container, image


class NetworkDeploymentGuards(unittest.TestCase):
    def test_only_the_confirmed_idle_customer_schema_and_url_identity_are_accepted(self):
        operator.validate_state(snapshot(), expected=operator.OLD_REVISION)
        changes = [
            {"active": [{"id": 125}]},
            {"customer": {**operator.CUSTOMER, "uuid": "other"}},
            {"revision": "unexpected"},
            {"indexes": []},
        ]
        for changeset in changes:
            with self.subTest(changeset=changeset), self.assertRaises(RuntimeError):
                operator.validate_state({**snapshot(), **changeset})

    def test_migration_preserves_old_rows_and_only_adds_empty_tables_and_defaults(self):
        before = snapshot()
        after = migrated(before)
        operator.assert_preserved(before, after)
        for mutation in ("row", "identity", "new-run", "port-metadata"):
            wrong = copy.deepcopy(after)
            if mutation == "row":
                wrong["tables"]["ports"]["sha256"] = "changed"
            elif mutation == "identity":
                wrong["identity"] = {"database": "different"}
            elif mutation == "new-run":
                wrong["tables"]["network_scans"]["count"] = 1
            else:
                wrong["port_evidence"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                operator.assert_preserved(before, wrong)

    def test_private_compose_drift_is_refused_without_printing_environment_values(self):
        config, container, image = service_fixture()
        operator.validate_service(config, "worker", container, image)
        for mutation in ("env", "command", "mount", "network", "image", "privileged", "port"):
            wrong = copy.deepcopy(container)
            if mutation == "env":
                wrong["Config"]["Env"].append("EXTRA_PRIVATE=do-not-print")
            elif mutation == "command":
                wrong["Config"]["Cmd"] = ["different"]
            elif mutation == "mount":
                wrong["Mounts"][0]["RW"] = False
            elif mutation == "network":
                wrong["NetworkSettings"]["Networks"] = {"other": {}}
            elif mutation == "image":
                wrong["Config"]["Image"] = "other"
            elif mutation == "privileged":
                wrong["HostConfig"]["Privileged"] = True
            else:
                wrong["HostConfig"]["PortBindings"] = {"22/tcp": [{"HostPort": "22"}]}
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError) as error:
                operator.validate_service(config, "worker", wrong, image)
            self.assertNotIn("private", str(error.exception))
            self.assertNotIn("do-not-print", str(error.exception))

    def test_override_changes_only_two_images_and_the_single_approved_cidr(self):
        value = operator.build_override("old-backend", "extended-worker")
        self.assertEqual(set(value["services"]), {"backend", "worker"})
        for service in value["services"].values():
            self.assertEqual(set(service), {"image", "environment", "pull_policy"})
            self.assertEqual(service["environment"], {"CCVM_NETWORK_ALLOWED_CIDRS": "192.0.2.0/24"})
            self.assertEqual(service["pull_policy"], "never")

    def test_omitted_restart_policy_matches_dockers_explicit_no_default(self):
        config, container, image = service_fixture()
        config["services"]["worker"].pop("restart")
        container["HostConfig"]["RestartPolicy"]["Name"] = "no"
        operator.validate_service(config, "worker", container, image)

    def test_frontend_publish_keeps_bind_directory_and_previous_client_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "build", root / "existing"
            source.mkdir()
            destination.mkdir()
            (source / "assets").mkdir()
            (destination / "assets").mkdir()
            (source / "index.html").write_text("new html")
            (source / "assets/new.js").write_text("new client")
            (destination / "index.html").write_text("old html")
            (destination / "assets/old.js").write_text("old client")
            inode = destination.stat().st_ino
            operator.install_frontend(source, destination)
            self.assertEqual(destination.stat().st_ino, inode)
            self.assertEqual((destination / "index.html").read_text(), "new html")
            self.assertEqual((destination / "assets/old.js").read_text(), "old client")
            (destination / "assets/new.js").unlink()
            (destination / "assets/new.js").symlink_to(root / "outside")
            with self.assertRaisesRegex(RuntimeError, "Symlink"):
                operator.install_frontend(source, destination)

    def test_lost_post_response_and_completed_run_never_create_a_second_scan(self):
        run = {
            **operator.PAYLOAD,
            "id": 1,
            "pipeline_id": "original-pipeline",
            "address_count": 254,
            "jobs": [],
            "status": "finished",
        }
        for lose_response in (False, True):
            with self.subTest(lose_response=lose_response), tempfile.TemporaryDirectory() as folder:
                marker = Path(folder) / "journal.json"
                operation = {"phase": "activated"}
                runs, posts = [], []

                def request(
                    runtime,
                    path,
                    *,
                    payload=None,
                    runs=runs,
                    marker=marker,
                    posts=posts,
                    lose_response=lose_response,
                    **kwargs,
                ):
                    if path.startswith("/api/v1/customers/"):
                        return dict(operator.CUSTOMER)
                    if path.endswith("/preview"):
                        return {"target": operator.CIDR, "address_count": 254}
                    if path.endswith("?customer_id=1"):
                        return list(runs)
                    if payload is not None:
                        self.assertEqual(json.loads(marker.read_text())["phase"], "scan-intent")
                        self.assertEqual(payload, operator.PAYLOAD)
                        posts.append(payload)
                        runs.append(run)
                        if lose_response:
                            raise TimeoutError("response lost after commit")
                    return copy.deepcopy(run)

                with (
                    patch.object(operator, "verify_api"),
                    patch.object(operator, "request", request),
                ):
                    with contextlib.redirect_stdout(io.StringIO()):
                        if lose_response:
                            with self.assertRaises(TimeoutError):
                                operator.start_once(None, marker, operation)
                            operation = json.loads(marker.read_text())
                        operator.start_once(None, marker, operation)
                        operator.start_once(None, marker, json.loads(marker.read_text()))
                self.assertEqual(len(posts), 1)

    def test_private_configuration_and_journal_are_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "docker-compose.yml").write_text("private settings")
            capture = operator.capture_config(root)
            operator.assert_config(root, capture)
            (root / "docker-compose.yml").write_text("changed")
            with self.assertRaises(RuntimeError):
                operator.assert_config(root, capture)
            marker = root / "operation.json"
            operator.write_json(marker, {"phase": "scan-intent"})
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)


class NetworkDeploymentGitGuards(unittest.TestCase):
    def test_only_ff_source_updates_preserve_private_files_and_refuse_collisions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)

            def git(*args):
                return (
                    subprocess.check_output(
                        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL
                    )
                    .decode()
                    .strip()
                )

            git("init", "-b", operator.BRANCH)
            git("config", "user.name", "Disposable test")
            git("config", "user.email", "test@example.invalid")
            (root / "backend/app").mkdir(parents=True)
            (root / "backend/app/main.py").write_text("base")
            (root / "docker-compose.yml").write_text("tracked compose")
            git("add", ".")
            git("commit", "-m", "base")
            base = git("rev-parse", "HEAD")
            git("switch", "-c", "incoming")
            (root / "backend/app/main.py").write_text("reviewed incoming")
            (root / "backend/app/new.py").write_text("reviewed new module")
            git("add", ".")
            git("commit", "-m", "reviewed")
            target = git("rev-parse", "HEAD")
            git("switch", operator.BRANCH)
            git("update-ref", f"refs/remotes/origin/{operator.BRANCH}", target)
            (root / "docker-compose.yml").write_text("private compose")
            module = type("Git", (), {"git": staticmethod(lambda root, *args: git(*args))})
            with patch.object(operator, "BASE", base), patch.object(operator, "FEATURE", base):
                plan = operator.source_plan(module, root, target)
                self.assertEqual(plan[0], base)
                (root / "backend/app/new.py").write_text("unreviewed collision")
                with self.assertRaisesRegex(RuntimeError, "untracked"):
                    operator.source_plan(module, root, target)
                self.assertEqual((root / "docker-compose.yml").read_text(), "private compose")


class NetworkDeploymentSequence(unittest.TestCase):
    def exercise(self, fail=None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / ".git").mkdir()
            (root / "frontend/dist").mkdir(parents=True)
            (root / "frontend/dist/index.html").write_text("old frontend")
            (root / "docker-compose.yml").write_text("private source")
            actions = []
            config = {
                "services": {
                    "backend": {"image": "original-backend"},
                    "worker": {"image": "original-worker"},
                }
            }

            def git(root, *args):
                if args == ("rev-parse", "--absolute-git-dir"):
                    return str(root / ".git")
                actions.append("advance-source")
                return ""

            def build(module, runtime, root, target, backup):
                actions.append("build")
                built = backup / "built"
                built.mkdir()
                (built / "index.html").write_text("new frontend")
                return "fixture-new-worker", built

            class Runtime:
                def __init__(self):
                    self.snapshot = snapshot()
                    self.paused, self.api = False, True
                    self.worker_image = operator.WORKER_IMAGE
                    self.worker_info = self.info("worker")
                    self.opener = SimpleNamespace(
                        open=lambda *a, **k: io.BytesIO(
                            (root / "frontend/dist/index.html").read_bytes()
                        )
                    )

                def info(self, name):
                    return {
                        "Image": self.worker_image if name == "worker" else operator.BACKEND_IMAGE,
                        "State": {"Running": True},
                        "Config": {
                            "Env": [],
                            "Labels": {
                                "com.docker.compose.project": "ccvm",
                                "com.docker.compose.project.config_files": str(
                                    root / "docker-compose.yml"
                                ),
                                "com.docker.compose.project.working_dir": str(root),
                            },
                        },
                    }

                def preflight(self, root):
                    return copy.deepcopy(self.snapshot)

                def prepare_maintenance(self, backup):
                    actions.append("helper")

                def state(self):
                    return copy.deepcopy(self.snapshot)

                def freeze(self):
                    actions.append("pause")
                    self.paused = True

                def resume(self):
                    actions.append("resume")
                    self.paused = False

                def database_backup(self, path):
                    assert self.paused and not self.api
                    actions.append("backup")
                    if fail == "backup":
                        raise RuntimeError("backup failed")
                    path.write_bytes(b"verified dump")

                def migrate(self):
                    assert self.paused and not self.api and "backup" in actions
                    actions.append("migrate")
                    if fail == "migration":
                        raise RuntimeError("migration failed")
                    self.snapshot = migrated(self.snapshot)
                    if fail == "fingerprint":
                        self.snapshot["tables"]["ports"]["sha256"] = "changed"

                def docker(self, *args):
                    if args[0] == "inspect":
                        return json.dumps(
                            self.info("worker" if args[-1] == "ccvm-worker" else "backend")
                        )
                    if args[0] == "image":
                        return json.dumps([{"Id": "new-worker-image"}])
                    if args[0] in {"stop", "start"}:
                        self.api = args[0] == "start"
                        actions.append("start-api" if self.api else "stop-api")
                    if args[0] == "compose":
                        if "config" in args:
                            resolved = copy.deepcopy(config)
                            if (root / operator.OVERRIDE).exists():
                                for name, changes in json.loads(
                                    (root / operator.OVERRIDE).read_text()
                                )["services"].items():
                                    resolved["services"][name].update(changes)
                            return json.dumps(resolved)
                        name = args[-1]
                        actions.append("replace-" + name)
                        if name == "worker":
                            if fail == "replace-worker":
                                raise RuntimeError("replacement failed")
                            self.worker_image = "new-worker-image"
                        else:
                            self.api = True
                    return ""

            runtime = Runtime()

            def verify(runtime):
                actions.append("verify-api")
                if fail == "api":
                    raise RuntimeError("API failed")

            def publish(runtime, root, built):
                actions.append("publish")
                operator.install_frontend(built, root / "frontend/dist")

            module = SimpleNamespace(git=git)
            plan = operator.BASE, ["backend/app/main.py"]
            with (
                patch.object(operator, "source_plan", return_value=plan),
                patch.object(operator, "build_artifacts", build),
                patch.object(operator, "validate_service"),
                patch.object(operator, "verify_api", verify),
                patch.object(operator, "publish_frontend", publish),
                patch.object(
                    operator, "start_once", side_effect=lambda *a: actions.append("queue")
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                if fail:
                    with self.assertRaises(RuntimeError):
                        operator.apply(module, runtime, root, "c" * 40, plan)
                else:
                    operator.apply(module, runtime, root, "c" * 40, plan)
            self.assertEqual((root / "docker-compose.yml").read_text(), "private source")
            if fail:
                self.assertNotIn("queue", actions)
                if fail == "backup":
                    self.assertNotIn("advance-source", actions)
                    self.assertTrue(runtime.api)
                    self.assertFalse(runtime.paused)
                else:
                    self.assertFalse(runtime.api)
                    self.assertTrue(runtime.paused)
            else:
                expected = [
                    "build",
                    "helper",
                    "stop-api",
                    "pause",
                    "backup",
                    "advance-source",
                    "migrate",
                    "resume",
                    "replace-worker",
                    "replace-backend",
                    "verify-api",
                    "publish",
                    "queue",
                ]
                self.assertEqual(actions, expected)

    def test_artifacts_backup_migration_replacements_and_submission_have_safe_order(self):
        self.exercise()

    def test_failures_keep_scans_unsubmitted_and_unknown_runtime_closed(self):
        for stage in ("backup", "migration", "fingerprint", "replace-worker", "api"):
            with self.subTest(stage=stage):
                self.exercise(stage)


if __name__ == "__main__":
    unittest.main()
