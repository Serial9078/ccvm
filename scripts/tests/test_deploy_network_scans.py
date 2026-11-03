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


if __name__ == "__main__":
    unittest.main()
