"""A UI publication retains the complete verified clients release and runtime."""

import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


op = load("workspace_updater", "update-host-workspace.py")
original = load("workspace_original", "deploy-authenticated-inventory.py")
clients_fixture = load("workspace_clients_fixture", "tests/test_update_windows_clients.py")


def driver():
    return load("workspace_driver", "update-host-inventory.py")


def clients():
    return load("workspace_clients", "update-windows-clients.py")


def configure(previous, runtime, directory, application_base):
    with patch.object(op, "load_helper", return_value=clients()):
        op.configure(previous, original, runtime, directory, application_base)


class RetainedReleaseChain(unittest.TestCase):
    fixture = clients_fixture.RetainedReleaseChain.fixture
    driver = clients_fixture.RetainedReleaseChain.driver
    record = clients_fixture.RetainedReleaseChain.record
    encoded = clients_fixture.RetainedReleaseChain.encoded
    write = clients_fixture.RetainedReleaseChain.write
    tearDown = clients_fixture.RetainedReleaseChain.tearDown

    def setUp(self):
        clients_fixture.RetainedReleaseChain.setUp(self)
        self.clients = clients()
        previous = self.driver()
        self.clients.configure(previous, original, self.runtime, self.root, "e" * 40)
        self.clients_record = self.record(
            op.PRIOR_JOURNAL,
            self.clients.BACKUP_PREFIX,
            "1" * 40,
            "e" * 40,
            previous.capture_private(original, self.runtime, self.operation),
        )

    def validate(self):
        with (
            patch.object(op, "load_helper", side_effect=[self.clients, self.driver()]),
            patch.object(self.clients, "load_helper", side_effect=[self.overview, self.driver()]),
            patch.object(self.overview, "load_helper", side_effect=[self.software, self.driver()]),
            patch.object(self.software, "load_helper", return_value=self.windows),
            patch.object(original, "validate_secrets") as secrets,
            patch.object(original, "assert_retained") as retained,
        ):
            target = op.previous_update(
                self.driver(), original, self.runtime, self.operation, self.root, "fixture"
            )
        return target, secrets, retained

    def test_all_five_journals_are_validated_before_selecting_the_exact_clients_base(self):
        target, secrets, retained = self.validate()
        self.assertEqual(target, self.clients_record["target"])
        self.assertNotEqual(target, self.operation["target"])
        self.assertNotEqual(target, self.overview_record["target"])
        self.assertEqual(secrets.call_count, 5)
        self.assertEqual(retained.call_count, 5)
        self.assertEqual(self.clients.BACKUP_PREFIX, "ccvm-windows-clients-before-")
        self.runtime.docker.assert_not_called()

    def test_new_capture_binds_all_five_predecessors_and_rejects_any_byte_drift(self):
        for name in (
            op.PRIOR_JOURNAL,
            self.clients.PRIOR_JOURNAL,
            self.clients.SOFTWARE_JOURNAL,
            self.clients.WINDOWS_JOURNAL,
            self.clients.INVENTORY_JOURNAL,
        ):
            with self.subTest(journal=name):
                previous = self.driver()
                configure(previous, self.runtime, self.root, self.clients_record["target"])
                captured = previous.capture_private(original, self.runtime, self.operation)
                self.assertEqual(len(captured), 6)
                path = self.root / name
                before = path.read_bytes()
                path.write_bytes(before + b" ")
                with (
                    patch.object(original, "validate_secrets"),
                    patch.object(original, "assert_retained"),
                    self.assertRaisesRegex(RuntimeError, "journal changed"),
                ):
                    previous.retained(
                        original,
                        self.runtime,
                        self.operation,
                        {"private_files": captured, "retained_ids": {}},
                    )
                path.write_bytes(before)

    def test_client_record_requires_verified_matching_parameters_and_private_bindings(self):
        for change in (
            {"phase": "services"},
            {"version": "next"},
            {"host": "other"},
            {"target": "not-a-sha"},
            {"base": "f" * 40},
            {"private_files": {"ingress": "edited"}},
        ):
            self.write(op.PRIOR_JOURNAL, {**self.clients_record, **change})
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.validate()
            self.write(op.PRIOR_JOURNAL, self.clients_record)

    def test_every_retained_source_and_built_frontend_tree_rejects_drift(self):
        for record in self.records:
            for name in ("backend", "frontend/dist"):
                path = Path(record["backup"]) / "release" / name / "fixture"
                before = path.read_bytes()
                path.write_bytes(b"unexpected retained source drift")
                with (
                    self.subTest(target=record["target"], name=name),
                    self.assertRaises(RuntimeError),
                ):
                    self.validate()
                path.write_bytes(before)

    def test_new_workspace_record_cannot_reuse_a_predecessor_journal_or_backup(self):
        previous = self.driver()
        configure(previous, self.runtime, self.root, self.clients_record["target"])
        record = self.record(
            op.JOURNAL,
            op.BACKUP_PREFIX,
            "2" * 40,
            self.clients_record["target"],
            previous.capture_private(original, self.runtime, self.operation),
        )
        marker = self.root / op.JOURNAL
        previous.validate_record(record, marker, "2" * 40, "fixture", "1" * 40)
        self.assertNotEqual(op.JOURNAL, op.PRIOR_JOURNAL)
        for change in (
            {"target": "a" * 40},
            {"base": "e" * 40},
            {"host": "other"},
            {"phase": "unknown"},
            {"backup": self.clients_record["backup"]},
        ):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                previous.validate_record(
                    {**record, **change}, marker, "2" * 40, "fixture", "1" * 40
                )


class PublicationContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.runtime = Mock(root=self.directory, reviewed_target="f" * 40)
        self.previous = driver()

    def tearDown(self):
        self.temporary.cleanup()

    def test_default_preflight_returns_before_backup_or_any_publication(self):
        self.previous.prepare = Mock(return_value={"base": "a" * 40})
        configure(self.previous, self.runtime, self.directory, "b" * 40)
        with (
            patch.object(original, "database_environment") as environment,
            patch.object(original, "write_json") as write,
            patch.object(tempfile, "mkdtemp") as backup,
        ):
            record = self.previous.prepare(original, self.runtime, {}, "c" * 40, None)
        self.assertEqual(record["base"], "b" * 40)
        environment.assert_not_called()
        write.assert_not_called()
        backup.assert_not_called()
        self.runtime.helper.assert_not_called()
        self.runtime.docker.assert_not_called()

    def test_active_jobs_refuse_preparation_before_creating_any_backup(self):
        configure(self.previous, self.runtime, self.directory, "b" * 40)
        self.runtime.inspect.return_value = {"Id": "retained"}
        self.runtime.docker.return_value = "ccvm-worker"
        self.previous.read_state = Mock(
            return_value={"revision": op.REVISION, "active": [{"id": 9, "status": "running"}]}
        )
        with (
            patch.object(original, "verify_runtime"),
            patch.object(original, "worker_identity"),
            patch.object(tempfile, "mkdtemp") as backup,
            self.assertRaisesRegex(RuntimeError, "Active jobs"),
        ):
            self.previous.prepare(original, self.runtime, {}, "c" * 40, self.directory / op.JOURNAL)
        backup.assert_not_called()
        self.assertEqual(self.runtime.docker.call_count, 1)

    def test_full_database_identity_schema_and_every_row_must_remain_exact(self):
        configure(self.previous, self.runtime, self.directory, "b" * 40)
        before = clients_fixture.snapshot()
        self.previous.preserve_rows(before, copy.deepcopy(before))
        for change in ("revision", "identity", "row", "added", "dropped"):
            after = copy.deepcopy(before)
            if change == "revision":
                after["revision"] = "unexpected"
            elif change == "identity":
                after["identity"]["database"] = "different"
            elif change == "row":
                after["tables"]["audit_credentials"]["sha256"] = "different-secret-bytes"
            elif change == "added":
                after["tables"]["unexpected"] = {"count": 0, "sha256": "empty"}
            else:
                del after["tables"]["host_audits"]
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.previous.preserve_rows(before, after)
        self.assertEqual(self.previous.state_code(original), original.STATE_CODE)
        self.assertEqual(op.NEW_TABLES, set())

    def test_verified_repeat_only_checks_existing_publication(self):
        configure(self.previous, self.runtime, self.directory, "b" * 40)
        self.previous.retained = Mock()
        self.previous.verify = Mock()
        self.previous.build = Mock()
        self.previous.quiesce = Mock()
        record = {"phase": "verified", "backup": str(self.directory), "target": "c" * 40}
        op.activate(self.previous, original, self.runtime, {}, record, self.directory / op.JOURNAL)
        self.previous.verify.assert_called_once()
        self.previous.build.assert_not_called()
        self.previous.quiesce.assert_not_called()
        self.runtime.docker.assert_not_called()
        self.runtime.helper.assert_not_called()


class HttpsPublication(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.frontend = self.root / "release/frontend/dist"
        (self.frontend / "assets").mkdir(parents=True)
        for name, content in {
            "app.js": b"reviewed-app-script",
            "app.css": b"reviewed-styles",
            "cloudcollab-logo.jpg": b"reviewed-logo",
        }.items():
            (self.frontend / "assets" / name).write_bytes(content)
        self.index = (
            '<script src="/assets/app.js"></script><link rel="stylesheet" href="/assets/app.css">'
        )
        self.work = {
            "built_frontend": str(self.frontend),
            "clients": ["192.0.2.0/24"],
            "hostname": "ui.example.test",
            "tls_port": 4448,
            "target": "c" * 40,
            "images": {"backend": "retained-backend-image"},
        }
        self.runtime = Mock(root=self.root, reviewed_target="f" * 40)
        self.update_index(self.index)

    def tearDown(self):
        self.temporary.cleanup()

    def update_index(self, value):
        (self.frontend / "index.html").write_text(value)
        self.record = {
            "backup": str(self.root),
            "phase": "services",
            "target": "f" * 40,
            "artifacts": {"frontend/dist": driver().directory_hashes(self.frontend)},
            "application_ids": {"backend": "retained-backend", "worker": "retained-worker"},
        }

    def test_https_probe_checks_exact_root_script_styles_and_logo_without_operator_credentials(
        self,
    ):
        self.runtime.docker.return_value = json.dumps({"ui": True, "assets": 3})
        op.verify_ui(self.runtime, self.work, self.record)
        args = self.runtime.docker.call_args
        self.assertIn("container:haproxy-edge", args.args)
        self.assertIn("--pull=never", args.args)
        self.assertIn("retained-backend-image", args.args)
        payload = json.loads(args.kwargs["data"])
        self.assertEqual(
            set(payload["files"]),
            {"/", "/assets/app.js", "/assets/app.css", "/assets/cloudcollab-logo.jpg"},
        )
        self.assertEqual(payload["client"], "192.0.2.1")
        self.assertNotIn("token", payload)
        self.assertEqual(
            payload["files"]["/assets/app.js"]["sha256"],
            hashlib.sha256(b"reviewed-app-script").hexdigest(),
        )
        self.runtime.helper.assert_not_called()

    def test_arbitrary_external_traversal_or_unrecorded_references_are_rejected_before_network(
        self,
    ):
        for path in (
            "https://external.example.test/app.js",
            "/assets/../private.env",
            "/assets/missing.js",
            "//external.example.test/app.js",
        ):
            self.update_index(f'<script src="{path}"></script>')
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, "unrecorded"):
                op.verify_ui(self.runtime, self.work, self.record)
        self.runtime.docker.assert_not_called()

    def test_entrypoint_changed_after_recording_is_rejected_before_network(self):
        (self.frontend / "index.html").write_text(self.index + "unexpected change")
        with self.assertRaisesRegex(RuntimeError, "entrypoint changed"):
            op.verify_ui(self.runtime, self.work, self.record)
        self.runtime.docker.assert_not_called()

    def run_probe(self, *, status=200, marker=None, body=b"reviewed-index"):
        expected = b"reviewed-index"
        payload = {
            "port": 4448,
            "hostname": "ui.example.test",
            "client": "192.0.2.1",
            "marker": "c" * 12,
            "files": {
                "/": {"bytes": len(expected), "sha256": hashlib.sha256(expected).hexdigest()}
            },
        }
        response = Mock(status=status)
        response.getheader.return_value = "c" * 12 if marker is None else marker
        response.read.side_effect = lambda limit: body[:limit]
        output = io.StringIO()
        with (
            patch("sys.stdin", io.StringIO(json.dumps(payload))),
            patch("sys.stdout", output),
            patch("socket.create_connection"),
            patch("ssl.create_default_context", return_value=MagicMock()),
            patch("http.client.HTTPResponse", return_value=response),
        ):
            exec(compile(op.UI_PROBE, "<ui-probe>", "exec"), {})
        return json.loads(output.getvalue())

    def test_real_probe_logic_rejects_unavailable_wrong_route_redirect_and_changed_bytes(self):
        self.assertEqual(self.run_probe(), {"ui": True, "assets": 0})
        for kwargs in (
            {"status": 503},
            {"status": 302},
            {"marker": "other-route"},
            {"body": b"wrong-ui-bytes"},
            {"body": b"reviewed-index-extra"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                self.run_probe(**kwargs)

    def test_failed_https_attestation_prevents_the_verified_phase(self):
        previous = driver()
        previous.verify = Mock()
        configure(previous, self.runtime, self.root, "b" * 40)
        previous.retained = Mock()
        previous.validate_artifacts = Mock()
        previous.write_phase = Mock(
            side_effect=lambda _o, _m, record, phase: record.update(phase=phase)
        )
        self.runtime.inspect.side_effect = lambda name: {
            "Id": "retained-" + name.removeprefix("ccvm-"),
            "State": {"Running": True},
        }
        self.runtime.docker.return_value = json.dumps({"ui": False, "assets": 0})
        with self.assertRaisesRegex(RuntimeError, "did not attest"):
            op.activate(
                previous, original, self.runtime, self.work, self.record, self.root / op.JOURNAL
            )
        self.assertEqual(self.record["phase"], "services")
        self.assertNotIn(
            "verified", [call.args[-1] for call in previous.write_phase.call_args_list]
        )


class SourceBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous = driver()
        configure(
            self.previous, Mock(root=self.root, reviewed_target="f" * 40), self.root, "b" * 40
        )
        self.git("init", "-b", self.previous.BRANCH)
        self.git("config", "user.name", "Workspace fixture")
        self.git("config", "user.email", "fixture@example.test")
        self.write("backend/app/services/host_inventory.py", "# unchanged clients release\n")
        self.git("add", ".")
        self.git("commit", "-m", "retained clients")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args):
        return (
            subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.PIPE)
            .decode()
            .strip()
        )

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def target(self, extra=None):
        self.write("frontend/src/features/host-audits/overview.tsx", "// reviewed workspace\n")
        self.write("scripts/update-host-workspace.py", "# reviewed UI-only updater\n")
        if extra:
            self.write(extra, "unrelated change\n")
        self.git("add", ".")
        self.git("commit", "-m", "workspace")
        target = self.git("rev-parse", "HEAD")
        self.git("reset", "--hard", self.base)
        self.git("update-ref", "refs/remotes/origin/" + self.previous.BRANCH, target)
        return target

    def test_only_the_reviewed_host_ui_and_companion_assets_are_allowed(self):
        self.previous.source_plan(self.root, self.target(), self.base)

    def test_backend_collectors_dependencies_schema_secrets_and_ingress_are_refused(self):
        for name in (
            "backend/app/services/host_inventory.py",
            "backend/app/api/v1/host_overview.py",
            "backend/requirements.txt",
            "backend/alembic/versions/unreviewed.py",
            "docker-compose.yml",
            "frontend/default.conf",
            "frontend/package.json",
            "scripts/update-windows-clients.py",
            "scripts/authenticated_ingress.py",
        ):
            with self.subTest(path=name), self.assertRaisesRegex(RuntimeError, "unrelated source"):
                self.previous.source_plan(self.root, self.target(name), self.base)

    def test_the_target_must_be_exactly_the_fetched_head_and_an_installed_base(self):
        target = self.target()
        self.git("update-ref", "refs/remotes/origin/" + self.previous.BRANCH, self.base)
        with self.assertRaisesRegex(RuntimeError, "Reviewed target"):
            self.previous.source_plan(self.root, target, self.base)
        self.git("update-ref", "refs/remotes/origin/" + self.previous.BRANCH, target)
        with self.assertRaisesRegex(RuntimeError, "Installed source"):
            self.previous.source_plan(self.root, target, "f" * 40)


if __name__ == "__main__":
    unittest.main()
