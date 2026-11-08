"""Secure login publication retains the workspace, evidence, secrets and ingress."""

import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


op = load("secure_login_updater", "update-secure-login.py")
original = load("secure_login_original", "deploy-authenticated-inventory.py")
workspace_fixture = load("secure_login_workspace_fixture", "tests/test_update_host_workspace.py")


def driver():
    return load("secure_login_driver", "update-host-inventory.py")


def workspace():
    return load("secure_login_workspace", "update-host-workspace.py")


def configure(previous, runtime, directory, application_base):
    prior = workspace()
    with (
        patch.object(op, "load_helper", return_value=prior),
        patch.object(prior, "load_helper", return_value=workspace_fixture.clients()),
    ):
        op.configure(previous, original, runtime, directory, application_base)


def before():
    return workspace_fixture.clients_fixture.snapshot()


def after():
    result = before()
    result["revision"] = op.REVISION
    result["tables"].update({name: {"count": 0, "sha256": "empty"} for name in op.NEW_TABLES})
    return result


class DatabaseContract(unittest.TestCase):
    def test_only_three_empty_authentication_tables_are_added(self):
        op.preserve_rows(before(), before())
        op.preserve_rows(before(), after())
        for table in before()["tables"]:
            altered = after()
            altered["tables"][table]["sha256"] = "changed-private-or-public-evidence"
            with self.subTest(table=table), self.assertRaisesRegex(RuntimeError, "rows changed"):
                op.preserve_rows(before(), altered)

    def test_rejects_nonempty_auth_tables_wrong_schema_identity_missing_and_extra_tables(self):
        for field in ("revision", "identity", "missing", "extra", *op.NEW_TABLES):
            altered = after()
            if field == "revision":
                altered[field] = "unexpected"
            elif field == "identity":
                altered[field]["database"] = "other"
            elif field == "missing":
                del altered["tables"]["auth_sessions"]
            elif field == "extra":
                altered["tables"]["unexpected"] = {"count": 0}
            else:
                altered["tables"][field]["count"] = 1
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                op.preserve_rows(before(), altered)

    def test_configured_driver_preserves_every_existing_column_and_migrates_the_auth_head(self):
        previous = driver()
        with tempfile.TemporaryDirectory() as directory:
            configure(previous, Mock(), Path(directory), "b" * 40)
        self.assertEqual(previous.state_code(original), original.STATE_CODE)
        self.assertEqual((previous.OLD_REVISION, previous.REVISION), (op.OLD_REVISION, op.REVISION))
        previous.assert_migrated(original, Mock(), {}, {"before": before()}, after())
        self.assertNotEqual(previous.JOURNAL, op.JOURNAL)


class RetainedChain(unittest.TestCase):
    fixture = workspace_fixture.RetainedReleaseChain.fixture
    driver = workspace_fixture.RetainedReleaseChain.driver
    record = workspace_fixture.RetainedReleaseChain.record
    encoded = workspace_fixture.RetainedReleaseChain.encoded
    write = workspace_fixture.RetainedReleaseChain.write
    tearDown = workspace_fixture.RetainedReleaseChain.tearDown

    def setUp(self):
        workspace_fixture.RetainedReleaseChain.setUp(self)
        self.workspace = workspace()
        previous = self.driver()
        with patch.object(self.workspace, "load_helper", return_value=workspace_fixture.clients()):
            self.workspace.configure(previous, original, self.runtime, self.root, "1" * 40)
        self.workspace_record = self.record(
            op.PRIOR_JOURNAL,
            self.workspace.BACKUP_PREFIX,
            "2" * 40,
            "1" * 40,
            previous.capture_private(original, self.runtime, self.operation),
        )

    def validate(self):
        with (
            patch.object(op, "load_helper", side_effect=[self.workspace, self.driver()]),
            patch.object(
                self.workspace,
                "load_helper",
                side_effect=[self.clients, self.driver(), workspace_fixture.clients()],
            ),
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

    def test_validates_all_six_prior_journals_and_uses_workspace_as_exact_base(self):
        target, secrets, retained = self.validate()
        self.assertEqual(target, self.workspace_record["target"])
        self.assertEqual(secrets.call_count, 6)
        self.assertEqual(retained.call_count, 6)
        self.runtime.docker.assert_not_called()

    def test_drift_in_any_prior_artifact_or_journal_refuses_a_new_publication(self):
        path = self.root / op.PRIOR_JOURNAL
        original_bytes = path.read_bytes()
        self.write(op.PRIOR_JOURNAL, {**self.workspace_record, "phase": "services"})
        with self.assertRaisesRegex(RuntimeError, "verified previous host workspace"):
            self.validate()
        path.write_bytes(original_bytes)
        for record in self.records:
            artifact = Path(record["backup"]) / "release/backend/fixture"
            contents = artifact.read_bytes()
            artifact.write_bytes(contents + b"changed")
            with self.subTest(target=record["target"]), self.assertRaises(RuntimeError):
                self.validate()
            artifact.write_bytes(contents)


class PublicationAndActivation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.runtime = Mock(root=self.directory, reviewed_target="f" * 40)
        self.previous = driver()

    def tearDown(self):
        self.temporary.cleanup()

    def test_read_only_preflight_creates_no_backup_and_requires_unactivated_policy(self):
        self.previous.prepare = Mock(return_value={"base": "a" * 40})
        configure(self.previous, self.runtime, self.directory, "b" * 40)
        with (
            patch.object(op, "policy_state", return_value={"mode": "legacy"}),
            patch.object(original, "database_environment") as environment,
            patch.object(original, "write_json") as write,
            patch.object(op.tempfile, "mkdtemp") as backup,
        ):
            result = self.previous.prepare(original, self.runtime, {}, "c" * 40, None)
        self.assertEqual(result["base"], "b" * 40)
        environment.assert_not_called()
        write.assert_not_called()
        backup.assert_not_called()
        with (
            patch.object(op, "policy_state", return_value={"mode": "local"}),
            self.assertRaisesRegex(RuntimeError, "retained token mode"),
        ):
            self.previous.prepare(original, self.runtime, {}, "c" * 40, None)

    def test_verified_repeat_does_not_bootstrap_reset_build_migrate_or_restart(self):
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

    def test_root_policy_inspection_accepts_only_legacy_or_the_retained_https_origin(self):
        self.runtime.privileged = ["sudo", "-n"]
        self.runtime.diagnostic = self.directory / "private.log"
        for result in ({"mode": "legacy"}, {"mode": "local", "origin": "https://ui.example.test"}):
            with patch.object(original, "run", return_value=json.dumps(result).encode()) as run:
                self.assertEqual(
                    op.policy_state(original, self.runtime, {"hostname": "ui.example.test"}), result
                )
                self.assertEqual(run.call_args.args[0][:4], ["sudo", "-n", "python3", "-I"])
        with (
            patch.object(
                original, "run", return_value=b'{"mode":"local","origin":"https://other.test"}'
            ),
            self.assertRaisesRegex(RuntimeError, "origin differs"),
        ):
            op.policy_state(original, self.runtime, {"hostname": "ui.example.test"})

    def test_policy_probe_rejects_a_symlink_instead_of_falling_back_to_legacy(self):
        parent = self.directory / "backend/.ccvm-auth"
        parent.mkdir(parents=True)
        policy = parent / "auth-policy.json"
        policy.symlink_to(self.directory / "missing-policy")
        with (
            patch("sys.argv", ["policy-probe", str(self.directory)]),
            patch("sys.stdout", io.StringIO()),
            self.assertRaises((OSError, RuntimeError)),
        ):
            exec(compile(op.POLICY_PROBE, "<policy-probe>", "exec"), {})


class SourceContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous = driver()
        self.previous.ALLOWED, self.previous.PREFIXES = op.ALLOWED, op.PREFIXES
        self.git("init", "-b", self.previous.BRANCH)
        self.git("config", "user.name", "Login deployment fixture")
        self.git("config", "user.email", "fixture@example.test")
        self.write("backend/app/main.py", "# retained workspace\n")
        self.git("add", ".")
        self.git("commit", "-m", "retained workspace")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args):
        return (
            subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.PIPE)
            .decode()
            .strip()
        )

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def target(self, extra=None):
        self.write("backend/app/services/auth_session.py", "# reviewed secure sessions\n")
        self.write("frontend/src/shared/auth/session.tsx", "// reviewed login\n")
        if extra:
            self.write(extra, "unrelated source or configuration\n")
        self.git("add", ".")
        self.git("commit", "-m", "secure login")
        target = self.git("rev-parse", "HEAD")
        self.git("reset", "--hard", self.base)
        self.git("update-ref", "refs/remotes/origin/" + self.previous.BRANCH, target)
        return target

    def test_secure_login_source_and_frontend_are_explicitly_allowed(self):
        self.previous.source_plan(self.root, self.target(), self.base)

    def test_unrelated_application_dependencies_scanners_secrets_and_ingress_are_refused(self):
        for name in (
            "backend/requirements.txt",
            "backend/app/plugins/nucleiurl.py",
            "backend/.ccvm-auth/auth-policy.json",
            "docker-compose.authenticated.yml",
            "scripts/authenticated_ingress.py",
        ):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "unrelated source"):
                self.previous.source_plan(self.root, self.target(name), self.base)


if __name__ == "__main__":
    unittest.main()
