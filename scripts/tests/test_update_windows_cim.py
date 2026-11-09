"""CIM publication preserves the selected login mode and every retained row."""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


op = load("cim_inventory_updater", "update-windows-cim.py")
original = load("cim_inventory_original", "deploy-authenticated-inventory.py")


def driver():
    return load("cim_inventory_driver", "update-host-inventory.py")


def snapshot():
    return {
        "revision": op.REVISION,
        "identity": {"database": "disposable-ci-only"},
        "active": [],
        "transactions": 0,
        "tables": {
            name: {"count": 2, "sha256": "retained-" + name}
            for name in (
                "jobs",
                "audit_credentials",
                "host_audits",
                "host_assessments",
                "software_assessments",
                "auth_users",
                "auth_sessions",
                "auth_login_limits",
            )
        },
    }


class NoSchemaOrPrivateEvidenceChanges(unittest.TestCase):
    def test_populated_authentication_sessions_credentials_and_evidence_are_preserved(self):
        before = snapshot()
        op.preserve_rows(before, copy.deepcopy(before))
        self.assertEqual(op.OLD_REVISION, op.REVISION)
        for name in before["tables"]:
            changed = copy.deepcopy(before)
            changed["tables"][name]["sha256"] = "modified-row"
            with self.subTest(table=name), self.assertRaisesRegex(RuntimeError, "rows or tables"):
                op.preserve_rows(before, changed)

    def test_schema_identity_missing_or_extra_tables_are_refused(self):
        for change in ("revision", "identity", "missing", "extra"):
            changed = snapshot()
            if change == "revision":
                changed["revision"] = "other-head"
            elif change == "identity":
                changed["identity"]["database"] = "other-database"
            elif change == "missing":
                del changed["tables"]["auth_sessions"]
            else:
                changed["tables"]["unexpected"] = {"count": 0}
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                op.preserve_rows(snapshot(), changed)

    def test_source_boundary_has_no_migration_dependencies_or_runtime_replacement(self):
        for path in (
            "backend/alembic/versions/arbitrary.py",
            "backend/requirements.txt",
            "backend/Dockerfile.worker",
            "docker-compose.yml",
            "frontend/default.conf",
            "frontend/package.json",
        ):
            with self.subTest(path=path):
                self.assertNotIn(path, op.ALLOWED)
                self.assertFalse(path.startswith(op.PREFIXES))

    def test_authentication_assets_and_old_publisher_helpers_remain_immutable(self):
        root = Path("/synthetic/repository")
        enrollment = SimpleNamespace(ASSETS={"backend/app/auth_admin.py"})
        with (
            patch.object(op, "load_helper", return_value=enrollment),
            patch.object(op, "git", return_value="same-reviewed-blob"),
        ):
            op.validate_fixed_source(root, "a" * 40)
        with (
            patch.object(op, "load_helper", return_value=enrollment),
            patch.object(op, "git", side_effect=["changed-blob", "retained-blob"]),
            self.assertRaisesRegex(RuntimeError, "authentication enrollment"),
        ):
            op.validate_fixed_source(root, "a" * 40)
        with (
            patch.object(op, "load_helper", return_value=SimpleNamespace(ASSETS=set())),
            patch.object(op, "git", side_effect=["changed-helper", "retained-helper"]),
            self.assertRaisesRegex(RuntimeError, "publication helpers"),
        ):
            op.validate_fixed_source(root, "a" * 40)


class RetainedPredecessor(unittest.TestCase):
    def setup_chain(self, directory, *, base=op.LOGIN_BASE, enrollment=None):
        root = Path(directory)
        record = {
            "phase": "verified",
            "version": "1.0.0",
            "host": "fixture",
            "target": op.LOGIN_BASE,
        }
        (root / op.PRIOR_JOURNAL).write_text(json.dumps(record))
        if enrollment is not None:
            (root / op.ENROLLMENT_JOURNAL).write_text(json.dumps(enrollment))
        previous, retained = Mock(), Mock()
        login = SimpleNamespace(
            VERSION="1.0.0",
            previous_update=Mock(return_value="workspace-base"),
            configure=Mock(),
        )
        enrolled = SimpleNamespace(validate_record=Mock())
        runtime = SimpleNamespace(root=root, reviewed_target="a" * 40)
        modules = [login, retained, enrolled]
        return root, previous, retained, login, enrolled, runtime, modules, base

    def validate(self, fixture):
        root, previous, retained, login, enrolled, runtime, modules, base = fixture
        with patch.object(op, "load_helper", side_effect=modules):
            result = op.previous_update(previous, original, runtime, {}, root, "fixture", base)
        return result, previous, retained, login, enrolled

    def test_login_release_without_enrollment_journal_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.setup_chain(directory)
            result, _previous, retained, login, enrolled = self.validate(fixture)
        self.assertEqual(result, op.LOGIN_BASE)
        login.previous_update.assert_called_once()
        retained.validate_record.assert_called_once()
        retained.retained.assert_called_once()
        retained.validate_artifacts.assert_called_once()
        enrolled.validate_record.assert_not_called()

    def test_enrollment_and_probe_releases_require_the_verified_enrollment_journal(self):
        for base in (op.ENROLLMENT_BASE, op.PROBE_BASE):
            with self.subTest(base=base), tempfile.TemporaryDirectory() as directory:
                fixture = self.setup_chain(directory, base=base)
                with self.assertRaisesRegex(RuntimeError, "lacks its verified"):
                    self.validate(fixture)
            with self.subTest(base=base), tempfile.TemporaryDirectory() as directory:
                fixture = self.setup_chain(directory, base=base, enrollment={"phase": "verified"})
                result, _previous, _retained, _login, enrolled = self.validate(fixture)
                self.assertEqual(result, base)
                enrolled.validate_record.assert_called_once()

    def test_unfinished_enrollment_and_unreviewed_source_stop_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.setup_chain(
                directory, base=op.ENROLLMENT_BASE, enrollment={"phase": "published"}
            )
            with self.assertRaisesRegex(RuntimeError, "Complete the retained"):
                self.validate(fixture)
        with (
            patch.object(op, "load_helper") as helper,
            self.assertRaisesRegex(RuntimeError, "not a reviewed"),
        ):
            op.previous_update(Mock(), original, Mock(), {}, Path("/tmp"), "fixture", "b" * 40)
        helper.assert_not_called()


class ConfigurationAndActivation(unittest.TestCase):
    def configure(self, previous, runtime, directory):
        login = SimpleNamespace(configure=Mock(), policy_state=Mock(return_value={"mode": "local"}))
        enrollment = SimpleNamespace(protected_config=Mock(return_value={"private": "hash"}))
        with patch.object(op, "load_helper", side_effect=[login, enrollment]):
            op.configure(previous, original, runtime, directory, op.LOGIN_BASE)
        return login, enrollment

    def test_preflight_preserves_local_auth_mode_and_creates_no_database_or_backup_work(self):
        previous, runtime = driver(), Mock()
        previous.prepare = Mock(return_value={"base": "old-base"})
        with tempfile.TemporaryDirectory() as directory:
            login, _enrollment = self.configure(previous, runtime, Path(directory))
            with (
                patch.object(op.tempfile, "mkdtemp") as backup,
                patch.object(original, "database_environment") as environment,
                patch.object(original, "write_json") as write,
            ):
                result = previous.prepare(original, runtime, {}, "a" * 40, None)
        self.assertEqual(result["base"], op.LOGIN_BASE)
        login.policy_state.assert_called_once()
        backup.assert_not_called()
        environment.assert_not_called()
        write.assert_not_called()
        runtime.docker.assert_not_called()
        self.assertEqual(previous.state_code(original), original.STATE_CODE)
        self.assertEqual((previous.OLD_REVISION, previous.REVISION), (op.REVISION, op.REVISION))

    def test_incomplete_source_target_is_refused_before_build_or_publication(self):
        previous, runtime = driver(), Mock()
        previous.source_plan = Mock(return_value=["docs/windows-cim-inventory.md"])
        with tempfile.TemporaryDirectory() as directory:
            self.configure(previous, runtime, Path(directory))
            with self.assertRaisesRegex(RuntimeError, "complete CIM collection source"):
                previous.source_plan(Path(directory), "a" * 40, op.LOGIN_BASE)
        runtime.docker.assert_not_called()

    def test_capture_attests_prior_journals_auth_policy_and_private_runtime_hashes(self):
        previous, runtime = driver(), Mock()
        previous.capture_private = Mock(return_value={"retained": "data"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / op.PRIOR_JOURNAL).write_bytes(b"private-login-journal")
            (root / op.ENROLLMENT_JOURNAL).write_bytes(b"private-enrollment-journal")
            _login, enrollment = self.configure(previous, runtime, root)
            with patch.object(op, "policy_fingerprint", return_value={"sha256": "private-hash"}):
                result = previous.capture_private(original, runtime, {})
        self.assertEqual(result["auth-policy-fingerprint"], {"sha256": "private-hash"})
        self.assertEqual(result["retained-private-config-hashes"], {"private": "hash"})
        self.assertEqual(result["retained"], "data")
        self.assertIn("prior-secure-login-journal", result)
        self.assertIn("prior-enrollment-journal", result)
        enrollment.protected_config.assert_called_once_with(runtime.root)

    def test_quiesced_publication_runs_same_schema_path_without_alembic(self):
        previous, runtime = Mock(), Mock()
        clients = load("cim_activation_clients", "update-windows-clients.py")
        state = snapshot()
        previous.work_operation.return_value = {"built_frontend": "/synthetic/frontend"}
        previous.read_state.return_value = state
        previous.assert_migrated = Mock()
        previous.VERIFICATION_LABEL = "cim"
        previous.VERIFIED_LABEL = "cim"
        record = {
            "phase": "quiesced",
            "before": state,
            "backup": "/synthetic/backup",
            "attempt_dir": "/synthetic/attempt",
            "target": "b" * 40,
            "base": op.LOGIN_BASE,
            "application_ids": {"backend": "retained-backend", "worker": "retained-worker"},
        }
        previous.write_phase.side_effect = lambda _o, _m, item, phase: item.update(phase=phase)
        runtime.inspect.side_effect = lambda name: {
            "Id": "retained-" + name.removeprefix("ccvm-"),
            "State": {"Running": True},
        }
        with (
            patch.object(op, "load_helper", return_value=clients),
            patch.object(clients, "git", return_value=record["target"]),
            patch.object(original, "write_json"),
            patch.object(original, "close_application"),
        ):
            op.activate(
                previous, original, runtime, {"images": {"backend": "retained"}}, record, Mock()
            )
        self.assertEqual(record["phase"], "verified")
        self.assertEqual(previous.read_state.call_count, 3)
        runtime.helper.assert_not_called()
        runtime.docker.assert_not_called()
        previous.assert_migrated.assert_not_called()
        previous.verify.assert_called_once()

    def test_verified_repeat_only_verifies_without_restart_or_rebuild(self):
        previous, runtime = Mock(), Mock()
        clients = load("cim_repeat_clients", "update-windows-clients.py")
        previous.work_operation.return_value = {}
        record = {"phase": "verified", "backup": "/synthetic/backup", "target": "a" * 40}
        with patch.object(op, "load_helper", return_value=clients):
            op.activate(previous, original, runtime, {}, record, Mock())
        previous.verify.assert_called_once()
        previous.build.assert_not_called()
        previous.quiesce.assert_not_called()
        previous.read_state.assert_not_called()
        runtime.helper.assert_not_called()
        runtime.docker.assert_not_called()

    def test_changed_rows_fail_before_source_frontend_or_service_mutations(self):
        previous, runtime = Mock(), Mock()
        clients = load("cim_changed_rows_clients", "update-windows-clients.py")
        previous.work_operation.return_value = {}
        after = snapshot()
        after["tables"]["auth_users"]["sha256"] = "changed-auth-account"
        previous.read_state.return_value = after
        record = {"phase": "quiesced", "before": snapshot(), "backup": "/synthetic/backup"}
        with (
            patch.object(op, "load_helper", return_value=clients),
            patch.object(original, "close_application"),
            self.assertRaisesRegex(RuntimeError, "rows or tables"),
        ):
            op.activate(previous, original, runtime, {}, record, Mock())
        previous.write_phase.assert_not_called()
        runtime.legacy.publish_frontend.assert_not_called()
        runtime.helper.assert_not_called()
        runtime.docker.assert_not_called()

    def test_api_probe_reads_contracts_without_scanning_or_authentication(self):
        runtime = Mock()
        runtime.docker.side_effect = [
            json.dumps(
                {
                    "modes": [
                        "connection",
                        "inventory",
                        "windows_updates",
                        "cim_connection",
                        "cim_inventory",
                    ],
                    "transport": {"default": "https", "enum": ["https", "http_ntlm"]},
                    "provider": "cim",
                }
            ),
            "cim-provider-ready",
        ]
        op.verify_cim_api(runtime)
        self.assertEqual(runtime.docker.call_count, 2)
        for call in runtime.docker.call_args_list:
            self.assertIn("exec", call.args)
            self.assertNotIn("run", call.args)
            self.assertNotIn("collect(", call.args[-1])
        runtime.helper.assert_not_called()
        runtime.docker.side_effect = [json.dumps({"modes": ["inventory"]})]
        with self.assertRaisesRegex(RuntimeError, "CIM collection modes"):
            op.verify_cim_api(runtime)


if __name__ == "__main__":
    unittest.main()
