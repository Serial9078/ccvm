"""Same-schema publication keeps every retained row and prior release journal."""

import copy
import importlib.util
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


op = load("clients_updater", "update-windows-clients.py")
original = load("overview_original", "deploy-authenticated-inventory.py")


def helper():
    return load("overview_driver", "update-host-inventory.py")


def snapshot():
    return {
        "revision": op.REVISION,
        "identity": {"database": "synthetic-ci-database"},
        "active": [],
        "transactions": 0,
        "tables": {
            name: {"count": 2, "sha256": "retained-" + name}
            for name in (
                "jobs",
                "findings",
                "audit_credentials",
                "host_audits",
                "windows_patch_catalogs",
                "host_assessments",
                "software_advisory_catalogs",
                "software_assessments",
            )
        },
    }


class SameSchemaPublication(unittest.TestCase):
    def test_all_populated_catalogs_assessments_and_transport_rows_are_retained(self):
        before = snapshot()
        op.preserve_rows(before, copy.deepcopy(before))
        self.assertEqual(op.OLD_REVISION, op.REVISION)
        self.assertEqual(op.NEW_TABLES, set())
        for table in before["tables"]:
            changed = copy.deepcopy(before)
            changed["tables"][table]["sha256"] += "-changed"
            with self.subTest(table=table), self.assertRaisesRegex(RuntimeError, "rows or tables"):
                op.preserve_rows(before, changed)

    def test_rejects_schema_identity_added_or_dropped_tables(self):
        for change in ("revision", "identity", "added", "dropped"):
            after = snapshot()
            if change == "revision":
                after["revision"] = "unexpected"
            elif change == "identity":
                after["identity"]["database"] = "unexpected"
            elif change == "added":
                after["tables"]["unexpected"] = {"count": 0, "sha256": "empty"}
            else:
                del after["tables"]["software_advisory_catalogs"]
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                op.preserve_rows(snapshot(), after)

    def test_configuration_preserves_full_snapshot_including_http_transport(self):
        previous = helper()
        with tempfile.TemporaryDirectory() as directory:
            op.configure(previous, original, Mock(), Path(directory), "b" * 40)
        self.assertEqual(previous.state_code(original), original.STATE_CODE)
        previous.assert_migrated(original, Mock(), {}, {"before": snapshot()}, snapshot())

    def test_preflight_creates_no_backup_or_database_or_target_work(self):
        previous, runtime = helper(), Mock()
        previous.prepare = Mock(return_value={"base": "a" * 40})
        with tempfile.TemporaryDirectory() as directory:
            op.configure(previous, original, runtime, Path(directory), "b" * 40)
            with (
                patch.object(original, "database_environment") as env,
                patch.object(original, "write_json") as write,
                patch.object(op.tempfile, "mkdtemp") as backup,
            ):
                result = previous.prepare(original, runtime, {}, "c" * 40, None)
            self.assertEqual(result["base"], "b" * 40)
            env.assert_not_called()
            write.assert_not_called()
            backup.assert_not_called()
        runtime.helper.assert_not_called()
        runtime.docker.assert_not_called()

    def test_quiesced_publication_verifies_schema_without_running_alembic(self):
        previous, runtime = Mock(), Mock()
        state = snapshot()
        previous.work_operation.return_value = {"built_frontend": "/synthetic/frontend"}
        previous.read_state.return_value = state
        previous.VERIFICATION_LABEL = "overview"
        previous.VERIFIED_LABEL = "overview"
        previous.assert_migrated = Mock()
        record = {
            "phase": "quiesced",
            "before": state,
            "backup": "/synthetic/backup",
            "attempt_dir": "/synthetic/attempt",
            "target": "b" * 40,
            "base": "a" * 40,
            "application_ids": {"backend": "retained-backend", "worker": "retained-worker"},
        }
        previous.write_phase.side_effect = lambda _o, _m, item, phase: item.update(phase=phase)
        runtime.inspect.side_effect = lambda name: {
            "Id": "retained-" + name.removeprefix("ccvm-"),
            "State": {"Running": True},
        }
        with (
            patch.object(op, "git", return_value=record["target"]),
            patch.object(original, "write_json"),
            patch.object(original, "close_application"),
        ):

            op.activate(
                previous, original, runtime, {"images": {"backend": "retained"}}, record, Mock()
            )
        self.assertEqual(record["phase"], "verified")
        runtime.helper.assert_not_called()
        runtime.docker.assert_not_called()
        previous.assert_migrated.assert_not_called()
        self.assertEqual(previous.read_state.call_count, 3)
        previous.verify.assert_called_once()

    def test_changed_rows_stop_before_source_or_frontend_publication(self):
        previous, runtime = Mock(), Mock()
        previous.work_operation.return_value = {}
        changed = snapshot()
        changed["tables"]["software_assessments"]["sha256"] = "changed"
        previous.read_state.return_value = changed
        record = {"phase": "quiesced", "before": snapshot(), "backup": "/synthetic/backup"}
        with (
            patch.object(original, "close_application"),
            self.assertRaisesRegex(RuntimeError, "rows or tables"),
        ):
            op.activate(previous, original, runtime, {}, record, Mock())
        runtime.helper.assert_not_called()
        runtime.docker.assert_not_called()
        runtime.legacy.publish_frontend.assert_not_called()
        previous.write_phase.assert_not_called()

    def test_verified_repeat_does_not_build_quiesce_migrate_or_restart(self):
        previous, runtime = Mock(), Mock()
        previous.work_operation.return_value = {}
        record = {"phase": "verified", "backup": "/synthetic/backup", "target": "a" * 40}
        op.activate(previous, original, runtime, {}, record, Mock())
        previous.verify.assert_called_once()
        previous.build.assert_not_called()
        previous.quiesce.assert_not_called()
        previous.read_state.assert_not_called()
        runtime.helper.assert_not_called()
        runtime.docker.assert_not_called()

    def test_api_verification_reads_only_the_contract(self):
        runtime, prior_verify = Mock(), Mock()
        runtime.docker.return_value = json.dumps(
            {
                "mode": {"enum": ["connection", "inventory", "windows_updates"]},
                "paths": [
                    "/api/v1/host-audits/overview",
                    "/api/v1/host-audits/capabilities",
                    "/api/v1/host-audits/discovered",
                    "/api/v1/host-audits/software-catalog",
                    "/api/v1/host-audits/{audit_id}/assess-software",
                    "/api/v1/host-audits/{audit_id}/software-assessments",
                ],
                "schemas": [
                    "SoftwareAssessmentOut",
                    "SoftwareCatalogOut",
                    "SoftwareAssessmentCreate",
                    "ScannerCapabilitiesOut",
                    "DiscoveredDevicesOut",
                ],
            }
        )
        op.verify_clients_api(runtime, prior_verify)
        prior_verify.assert_called_once_with(runtime)
        self.assertIn("app.openapi()", runtime.docker.call_args.args[-1])
        runtime.helper.assert_not_called()
        runtime.docker.return_value = '{"paths":[],"schemas":[]}'
        with self.assertRaisesRegex(RuntimeError, "Windows clients"):
            op.verify_clients_api(runtime, prior_verify)


class RetainedReleaseChain(unittest.TestCase):
    """Extend the actual three-journal fixture with the fourth retained release."""

    fixture = load("clients_overview_fixture", "tests/test_update_inventory_overview.py")
    driver = fixture.RealPublicationChain.driver
    record = fixture.RealPublicationChain.record
    encoded = fixture.RealPublicationChain.encoded
    write = fixture.RealPublicationChain.write
    tearDown = fixture.RealPublicationChain.tearDown

    def setUp(self):
        self.fixture.RealPublicationChain.setUp(self)
        self.overview = load("clients_prior_overview", "update-inventory-overview.py")
        driver = self.driver()
        self.overview.configure(driver, original, self.runtime, self.root, "d" * 40)
        self.overview_record = self.record(
            op.PRIOR_JOURNAL,
            "ccvm-inventory-overview-before-",
            "e" * 40,
            "d" * 40,
            driver.capture_private(original, self.runtime, self.operation),
        )

    def validate(self):
        with (
            patch.object(op, "load_helper", side_effect=[self.overview, self.driver()]),
            patch.object(self.overview, "load_helper", side_effect=[self.software, self.driver()]),
            patch.object(self.software, "load_helper", return_value=self.windows),
            patch.object(original, "validate_secrets") as secrets,
            patch.object(original, "assert_retained") as retained,
        ):
            target = op.previous_update(
                self.driver(), original, self.runtime, self.operation, self.root, "fixture"
            )
        return target, secrets, retained

    def test_all_four_journals_and_artifact_trees_are_validated(self):
        target, secrets, retained = self.validate()
        self.assertEqual(target, self.overview_record["target"])
        self.assertEqual(secrets.call_count, 4)
        self.assertEqual(retained.call_count, 4)
        self.runtime.docker.assert_not_called()

    def test_capture_binds_every_retained_journal_and_rejects_drift(self):
        for name in (
            op.PRIOR_JOURNAL,
            op.SOFTWARE_JOURNAL,
            op.WINDOWS_JOURNAL,
            op.INVENTORY_JOURNAL,
        ):
            with self.subTest(journal=name):
                driver = self.driver()
                op.configure(driver, original, self.runtime, self.root, "e" * 40)
                captured = driver.capture_private(original, self.runtime, self.operation)
                self.assertEqual(len(captured), 5)
                path = self.root / name
                before = path.read_bytes()
                path.write_bytes(before + b" ")
                with (
                    patch.object(original, "validate_secrets"),
                    patch.object(original, "assert_retained"),
                    self.assertRaisesRegex(RuntimeError, "journal changed"),
                ):
                    driver.retained(
                        original,
                        self.runtime,
                        self.operation,
                        {"private_files": captured, "retained_ids": {}},
                    )
                path.write_bytes(before)

    def test_prior_overview_requires_verified_matching_parameters_and_private_files(self):
        for change in (
            {"phase": "services"},
            {"version": "next"},
            {"host": "other"},
            {"target": "not-a-sha"},
            {"base": "f" * 40},
            {"private_files": {"ingress": "edited"}},
        ):
            self.write(op.PRIOR_JOURNAL, {**self.overview_record, **change})
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.validate()
            self.write(op.PRIOR_JOURNAL, self.overview_record)

    def test_each_retained_artifact_tree_rejects_drift(self):
        for record in self.records:
            for name in ("backend", "frontend/dist"):
                path = Path(record["backup"]) / "release" / name / "fixture"
                before = path.read_bytes()
                path.write_bytes(b"changed retained source")
                with (
                    self.subTest(target=record["target"], name=name),
                    self.assertRaises(RuntimeError),
                ):
                    self.validate()
                path.write_bytes(before)

    def test_new_record_binds_exact_base_target_host_and_phase(self):
        driver = self.driver()
        op.configure(driver, original, self.runtime, self.root, "e" * 40)
        record = self.record(
            op.JOURNAL,
            op.BACKUP_PREFIX,
            "f" * 40,
            "e" * 40,
            driver.capture_private(original, self.runtime, self.operation),
        )
        marker = self.root / op.JOURNAL
        driver.validate_record(record, marker, "f" * 40, "fixture", "e" * 40)
        for change in (
            {"target": "a" * 40},
            {"base": "a" * 40},
            {"host": "other"},
            {"version": "next"},
            {"phase": "unknown"},
        ):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                driver.validate_record({**record, **change}, marker, "f" * 40, "fixture", "e" * 40)


class SourceBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous = helper()
        op.configure(self.previous, original, Mock(), self.root, "b" * 40)
        self.git("init", "-b", self.previous.BRANCH)
        self.git("config", "user.name", "Overview fixture")
        self.git("config", "user.email", "fixture@example.test")
        self.write("backend/app/services/host_inventory.py", "# retained release\n")
        self.git("add", ".")
        self.git("commit", "-m", "retained")
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
        self.write("backend/app/api/v1/host_overview.py", "# reviewed protected overview\n")
        self.write("frontend/src/shared/theme/theme.ts", "// reviewed platform routing\n")
        if extra:
            self.write(extra, "outside review\n")
        self.git("add", ".")
        self.git("commit", "-m", "overview")
        target = self.git("rev-parse", "HEAD")
        self.git("reset", "--hard", self.base)
        self.git("update-ref", "refs/remotes/origin/" + self.previous.BRANCH, target)
        return target

    def test_exact_overview_navigation_source_is_allowed(self):
        self.previous.source_plan(self.root, self.target(), self.base)

    def test_dependencies_schema_ingress_and_public_findings_changes_are_refused(self):
        for name in (
            "backend/requirements.txt",
            "backend/alembic/versions/unreviewed.py",
            "docker-compose.yml",
            "backend/app/api/v1/findings.py",
            "backend/app/services/software_catalog_sync.py",
        ):
            with self.subTest(path=name), self.assertRaisesRegex(RuntimeError, "unrelated source"):
                self.previous.source_plan(self.root, self.target(name), self.base)


if __name__ == "__main__":
    unittest.main()
