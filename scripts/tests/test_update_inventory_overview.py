"""Same-schema publication keeps every retained row and prior release journal."""

import base64
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


op = load("overview_updater", "update-inventory-overview.py")
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
                "paths": [
                    "/api/v1/host-audits/overview",
                    "/api/v1/host-audits/software-catalog",
                    "/api/v1/host-audits/{audit_id}/assess-software",
                    "/api/v1/host-audits/{audit_id}/software-assessments",
                ],
                "schemas": [
                    "SoftwareAssessmentOut",
                    "SoftwareCatalogOut",
                    "SoftwareAssessmentCreate",
                ],
            }
        )
        op.verify_overview_api(runtime, prior_verify)
        prior_verify.assert_called_once_with(runtime)
        self.assertIn("app.openapi()", runtime.docker.call_args.args[-1])
        runtime.helper.assert_not_called()
        runtime.docker.return_value = '{"paths":[],"schemas":[]}'
        with self.assertRaisesRegex(RuntimeError, "inventory overview"):
            op.verify_overview_api(runtime, prior_verify)


class RealPublicationChain(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.software = load("overview_real_software", "update-software-assessment.py")
        self.windows = load("overview_real_windows", "update-windows-patch-assessment.py")
        self.operation = {"target": "c" * 40, "private": str(self.root)}
        self.runtime = Mock(root=self.root, reviewed_target="f" * 40)
        self.records = []
        self.inventory_record = self.record(
            op.INVENTORY_JOURNAL,
            "ccvm-host-inventory-before-",
            "a" * 40,
            "c" * 40,
            {"ingress": "retained"},
        )
        self.windows_record = self.record(
            op.WINDOWS_JOURNAL,
            "ccvm-windows-patch-before-",
            "b" * 40,
            "a" * 40,
            {
                "ingress": "retained",
                "prior-inventory-update-journal": self.encoded(op.INVENTORY_JOURNAL),
            },
        )
        self.software_record = self.record(
            op.PRIOR_JOURNAL,
            "ccvm-software-assessment-before-",
            "d" * 40,
            "b" * 40,
            {
                "ingress": "retained",
                "prior-inventory-update-journal": self.encoded(op.INVENTORY_JOURNAL),
                "prior-windows-patch-journal": self.encoded(op.WINDOWS_JOURNAL),
            },
        )

    def tearDown(self):
        self.temporary.cleanup()

    def encoded(self, name):
        return base64.b64encode((self.root / name).read_bytes()).decode()

    def driver(self):
        driver = helper()
        driver.capture_private = Mock(side_effect=lambda *_args: {"ingress": "retained"})
        return driver

    def record(self, journal, prefix, target, base, private):
        backup = self.root / (prefix + "fixture")
        for name in ("backend", "frontend/dist"):
            directory = backup / "release" / name
            directory.mkdir(parents=True, mode=0o700)
            (directory / "fixture").write_text("retained reviewed release")
        backup.chmod(0o700)
        record = {
            "phase": "verified",
            "version": "1.0.0",
            "host": "fixture",
            "target": target,
            "base": base,
            "backup": str(backup),
            "private_files": private,
            "retained_ids": {},
            "artifacts": {
                name: helper().directory_hashes(backup / "release" / name)
                for name in ("backend", "frontend/dist")
            },
        }
        self.write(journal, record)
        self.records.append(record)
        return record

    def write(self, name, record):
        path = self.root / name
        path.write_text(json.dumps(record))
        path.chmod(0o600)

    def validate(self):
        software_driver = self.driver()
        with (
            patch.object(op, "load_helper", side_effect=[self.software, software_driver]),
            patch.object(self.software, "load_helper", return_value=self.windows),
            patch.object(original, "validate_secrets") as secrets,
            patch.object(original, "assert_retained") as retained,
        ):
            target = op.previous_update(
                self.driver(), original, self.runtime, self.operation, self.root, "fixture"
            )
        return target, secrets, retained

    def test_all_three_private_journals_and_artifact_trees_are_validated(self):
        target, secrets, retained = self.validate()
        self.assertEqual(target, self.software_record["target"])
        self.assertEqual(secrets.call_count, 3)
        self.assertEqual(retained.call_count, 3)
        self.runtime.docker.assert_not_called()

    def test_new_capture_binds_each_prior_journal_and_rejects_any_drift(self):
        for name in (op.PRIOR_JOURNAL, op.WINDOWS_JOURNAL, op.INVENTORY_JOURNAL):
            with self.subTest(journal=name):
                previous = self.driver()
                op.configure(previous, original, self.runtime, self.root, "d" * 40)
                captured = previous.capture_private(original, self.runtime, self.operation)
                self.assertEqual(len(captured), 4)
                path = self.root / name
                before = path.read_bytes()
                path.write_bytes(before + b" ")
                with (
                    patch.object(original, "validate_secrets"),
                    patch.object(original, "assert_retained"),
                    self.assertRaisesRegex(RuntimeError, "deployment journal changed"),
                ):
                    previous.retained(
                        original,
                        self.runtime,
                        self.operation,
                        {"private_files": captured, "retained_ids": {}},
                    )
                path.write_bytes(before)
        self.runtime.docker.assert_not_called()

    def test_new_journal_rejects_different_target_base_host_and_unknown_phase(self):
        driver = self.driver()
        op.configure(driver, original, self.runtime, self.root, self.software_record["target"])
        record = self.record(
            op.JOURNAL,
            op.BACKUP_PREFIX,
            "e" * 40,
            self.software_record["target"],
            driver.capture_private(original, self.runtime, self.operation),
        )
        marker = self.root / op.JOURNAL
        driver.validate_record(record, marker, "e" * 40, "fixture", "d" * 40)
        for change in (
            {"target": "f" * 40},
            {"base": "a" * 40},
            {"host": "other"},
            {"version": "next"},
            {"phase": "unknown"},
        ):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                driver.validate_record({**record, **change}, marker, "e" * 40, "fixture", "d" * 40)
        self.runtime.docker.assert_not_called()

    def test_old_inventory_or_windows_bytes_drift_is_not_bypassed(self):
        for name in (op.INVENTORY_JOURNAL, op.WINDOWS_JOURNAL):
            path = self.root / name
            before = path.read_bytes()
            record = json.loads(before)
            record["unexpected-edit"] = "retained even when parameters are unchanged"
            self.write(name, record)
            with (
                self.subTest(journal=name),
                self.assertRaisesRegex(RuntimeError, "journal changed"),
            ):
                self.validate()
            path.write_bytes(before)

    def test_prior_software_requires_verified_matching_parameters_and_private_files(self):
        for change in (
            {"phase": "services"},
            {"version": "next"},
            {"host": "other"},
            {"target": "not-a-sha"},
            {"base": "e" * 40},
            {"private_files": {"ingress": "edited"}},
        ):
            self.write(op.PRIOR_JOURNAL, {**self.software_record, **change})
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.validate()
            self.write(op.PRIOR_JOURNAL, self.software_record)
        self.runtime.docker.assert_not_called()

    def test_each_retained_artifact_tree_rejects_drift(self):
        for record in self.records:
            for name in ("backend", "frontend/dist"):
                path = Path(record["backup"]) / "release" / name / "fixture"
                before = path.read_bytes()
                path.write_bytes(b"changed retained source")
                with (
                    self.subTest(target=record["target"], name=name),
                    self.assertRaisesRegex(RuntimeError, "artifacts changed"),
                ):
                    self.validate()
                path.write_bytes(before)


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
        self.write("frontend/src/App.tsx", "// reviewed platform routing\n")
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
