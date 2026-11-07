"""Verified update chaining, additive migration and retained ingress boundaries."""

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


op = load("software_updater", "update-software-assessment.py")
original = load("patch_original_deployment", "deploy-authenticated-inventory.py")


def helper():
    return load("patch_previous_update", "update-host-inventory.py")


def snapshot(revision=op.OLD_REVISION):
    return {
        "revision": revision,
        "identity": {"database": "synthetic-ci-database"},
        "active": [],
        "transactions": 0,
        "tables": {
            "jobs": {"count": 2, "sha256": "retained-completed-jobs"},
            "audit_credentials": {"count": 1, "sha256": "retained-ciphertext"},
            "host_audits": {"count": 1, "sha256": "retained-http-transport-and-evidence"},
            "windows_patch_catalogs": {"count": 2, "sha256": "retained-os-catalogs"},
            "host_assessments": {"count": 2, "sha256": "retained-os-assessments"},
        },
    }


def migrated():
    result = snapshot(op.REVISION)
    result["tables"].update({name: {"count": 0, "sha256": "empty"} for name in op.NEW_TABLES})
    return result


class DatabaseBoundaries(unittest.TestCase):
    def test_append_only_empty_tables_keeps_all_old_fingerprints(self):
        before, after = snapshot(), migrated()
        op.preserve_rows(before, before)
        op.preserve_rows(before, after)
        self.assertEqual(
            before["tables"]["host_audits"]["sha256"], "retained-http-transport-and-evidence"
        )
        for table in before["tables"]:
            changed = copy.deepcopy(after)
            changed["tables"][table]["sha256"] += "-changed"
            with self.subTest(table=table), self.assertRaisesRegex(RuntimeError, "rows changed"):
                op.preserve_rows(before, changed)

    def test_refuses_unexpected_tables_missing_table_data_and_identity_changes(self):
        for mutation in ("missing", "unexpected", "nonempty", "old-dropped", "identity"):
            after = migrated()
            if mutation == "missing":
                del after["tables"]["software_assessments"]
            if mutation == "unexpected":
                after["tables"]["other"] = {"count": 0}
            if mutation == "nonempty":
                after["tables"]["software_advisory_catalogs"]["count"] = 1
            if mutation == "old-dropped":
                del after["tables"]["jobs"]
            if mutation == "identity":
                after["identity"]["database"] = "other"
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                op.preserve_rows(snapshot(), after)

    def test_new_snapshot_does_not_omit_existing_transport_column(self):
        previous = helper()
        with tempfile.TemporaryDirectory() as directory:
            op.configure(previous, original, Mock(), Path(directory), "b" * 40)
        self.assertEqual(previous.state_code(original), original.STATE_CODE)
        self.assertNotIn("key=='winrm_transport'", previous.state_code(original))
        previous.assert_migrated(original, Mock(), {}, {"before": snapshot()}, migrated())

    def test_original_transport_backfill_remains_required(self):
        previous = helper()
        runtime = Mock()
        runtime.helper.return_value = "wrong-backfill"
        with self.assertRaisesRegex(RuntimeError, "HTTPS transport"):
            previous.assert_migrated(original, runtime, {}, {}, {})
        self.assertIn("winrm_transport", runtime.helper.call_args.args[1])
        runtime.helper.return_value = "retained-https"
        previous.assert_migrated(original, runtime, {}, {}, {})

    def test_fresh_deployment_accepts_exact_old_or_new_schema_additions(self):
        before = {"identity": {}, "tables": {"jobs": {"count": 1, "sha256": "retained"}}}
        for revision in ("a4c1d8e7f209", "b7e2c9d1a630", op.OLD_REVISION, op.REVISION):
            after = copy.deepcopy(before)
            after["revision"] = revision
            names = {"audit_credentials", "host_audits"}
            if revision in {op.OLD_REVISION, op.REVISION}:
                names |= {"windows_patch_catalogs", "host_assessments"}
            if revision == op.REVISION:
                names |= op.NEW_TABLES
            after["tables"].update({name: {"count": 0} for name in names})
            original.assert_preserved(before, after)
            after["tables"]["unrelated"] = {"count": 0}
            with self.assertRaises(RuntimeError):
                original.assert_preserved(before, after)


class JournalAndRuntimeBoundaries(unittest.TestCase):
    def test_previous_verified_journal_supplies_application_base_not_ingress_release(self):
        previous = helper()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / op.PRIOR_JOURNAL
            record = {
                "phase": "verified",
                "version": "1.0.0",
                "host": "fixture",
                "target": "b" * 40,
            }
            marker.write_text(json.dumps(record))
            marker.chmod(0o600)
            with (
                patch.object(op, "load_helper") as load_prior,
                patch.object(previous, "validate_record") as checked,
                patch.object(previous, "retained") as retained,
                patch.object(previous, "validate_artifacts") as artifacts,
            ):
                load_prior.return_value.previous_update.return_value = "a" * 40
                actual = op.previous_update(
                    previous, original, Mock(), {"target": "a" * 40}, root, "fixture"
                )
            self.assertEqual(actual, "b" * 40)
            self.assertEqual(checked.call_args.args[-1], "a" * 40)
            retained.assert_called_once()
            artifacts.assert_called_once_with(record)
            for mutation in ({"phase": "services"}, {"host": "other"}, {"version": "next"}):
                marker.write_text(json.dumps({**record, **mutation}))
                with self.assertRaisesRegex(RuntimeError, "verified previous"):
                    op.previous_update(previous, original, Mock(), {}, root, "fixture")

    def test_drift_in_either_prior_journal_invalidates_resume(self):
        for journal in (op.PRIOR_JOURNAL, op.INVENTORY_JOURNAL):
            with self.subTest(journal=journal), tempfile.TemporaryDirectory() as directory:
                previous = helper()
                runtime = Mock()
                root = Path(directory)
                prior = root / op.PRIOR_JOURNAL
                prior.write_bytes(b"retained prior journal")
                inventory = root / op.INVENTORY_JOURNAL
                inventory.write_bytes(b"retained inventory journal")
                previous.capture_private = Mock(side_effect=lambda *_args: {"ingress": "retained"})
                op.configure(previous, original, runtime, root, "b" * 40)
                captured = previous.capture_private(original, runtime, {})
                self.assertEqual(
                    captured["prior-windows-patch-journal"],
                    base64.b64encode(prior.read_bytes()).decode(),
                )
                self.assertEqual(
                    captured["prior-inventory-update-journal"],
                    base64.b64encode(inventory.read_bytes()).decode(),
                )
                (root / journal).write_bytes(b"edited prior journal")
                with (
                    patch.object(original, "validate_secrets"),
                    patch.object(original, "assert_retained"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "deployment journal changed"):
                        previous.retained(
                            original,
                            runtime,
                            {"private": str(root)},
                            {"private_files": captured, "retained_ids": {}},
                        )
                runtime.docker.assert_not_called()

    def test_preflight_has_no_backup_write_migration_catalog_sync_or_host_authentication(self):
        previous = helper()
        runtime = Mock()
        previous.prepare = Mock(return_value={"base": "a" * 40, "phase": "prepared"})
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

    def test_api_verification_reads_contract_without_running_an_assessment(self):
        runtime = Mock()
        runtime.docker.return_value = json.dumps(
            {
                "paths": [
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
        previous_verify = Mock()
        op.verify_assessment_api(runtime, previous_verify)
        previous_verify.assert_called_once_with(runtime)
        self.assertIn("app.openapi()", runtime.docker.call_args.args[-1])
        runtime.helper.assert_not_called()
        runtime.docker.return_value = '{"paths":[],"schemas":[]}'
        with self.assertRaisesRegex(RuntimeError, "assessment workflow"):
            op.verify_assessment_api(runtime, previous_verify)


class RealPriorPublicationChain(unittest.TestCase):
    """Exercise the real nested wrappers with immutable synthetic release trees."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous_patch = load(
            "software_real_prior_patch", "update-windows-patch-assessment.py"
        )
        self.operation = {"target": "c" * 40, "private": str(self.root)}
        self.runtime = Mock(root=self.root, reviewed_target="f" * 40)
        self.inventory_marker = self.root / op.INVENTORY_JOURNAL
        self.patch_marker = self.root / op.PRIOR_JOURNAL
        self.inventory_record = self.record(
            "ccvm-host-inventory-before-", "a" * 40, "c" * 40, {"ingress": "retained"}
        )
        self.write_journal(self.inventory_marker, self.inventory_record)
        self.patch_record = self.record(
            "ccvm-windows-patch-before-",
            "b" * 40,
            "a" * 40,
            {
                "ingress": "retained",
                "prior-inventory-update-journal": base64.b64encode(
                    self.inventory_marker.read_bytes()
                ).decode(),
            },
        )
        self.write_journal(self.patch_marker, self.patch_record)

    def tearDown(self):
        self.temporary.cleanup()

    def record(self, prefix, target, base, files):
        backup = self.root / (prefix + "fixture")
        for name in ("backend", "frontend/dist"):
            directory = backup / "release" / name
            directory.mkdir(parents=True, mode=0o700)
            (directory / "retained-fixture").write_text("reviewed synthetic release")
        backup.chmod(0o700)
        return {
            "version": "1.0.0",
            "phase": "verified",
            "host": "fixture",
            "target": target,
            "base": base,
            "backup": str(backup),
            "private_files": files,
            "retained_ids": {},
            "artifacts": {
                name: helper().directory_hashes(backup / "release" / name)
                for name in ("backend", "frontend/dist")
            },
        }

    def write_journal(self, marker, record):
        marker.write_text(json.dumps(record))
        marker.chmod(0o600)

    def validate(self):
        # Keep all journal, wrapper configuration, private-file comparison and
        # artifact validation real. Only Docker/secret-bearing runtime probes
        # are replaced; the fixture never contains actual credentials.
        previous = helper()
        previous.capture_private = Mock(side_effect=lambda *_args: {"ingress": "retained"})
        with (
            patch.object(op, "load_helper", return_value=self.previous_patch) as loaded,
            patch.object(original, "validate_secrets") as secrets,
            patch.object(original, "assert_retained") as retained,
        ):
            target = op.previous_update(
                previous, original, self.runtime, self.operation, self.root, "fixture"
            )
        return target, previous, loaded, secrets, retained

    def test_real_nested_journal_validation_returns_latest_application_target(self):
        target, previous, loaded, secrets, retained = self.validate()
        self.assertEqual(target, self.patch_record["target"])
        self.assertNotEqual(target, self.inventory_record["target"])
        self.assertNotEqual(target, self.operation["target"])
        loaded.assert_called_once_with(
            self.root,
            "f" * 40,
            "scripts/update-windows-patch-assessment.py",
            "software_prior_patch",
        )
        self.assertEqual(secrets.call_count, 2)
        self.assertEqual(retained.call_count, 2)
        self.assertEqual(previous.OLD_REVISION, "b7e2c9d1a630")
        self.assertEqual(previous.REVISION, op.OLD_REVISION)
        self.runtime.docker.assert_not_called()

        # Main deliberately starts from a fresh driver after prior validation;
        # the new capture must bind both journals exactly once.
        fresh = helper()
        fresh.capture_private = Mock(side_effect=lambda *_args: {"ingress": "retained"})
        op.configure(fresh, original, self.runtime, self.root, target)
        captured = fresh.capture_private(original, self.runtime, self.operation)
        self.assertEqual(fresh.OLD_REVISION, op.OLD_REVISION)
        self.assertEqual(fresh.REVISION, op.REVISION)
        self.assertEqual(
            set(captured),
            {"ingress", "prior-inventory-update-journal", "prior-windows-patch-journal"},
        )

    def test_inventory_journal_drift_is_detected_by_real_patch_private_capture(self):
        changed = copy.deepcopy(self.inventory_record)
        changed["unexpected-edit"] = "even unrelated journal bytes are retained"
        self.write_journal(self.inventory_marker, changed)
        with self.assertRaisesRegex(RuntimeError, "deployment journal changed"):
            self.validate()
        self.runtime.docker.assert_not_called()

    def test_patch_journal_parameters_and_private_capture_are_validated(self):
        for change in (
            {"phase": "services"},
            {"host": "other"},
            {"base": "d" * 40},
            {"private_files": {"ingress": "edited"}},
        ):
            with self.subTest(change=change):
                self.write_journal(self.patch_marker, {**self.patch_record, **change})
                with self.assertRaises(RuntimeError):
                    self.validate()
                self.write_journal(self.patch_marker, self.patch_record)
        self.runtime.docker.assert_not_called()

    def test_artifact_drift_is_rejected_for_each_prior_release(self):
        for record in (self.inventory_record, self.patch_record):
            for name in ("backend", "frontend/dist"):
                with self.subTest(release=record["target"], artifact=name):
                    artifact = Path(record["backup"]) / "release" / name / "retained-fixture"
                    original_bytes = artifact.read_bytes()
                    artifact.write_bytes(b"modified retained artifact")
                    with self.assertRaisesRegex(RuntimeError, "artifacts changed"):
                        self.validate()
                    artifact.write_bytes(original_bytes)
        self.runtime.docker.assert_not_called()


class SourceBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous = helper()
        op.configure(self.previous, original, Mock(), self.root, "b" * 40)
        self.git("init", "-b", self.previous.BRANCH)
        self.git("config", "user.name", "Patch fixture")
        self.git("config", "user.email", "fixture@example.test")
        self.write("backend/app/services/host_inventory.py", "# old ingress release\n")
        self.git("add", ".")
        self.git("commit", "-m", "ingress")
        self.ingress = self.git("rev-parse", "HEAD")
        self.write("backend/app/retained_inventory_module.py", "# earlier approved inventory\n")
        self.git("add", ".")
        self.git("commit", "-m", "inventory update")
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
        self.write("backend/app/services/software_assessment.py", "# reviewed assessment\n")
        if extra:
            self.write(extra, "unrelated change\n")
        self.git("add", ".")
        self.git("commit", "-m", "assessment")
        result = self.git("rev-parse", "HEAD")
        self.git("reset", "--hard", self.base)
        self.git("update-ref", "refs/remotes/origin/" + self.previous.BRANCH, result)
        return result

    def test_scope_is_based_on_previous_application_update(self):
        target = self.target()
        self.previous.source_plan(self.root, target, self.base)
        with self.assertRaisesRegex(RuntimeError, "retained update journal"):
            self.previous.source_plan(self.root, target, self.ingress)

    def test_dependency_ingress_or_legacy_public_finding_changes_are_refused(self):
        for filename in (
            "backend/requirements.txt",
            "docker-compose.yml",
            "backend/app/api/v1/findings.py",
        ):
            with self.subTest(filename=filename):
                target = self.target(filename)
                with self.assertRaisesRegex(RuntimeError, "unrelated source"):
                    self.previous.source_plan(self.root, target, self.base)


if __name__ == "__main__":
    unittest.main()
