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


op = load("windows_patch_updater", "update-windows-patch-assessment.py")
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
                del after["tables"]["host_assessments"]
            if mutation == "unexpected":
                after["tables"]["other"] = {"count": 0}
            if mutation == "nonempty":
                after["tables"]["windows_patch_catalogs"]["count"] = 1
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
        for revision in ("a4c1d8e7f209", "b7e2c9d1a630", op.REVISION):
            after = copy.deepcopy(before)
            after["revision"] = revision
            names = {"audit_credentials", "host_audits"}
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
                patch.object(previous, "validate_record") as checked,
                patch.object(previous, "retained") as retained,
                patch.object(previous, "validate_artifacts") as artifacts,
            ):
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

    def test_prior_journal_drift_invalidates_resume(self):
        previous = helper()
        runtime = Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = root / op.PRIOR_JOURNAL
            prior.write_bytes(b"retained prior journal")
            previous.capture_private = Mock(side_effect=lambda *_args: {"ingress": "retained"})
            op.configure(previous, original, runtime, root, "b" * 40)
            captured = previous.capture_private(original, runtime, {})
            self.assertEqual(
                captured["prior-inventory-update-journal"],
                base64.b64encode(prior.read_bytes()).decode(),
            )
            prior.write_bytes(b"edited prior journal")
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
                    "/api/v1/host-audits/patch-catalog",
                    "/api/v1/host-audits/{audit_id}/assess",
                    "/api/v1/host-audits/{audit_id}/assessments",
                ],
                "schemas": ["HostAssessmentOut", "PatchCatalogOut", "AssessmentCreate"],
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
        self.write("backend/app/services/windows_patch_assessment.py", "# reviewed assessment\n")
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
