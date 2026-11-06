"""Inventory updater boundaries; synthetic Git history and private fixtures only."""

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


op = load("host_inventory_update", "update-host-inventory.py")
original = load("host_inventory_previous", "deploy-authenticated-inventory.py")


class GitBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.git("init", "-b", op.BRANCH)
        self.git("config", "user.name", "Inventory fixture")
        self.git("config", "user.email", "fixture@example.test")
        self.write("backend/app/services/host_audit_transport.py", "# retained\n")
        self.write("docker-compose.yml", "retained runtime\n")
        self.write("frontend/default.conf", "retained ingress\n")
        self.git("add", ".")
        self.git("commit", "-m", "retained fixture")
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

    def feature(self, extra=None):
        self.write("backend/app/services/host_audit_transport.py", "# reviewed mode\n")
        if extra:
            self.write(extra, "# reviewed fixture\n")
        self.git("add", ".")
        self.git("commit", "-m", "reviewed fixture")
        target = self.git("rev-parse", "HEAD")
        self.git("reset", "--hard", self.base)
        self.git("update-ref", "refs/remotes/origin/" + op.BRANCH, target)
        return target

    def test_preserves_private_runtime_and_non_source_backups(self):
        target = self.feature()
        self.write("docker-compose.yml", "private runtime override\n")
        self.write("frontend/default.conf", "private ingress\n")
        self.write("backend/app/plugins/old.py.bak-final", "retained operator backup\n")
        self.write("frontend/Host:", "retained diagnostic artifact\n")
        self.assertEqual(
            op.source_plan(self.root, target, self.base),
            ["backend/app/services/host_audit_transport.py"],
        )
        self.assertEqual(
            (self.root / "docker-compose.yml").read_text(), "private runtime override\n"
        )

    def test_refuses_dependency_or_ingress_changes_in_target(self):
        for name in (
            "backend/requirements.txt",
            "frontend/package-lock.json",
            "docker-compose.yml",
        ):
            with self.subTest(name=name):
                target = self.feature(extra=name)
                with self.assertRaisesRegex(RuntimeError, "unrelated"):
                    op.source_plan(self.root, target, self.base)

    def test_refuses_a_new_application_module_and_target_collision(self):
        target = self.feature(extra="backend/alembic/versions/b7e2c9d1a630_add_winrm_transport.py")
        self.write("backend/app/extra.py", "# retained source\n")
        with self.assertRaisesRegex(RuntimeError, "Additional application source"):
            op.source_plan(self.root, target, self.base)
        (self.root / "backend/app/extra.py").unlink()
        self.write(
            "backend/alembic/versions/b7e2c9d1a630_add_winrm_transport.py", "# local collision\n"
        )
        with self.assertRaisesRegex(RuntimeError, "collision"):
            op.source_plan(self.root, target, self.base)

    def test_installed_target_requires_a_retained_journal(self):
        target = self.feature()
        self.git("merge", "--ff-only", target)
        with self.assertRaisesRegex(RuntimeError, "retained update journal"):
            op.source_plan(self.root, target, self.base)
        op.source_plan(self.root, target, self.base, resume=True)

    def test_refuses_review_target_mismatch_and_symlinked_publication(self):
        target = self.feature()
        self.git("update-ref", "refs/remotes/origin/" + op.BRANCH, self.base)
        with self.assertRaisesRegex(RuntimeError, "Reviewed target"):
            op.source_plan(self.root, target, self.base)
        self.git("update-ref", "refs/remotes/origin/" + op.BRANCH, target)
        (self.root / "frontend/dist").symlink_to(self.root / "unrelated")
        with self.assertRaisesRegex(RuntimeError, "Symlink"):
            op.source_plan(self.root, target, self.base)


class EvidenceAndRecovery(unittest.TestCase):
    def state(self):
        return {
            "identity": {"database": "fixture"},
            "revision": op.OLD_REVISION,
            "active": [],
            "transactions": 0,
            "tables": {
                "jobs": {"count": 2, "sha256": "old-jobs"},
                "audit_credentials": {"count": 1, "sha256": "encrypted-credential"},
                "host_audits": {"count": 1, "sha256": "old-evidence-and-scope"},
            },
        }

    def test_every_old_row_and_identity_are_preserved_not_just_counts(self):
        before = self.state()
        after = json.loads(json.dumps(before))
        after["revision"] = op.REVISION
        op.preserve_rows(before, after)
        for name in ("jobs", "audit_credentials", "host_audits"):
            broken = json.loads(json.dumps(after))
            broken["tables"][name]["sha256"] = "changed-with-identical-count"
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "rows changed"):
                op.preserve_rows(before, broken)
        after["identity"]["database"] = "different-database"
        with self.assertRaises(RuntimeError):
            op.preserve_rows(before, after)

    def test_quiesce_queue_race_never_migrates_or_backs_up(self):
        runtime = Mock()
        runtime.inspect.side_effect = [
            {"Id": "worker", "State": {"Running": True, "Paused": False}},
            {"Id": "backend", "State": {"Running": True}},
        ]
        state = {**self.state(), "active": [{"id": 1}]}
        record = {"application_ids": {"backend": "backend", "worker": "worker"}}
        with (
            patch.object(op, "read_state", return_value=state),
            patch.object(original, "backup_database") as backup,
            patch.object(original, "close_application") as close,
        ):
            with self.assertRaisesRegex(RuntimeError, "Active jobs"):
                op.quiesce(original, runtime, {}, record, Path("unused"))
            close.assert_not_called()
            backup.assert_not_called()
        runtime.helper.assert_not_called()

    def test_post_migration_intent_failure_closes_writers_without_rollback(self):
        runtime = Mock()
        for phase in ("migrating", "migrated", "source", "published", "services"):
            with (
                self.subTest(phase=phase),
                patch.object(original, "close_application") as close,
                patch.object(op, "restore_before_migration") as restore,
            ):
                op.recover(original, runtime, {"phase": phase}, Path("unused"))
                close.assert_called_once_with(runtime)
                restore.assert_not_called()
        runtime.helper.assert_not_called()

    def test_backup_failure_resumes_only_exact_original_containers(self):
        runtime = Mock()
        runtime.inspect.return_value = {
            "Id": "unexpected",
            "State": {"Running": False, "Paused": False},
        }
        record = {"application_ids": {"backend": "retained", "worker": "worker"}}
        with self.assertRaisesRegex(RuntimeError, "changed"):
            op.restore_before_migration(original, runtime, record)
        runtime.docker.assert_not_called()

    def test_verified_repeat_failure_never_stops_existing_work(self):
        runtime = Mock()
        with (
            patch.object(original, "close_application") as close,
            patch.object(op, "restore_before_migration") as restore,
        ):
            op.recover(original, runtime, {"phase": "verified"}, Path("unused"))
            close.assert_not_called()
            restore.assert_not_called()
        runtime.helper.assert_not_called()

    def test_read_only_preflight_has_no_backup_publication_or_authentication(self):
        runtime = Mock()
        runtime.legacy = Mock()
        runtime.inspect.return_value = {"Id": "fixture"}
        runtime.docker.return_value = "ccvm-worker"
        operation = {"host": "fixture", "private": "/private", "target": "a" * 40}
        with (
            patch.object(original, "verify_runtime"),
            patch.object(original, "worker_identity"),
            patch.object(original, "database_identity"),
            patch.object(op, "read_state", return_value=self.state()),
            patch.object(op, "capture_private", return_value={}),
            patch.object(original, "write_json") as write,
            patch.object(original, "database_environment") as env,
        ):
            record = op.prepare(original, runtime, operation, "b" * 40, None)
        self.assertEqual(record["phase"], "prepared")
        self.assertNotIn("backup", record)
        write.assert_not_called()
        env.assert_not_called()
        runtime.helper.assert_not_called()
        self.assertEqual(runtime.docker.call_count, 1)


class PrivateArtifacts(unittest.TestCase):
    def test_artifact_change_or_extra_module_invalidates_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = root / "release/backend"
            frontend = root / "release/frontend/dist"
            backend.mkdir(parents=True)
            frontend.mkdir(parents=True)
            (backend / "module.py").write_text("reviewed source\n")
            (frontend / "index.html").write_text("reviewed UI\n")
            record = {
                "backup": directory,
                "artifacts": {
                    "backend": op.directory_hashes(backend),
                    "frontend/dist": op.directory_hashes(frontend),
                },
            }
            op.validate_artifacts(record)
            (backend / "extra.py").write_text("unreviewed import\n")
            with self.assertRaisesRegex(RuntimeError, "artifacts changed"):
                op.validate_artifacts(record)
            (backend / "extra.py").unlink()
            (frontend / "index.html").write_text("unreviewed UI\n")
            with self.assertRaisesRegex(RuntimeError, "artifacts changed"):
                op.validate_artifacts(record)

    def test_journal_rejects_symlink_permissions_wrong_target_and_unknown_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "ccvm-host-inventory-before-fixture"
            backup.mkdir(mode=0o700)
            marker = root / "journal.json"
            marker.write_text("{}")
            marker.chmod(0o600)
            record = {
                "version": op.VERSION,
                "target": "b" * 40,
                "base": "a" * 40,
                "host": "fixture",
                "backup": str(backup),
                "phase": "prepared",
            }
            op.validate_record(record, marker, "b" * 40, "fixture", "a" * 40)
            for key, value in (("target", "c" * 40), ("host", "other"), ("phase", "unknown")):
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    op.validate_record(
                        {**record, key: value}, marker, "b" * 40, "fixture", "a" * 40
                    )
            marker.chmod(0o644)
            with self.assertRaises(RuntimeError):
                op.validate_record(record, marker, "b" * 40, "fixture", "a" * 40)
            marker.chmod(0o600)
            link = root / "link.json"
            link.symlink_to(marker)
            with self.assertRaises(RuntimeError):
                op.validate_record(record, link, "b" * 40, "fixture", "a" * 40)


if __name__ == "__main__":
    unittest.main()
