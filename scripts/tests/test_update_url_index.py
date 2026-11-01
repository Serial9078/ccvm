"""Exercise maintenance ordering and rollback using disposable Git and fake Docker."""

import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "update_url_index", Path(__file__).resolve().parents[1] / "update-url-index.py"
)
operator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(operator)


def state(revision):
    name = "uq_urls_domain_url_sha256" if revision == operator.REVISION else "uq_urls_domain_url"
    return {
        "revision": revision,
        "active": [],
        "indexes": [
            {
                "name": name,
                "unique": True,
                "valid": True,
                "definition": "CREATE UNIQUE INDEX ... sha256(...)",
            }
        ],
        "tables": {"urls": {"count": 2, "sha256": "retained"}},
    }


class FakeRuntime:
    def __init__(self):
        self.snapshot = state(operator.OLD_REVISION)
        self.actions = []
        self.fail = None
        self.new_queue = False
        self.changed_rows = False
        self.unknown_revision = False

    def preflight(self, root):
        operator.validate_state(self.snapshot)
        return copy.deepcopy(self.snapshot)

    def docker(self, *args):
        self.actions.append(args)
        if args[0] == "stop" and args[-1] == "ccvm-backend" and self.new_queue:
            self.snapshot["active"] = [{"id": 200, "plugin": "katana", "status": "queued"}]

    def state(self):
        return copy.deepcopy(self.snapshot)

    def freeze(self):
        self.actions.append(("freeze",))
        if self.fail == "freeze":
            raise RuntimeError("freeze response lost")

    def resume(self):
        self.actions.append(("resume",))

    def database_backup(self, destination):
        self.actions.append(("database_backup",))
        if self.fail == "backup":
            raise RuntimeError("backup failed")
        destination.write_bytes(b"FAKE verified custom-format dump")

    def migrate(self):
        self.actions.append(("migrate",))
        if self.fail == "migration":
            raise RuntimeError("migration rolled back")
        self.snapshot = state("unknown" if self.unknown_revision else operator.REVISION)
        if self.changed_rows:
            self.snapshot["tables"]["urls"]["count"] += 1

    def verify(self):
        self.actions.append(("verify",))


class UpdateUrlIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ccvm-url-index-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run_git("init", "-b", operator.BRANCH)
        self.run_git("config", "user.name", "Test")
        self.run_git("config", "user.email", "test@example.invalid")
        for name, content in {
            "backend/app/url.py": "original source\n",
            "docker-compose.yml": "original compose\n",
            "frontend/default.conf": "original nginx\n",
        }.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.run_git("add", ".")
        self.run_git("commit", "-m", "base")
        self.base = self.run_git("rev-parse", "HEAD")
        (self.root / "backend/app/url.py").write_text("reviewed URL correction\n")
        (self.root / "backend/app/digest.py").write_text("reviewed helper\n")
        self.run_git("add", ".")
        self.run_git("commit", "-m", "reviewed target")
        self.target = self.run_git("rev-parse", "HEAD")
        self.run_git("update-ref", f"refs/remotes/origin/{operator.BRANCH}", self.target)
        self.run_git("restore", "--source", self.base, "--staged", "--worktree", "--", ".")
        self.run_git("update-ref", "HEAD", self.base, self.target)
        (self.root / "docker-compose.yml").write_text("private compose retained\n")
        (self.root / "frontend/default.conf").write_text("private nginx retained\n")
        self.original_base = operator.BASE
        operator.BASE = self.base
        self.addCleanup(setattr, operator, "BASE", self.original_base)
        self.runtime = FakeRuntime()

    def run_git(self, *args):
        return (
            subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.DEVNULL)
            .decode()
            .strip()
        )

    def apply(self):
        plan = operator.source_plan(self.root, self.target)
        with contextlib.redirect_stdout(io.StringIO()):
            operator.apply(self.root, self.target, self.runtime, plan)

    def assert_configs(self):
        self.assertEqual(
            (self.root / "docker-compose.yml").read_text(), "private compose retained\n"
        )
        self.assertEqual(
            (self.root / "frontend/default.conf").read_text(), "private nginx retained\n"
        )

    def test_apply_orders_backup_before_schema_change_and_resumes_services(self):
        self.apply()
        self.assertEqual(self.run_git("rev-parse", "HEAD"), self.target)
        self.assert_configs()
        actions = self.runtime.actions
        self.assertLess(actions.index(("freeze",)), actions.index(("database_backup",)))
        self.assertLess(actions.index(("database_backup",)), actions.index(("migrate",)))
        self.assertLess(actions.index(("migrate",)), actions.index(("resume",)))
        self.assertEqual(actions[-1], ("verify",))
        backup = next((self.root / ".git").glob("ccvm-url-index-before-*"))
        self.assertTrue((backup / "database.dump").exists())
        before, after = (
            json.loads((backup / name).read_text()) for name in ("before.json", "after.json")
        )
        self.assertEqual(before["tables"], after["tables"])

    def test_active_jobs_stop_before_backup_or_services(self):
        self.runtime.snapshot["active"] = [{"id": 109, "status": "running"}]
        with self.assertRaisesRegex(RuntimeError, "Active jobs preserved"):
            self.apply()
        self.assertFalse(self.runtime.actions)
        self.assertEqual(self.run_git("rev-parse", "HEAD"), self.base)

    def test_queue_race_after_api_stop_preserves_the_job(self):
        self.runtime.new_queue = True
        with self.assertRaisesRegex(RuntimeError, "Active jobs preserved"):
            self.apply()
        self.assertEqual(self.run_git("rev-parse", "HEAD"), self.base)
        self.assertNotIn(("freeze",), self.runtime.actions)
        self.assertEqual(self.runtime.actions[-1], ("start", "ccvm-backend"))
        self.assertEqual(self.runtime.snapshot["active"][0]["id"], 200)

    def test_failed_freeze_response_still_resumes_worker(self):
        self.runtime.fail = "freeze"
        with self.assertRaisesRegex(RuntimeError, "freeze response lost"):
            self.apply()
        self.assertIn(("resume",), self.runtime.actions)
        self.assertEqual(self.run_git("rev-parse", "HEAD"), self.base)

    def test_backup_failure_preserves_source_and_restarts_services(self):
        self.runtime.fail = "backup"
        with self.assertRaisesRegex(RuntimeError, "backup failed"):
            self.apply()
        self.assertNotIn(("migrate",), self.runtime.actions)
        self.assertIn(("resume",), self.runtime.actions)
        self.assertEqual(self.run_git("rev-parse", "HEAD"), self.base)
        self.assert_configs()

    def test_failed_migration_rolls_code_back_without_downgrading_database(self):
        self.runtime.fail = "migration"
        with self.assertRaisesRegex(RuntimeError, "migration rolled back"):
            self.apply()
        self.assertEqual(self.run_git("rev-parse", "HEAD"), self.base)
        self.assertEqual((self.root / "backend/app/url.py").read_text(), "original source\n")
        self.assertFalse((self.root / "backend/app/digest.py").exists())
        self.assertIn(("resume",), self.runtime.actions)
        self.assert_configs()

    def test_post_migration_error_keeps_matching_new_code_and_schema(self):
        self.runtime.changed_rows = True
        with self.assertRaisesRegex(RuntimeError, "fingerprints changed"):
            self.apply()
        self.assertEqual(self.run_git("rev-parse", "HEAD"), self.target)
        self.assertEqual(self.runtime.snapshot["revision"], operator.REVISION)
        self.assertIn(("resume",), self.runtime.actions)
        self.assert_configs()

    def test_unknown_schema_keeps_services_stopped(self):
        self.runtime.unknown_revision = True
        with self.assertRaisesRegex(RuntimeError, "Unexpected database revision"):
            self.apply()
        self.assertNotIn(("resume",), self.runtime.actions)
        self.assertNotIn(("start", "ccvm-backend"), self.runtime.actions)
        self.assertEqual(self.runtime.actions[-1], ("stop", "--time", "5", "ccvm-worker"))

    def test_repeat_apply_verifies_without_repeating_migration_or_backup(self):
        self.apply()
        self.runtime.actions.clear()
        self.apply()
        self.assertEqual(self.runtime.actions, [("verify",)])
        self.assertEqual(len(list((self.root / ".git").glob("ccvm-url-index-before-*"))), 1)

    def test_staged_changes_are_rejected(self):
        (self.root / "docker-compose.yml").write_text("staged config\n")
        self.run_git("add", "docker-compose.yml")
        with self.assertRaises(RuntimeError):
            operator.source_plan(self.root, self.target)

    def test_application_edits_are_preserved_and_rejected(self):
        (self.root / "backend/app/url.py").write_text("unreviewed edit\n")
        with self.assertRaisesRegex(RuntimeError, "Additional tracked edits"):
            operator.source_plan(self.root, self.target)
        self.assertEqual((self.root / "backend/app/url.py").read_text(), "unreviewed edit\n")

    def test_untracked_target_collision_is_preserved(self):
        (self.root / "backend/app/digest.py").write_text("local untracked source\n")
        with self.assertRaisesRegex(RuntimeError, "Untracked target"):
            operator.source_plan(self.root, self.target)
        self.assertEqual(
            (self.root / "backend/app/digest.py").read_text(), "local untracked source\n"
        )

    def test_additional_untracked_source_is_rejected(self):
        (self.root / "backend/app/other.py").write_text("local feature\n")
        with self.assertRaisesRegex(RuntimeError, "Additional application source"):
            operator.source_plan(self.root, self.target)

    def test_remote_target_drift_is_rejected(self):
        self.run_git("update-ref", f"refs/remotes/origin/{operator.BRANCH}", self.base)
        with self.assertRaisesRegex(RuntimeError, "reviewed target"):
            operator.source_plan(self.root, self.target)

    def test_invalid_new_index_is_rejected(self):
        snapshot = state(operator.REVISION)
        for key in ("unique", "valid"):
            with self.subTest(key=key):
                broken = copy.deepcopy(snapshot)
                broken["indexes"][0][key] = False
                with self.assertRaisesRegex(RuntimeError, "identity index"):
                    operator.validate_state(broken)

    def test_source_cannot_be_marked_updated_before_schema_is_migrated(self):
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            operator.validate_state(state(operator.OLD_REVISION), expected=operator.REVISION)


if __name__ == "__main__":
    unittest.main()
