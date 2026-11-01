"""Disposable Git and fake-Docker checks for a narrowly selected pipeline retry."""

import ast
import contextlib
import copy
import importlib.util
import io
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


operator = load("header_findings_updater_test", "update-header-findings.py")
SELECTION = (8, "11111111-1111-4111-8111-111111111111")


def snapshot(revision=operator.OLD_REVISION):
    jobs = []
    for index, plugin in enumerate(operator.STAGES):
        jobs.append(
            {
                "id": index + 1,
                "uuid": SELECTION[1] if index == 7 else f"identity-{index}",
                "asset_id": None,
                "domain_id": 1,
                "pipeline_id": "test-pipeline",
                "parent_job_id": index or None,
                "plugin": plugin,
                "status": "finished" if index < 7 else "running" if index == 7 else "queued",
                "progress": 100 if index < 7 else 10 if index == 7 else 0,
                "message": "Correlating security headers for 119 HTML URLs" if index == 7 else "",
                "worker": "ccvm-worker-01" if index <= 7 else None,
            }
        )
    return {
        "jobs": jobs,
        "active": [dict(row) for row in jobs[7:]],
        "revision": revision,
        "matched_at_type": "text" if revision == operator.REVISION else "character varying",
        "indexes": [
            {
                "name": "uq_urls_domain_url_sha256",
                "unique": True,
                "valid": True,
                "definition": "CREATE UNIQUE INDEX ... sha256(...)",
            }
        ],
        "tables": {
            name: {"count": 10, "sha256": "retained"} for name in ("urls", "findings", "jobs")
        },
        "transactions": [],
    }


class FakeRuntime:
    def __init__(self, module):
        self.module = module
        self.snapshot = snapshot()
        self.actions = []
        self.fail = None
        self.paused = False
        self.started = 1
        self.verified = False

    def preflight(self, root):
        self.module.validate_state(self.snapshot)
        return copy.deepcopy(self.snapshot)

    def prepare_maintenance(self, backup):
        self.actions.append("prepare")
        if self.fail == "prepare":
            raise RuntimeError("helper failed")

    def docker(self, *args):
        self.actions.append(args)
        if args[0] == "inspect":
            return json.dumps({"Running": True, "StartedAt": str(self.started)})
        if args[0] == "restart":
            if self.fail == "restart":
                raise RuntimeError("restart denied")
            self.started += 1
        return ""

    def freeze(self):
        self.actions.append("pause")
        self.paused = True

    def resume(self):
        self.actions.append("resume")
        self.paused = False

    def state(self):
        return copy.deepcopy(self.snapshot)

    def database_backup(self, path):
        self.actions.append("backup")
        if self.fail == "backup":
            raise RuntimeError("backup failed")
        path.write_bytes(b"verified disposable dump")

    def migrate(self):
        assert self.paused and "backup" in self.actions
        self.actions.append("migrate")
        if self.fail == "migration":
            raise RuntimeError("migration rolled back")
        self.snapshot["revision"] = operator.REVISION
        self.snapshot["matched_at_type"] = "text"
        if self.fail == "fingerprint":
            self.snapshot["tables"]["findings"]["sha256"] = "changed"

    def maintenance_python(self, code):
        assert self.paused and self.started == 2
        assert self.snapshot["revision"] == operator.REVISION
        self.actions.append("requeue")
        if self.fail == "requeue":
            raise RuntimeError("requeue response lost")
        payload = json.loads(ast.literal_eval(code.splitlines()[0].split("=", 1)[1]))
        assert payload["job_id"] == SELECTION[0]
        assert payload["jobs"] == self.snapshot["jobs"]
        row = self.snapshot["jobs"][7]
        row.update(status="queued", progress=0, message=operator.RETRY_MESSAGE, worker=None)
        self.snapshot["tables"]["jobs"]["sha256"] = "selected job requeued"
        return json.dumps({"requeued": row["id"], "pipeline_id": row["pipeline_id"]})


class HeaderFindingsUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ccvm-header-retry-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.module = operator.configure_maintenance(
            load("url_maintenance_adapter_test", "update-url-index.py"), SELECTION
        )
        self.git("init", "-b", self.module.BRANCH)
        self.git("config", "user.name", "Disposable Test")
        self.git("config", "user.email", "test@example.invalid")
        for name, content in {
            "backend/app/finding.py": "original source\n",
            "docker-compose.yml": "versioned compose\n",
            "frontend/default.conf": "versioned nginx\n",
        }.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.git("add", ".")
        self.git("commit", "-m", "base")
        self.base = self.git("rev-parse", "HEAD")
        (self.root / "backend/app/finding.py").write_text("reviewed correction\n")
        self.git("add", ".")
        self.git("commit", "-m", "target")
        self.target = self.git("rev-parse", "HEAD")
        self.git("update-ref", f"refs/remotes/origin/{self.module.BRANCH}", self.target)
        self.git("restore", "--source", self.base, "--staged", "--worktree", "--", ".")
        self.git("update-ref", "HEAD", self.base, self.target)
        self.module.BASE = self.base
        self.compose = self.root / "docker-compose.yml"
        self.compose.write_text("private compose retained\n")
        self.runtime = FakeRuntime(self.module)
        self.original_verify = operator.verify
        operator.verify = lambda *args: setattr(self.runtime, "verified", True)
        self.addCleanup(setattr, operator, "verify", self.original_verify)

    def git(self, *args):
        return (
            subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.DEVNULL)
            .decode()
            .strip()
        )

    def apply(self):
        plan = self.module.source_plan(self.root, self.target)
        with contextlib.redirect_stdout(io.StringIO()):
            operator.apply(self.root, self.target, SELECTION, self.module, self.runtime, plan)

    def test_preserves_rows_and_configuration_then_requeues_only_selected_job(self):
        before = copy.deepcopy(self.runtime.snapshot["jobs"])
        self.apply()
        self.assertEqual(self.git("rev-parse", "HEAD"), self.target)
        self.assertEqual(self.compose.read_text(), "private compose retained\n")
        self.assertTrue(self.runtime.verified)
        self.assertFalse(self.runtime.paused)
        self.assertEqual(self.runtime.snapshot["jobs"][:7], before[:7])
        self.assertEqual(self.runtime.snapshot["jobs"][8:], before[8:])
        self.assertEqual(self.runtime.snapshot["jobs"][7]["uuid"], SELECTION[1])
        self.assertEqual(self.runtime.snapshot["jobs"][7]["status"], "queued")
        actions = self.runtime.actions
        self.assertLess(actions.index("backup"), actions.index("migrate"))
        self.assertLess(actions.index("migrate"), actions.index("requeue"))
        self.assertEqual(actions[-1], ("start", "ccvm-backend"))
        backup = next((self.root / ".git").glob("ccvm-header-findings-before-*"))
        before_state = json.loads((backup / "before.json").read_text())
        after = json.loads((backup / "after-migration.json").read_text())
        self.assertEqual(before_state["tables"], after["tables"])
        self.assertTrue((backup / "database.dump").exists())

    def test_repeated_apply_after_intent_only_verifies_without_requeue_or_restart(self):
        self.apply()
        self.runtime.actions.clear()
        self.apply()
        self.assertEqual(self.runtime.actions, [])

    def test_prepare_and_backup_failures_preserve_source_jobs_and_resume(self):
        for failure in ("prepare", "backup"):
            with self.subTest(failure=failure):
                self.runtime.fail = failure
                before = self.runtime.state()
                with self.assertRaises(RuntimeError):
                    self.apply()
                self.assertEqual(self.git("rev-parse", "HEAD"), self.base)
                self.assertEqual(self.runtime.state(), before)
                self.assertFalse(self.runtime.paused)

    def test_rolled_back_migration_restores_code_only_and_retains_database(self):
        self.runtime.fail = "migration"
        before = self.runtime.state()
        with self.assertRaisesRegex(RuntimeError, "migration rolled back"):
            self.apply()
        self.assertEqual(self.git("rev-parse", "HEAD"), self.base)
        self.assertEqual(self.runtime.state(), before)
        self.assertFalse(self.runtime.paused)
        self.assertNotIn("requeue", self.runtime.actions)

    def test_fingerprint_mismatch_keeps_api_closed_and_worker_paused(self):
        self.runtime.fail = "fingerprint"
        with self.assertRaisesRegex(RuntimeError, "fingerprints changed"):
            self.apply()
        self.assertTrue(self.runtime.paused)
        self.assertNotIn("requeue", self.runtime.actions)
        self.assertNotIn(("start", "ccvm-backend"), self.runtime.actions)

    def test_restart_failure_keeps_api_closed_without_requeuing(self):
        self.runtime.fail = "restart"
        with self.assertRaisesRegex(RuntimeError, "restart denied"):
            self.apply()
        self.assertTrue(self.runtime.paused)
        self.assertNotIn("requeue", self.runtime.actions)
        self.assertNotIn(("start", "ccvm-backend"), self.runtime.actions)

    def test_lost_requeue_response_is_not_retried(self):
        self.runtime.fail = "requeue"
        with self.assertRaisesRegex(RuntimeError, "response lost"):
            self.apply()
        self.assertFalse(self.runtime.paused)
        self.assertEqual(self.runtime.actions.count("requeue"), 1)
        self.runtime.actions.clear()
        self.apply()
        self.assertEqual(self.runtime.actions, [])

    def test_preflight_rejects_wrong_identity_changed_queue_and_other_work(self):
        mutations = [
            lambda state: state["jobs"][7].update(uuid="changed"),
            lambda state: state["jobs"][7].update(progress=11),
            lambda state: state["jobs"][7].update(plugin="other"),
            lambda state: state["jobs"][8].update(status="running"),
            lambda state: state["jobs"][9].update(parent_job_id=1),
            lambda state: state["jobs"][6].update(status="failed"),
            lambda state: state["active"].append({"id": 99, "status": "queued"}),
        ]
        for change in mutations:
            with self.subTest(change=change):
                self.runtime.snapshot = snapshot()
                change(self.runtime.snapshot)
                with self.assertRaises(RuntimeError):
                    self.apply()
                self.assertEqual(self.runtime.actions, [])
                self.assertEqual(self.git("rev-parse", "HEAD"), self.base)

    def test_private_atomic_journal_preserves_newlines_and_permissions(self):
        path = self.root / "journal.json"
        operator.write_json(path, {"message": "line one\nline two"})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(path.read_text()), {"message": "line one\nline two"})

    def test_schema_validation_rejects_missing_digest_and_wrong_column_type(self):
        state = snapshot(operator.REVISION)
        operator.validate_schema(state, expected=operator.REVISION)
        state["matched_at_type"] = "character varying"
        with self.assertRaises(RuntimeError):
            operator.validate_schema(state)
        state = snapshot(operator.REVISION)
        state["indexes"][0]["valid"] = False
        with self.assertRaises(RuntimeError):
            operator.validate_schema(state)


if __name__ == "__main__":
    unittest.main()
