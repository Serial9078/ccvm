"""Reuse the staged maintenance guards for one selected failed Nuclei stage."""

import ast
import contextlib
import copy
import functools
import io
import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import test_update_header_findings as header_test

nuclei = header_test.load("nuclei_template_operator_test", "update-nuclei-templates.py")
SELECTION = (10, "22222222-2222-4222-8222-222222222222")


class NucleiTemplateUpdateTests(unittest.TestCase):
    git = header_test.HeaderFindingsUpdateTests.git

    def setUp(self):
        header_test.HeaderFindingsUpdateTests.setUp(self)
        self.header = header_test.load("nuclei_staged_operator_test", "update-header-findings.py")
        self.header.OLD_REVISION = self.header.REVISION
        self.header.selected_pipeline = nuclei.selected_pipeline
        self.header.validate_state = functools.partial(
            nuclei.validate_state, schema_validator=self.header.validate_schema
        )
        self.header.requeue_source = nuclei.requeue_source
        self.header.verify = lambda *args: setattr(self.runtime, "verified", True)
        self.module.validate_state = functools.partial(
            self.header.validate_state, selection=SELECTION
        )
        self.runtime.snapshot = header_test.snapshot(nuclei.REVISION)
        self.runtime.snapshot["active"] = []
        for row in self.runtime.snapshot["jobs"]:
            row.update(status="finished", progress=100, worker="ccvm-worker-01")
        self.runtime.snapshot["jobs"][9].update(
            uuid=SELECTION[1], status="failed", message="no templates provided for scan"
        )
        self.runtime.maintenance_python = self.requeue

    def install(self, runtime, backup):
        assert runtime.paused and (backup / "database.dump").exists()
        runtime.actions.append("templates")
        if runtime.fail == "templates":
            raise RuntimeError("template installation failed")

    def requeue(self, code):
        assert self.runtime.paused and self.runtime.started == 2
        payload = json.loads(ast.literal_eval(code.splitlines()[0].split("=", 1)[1]))
        assert payload["jobs"] == self.runtime.snapshot["jobs"]
        assert payload["job_id"] == SELECTION[0]
        self.runtime.actions.append("requeue")
        self.runtime.snapshot["jobs"][9].update(
            status="queued", progress=0, message=nuclei.RETRY_MESSAGE, worker=None
        )
        return json.dumps({"requeued": SELECTION[0]})

    def apply(self):
        plan = self.module.source_plan(self.root, self.target)
        with contextlib.redirect_stdout(io.StringIO()):
            self.header.apply(
                self.root,
                self.target,
                SELECTION,
                self.module,
                self.runtime,
                plan,
                journal_name="ccvm-nuclei-templates-retry.json",
                backup_prefix="ccvm-nuclei-templates-before-",
                install_runtime=self.install,
            )

    def test_backups_and_templates_precede_the_only_selected_retry(self):
        before = copy.deepcopy(self.runtime.snapshot["jobs"])
        self.apply()
        self.assertEqual(self.runtime.snapshot["jobs"][:9], before[:9])
        self.assertEqual(self.runtime.snapshot["jobs"][9]["uuid"], SELECTION[1])
        self.assertEqual(self.runtime.snapshot["jobs"][9]["status"], "queued")
        actions = self.runtime.actions
        self.assertLess(actions.index("backup"), actions.index("templates"))
        self.assertLess(actions.index("templates"), actions.index("requeue"))
        self.assertNotIn("migrate", actions)
        self.assertTrue(self.runtime.verified)

    def test_failed_template_install_rolls_back_source_and_preserves_failed_job(self):
        self.runtime.fail = "templates"
        before = self.runtime.state()
        with self.assertRaisesRegex(RuntimeError, "template installation failed"):
            self.apply()
        self.assertEqual(self.git("rev-parse", "HEAD"), self.base)
        self.assertEqual(self.runtime.state(), before)
        self.assertNotIn("requeue", self.runtime.actions)
        self.assertFalse(self.runtime.paused)

    def test_repeat_only_verifies_and_uses_a_separate_journal(self):
        self.apply()
        self.runtime.actions.clear()
        self.apply()
        self.assertEqual(self.runtime.actions, [])
        self.assertFalse((self.root / ".git/ccvm-header-findings-resume.json").exists())

    def test_changed_identity_parent_and_other_active_work_are_refused(self):
        for defect in ("uuid", "parent", "running", "different-failure", "other-work"):
            with self.subTest(defect=defect):
                state = self.runtime.state()
                if defect == "uuid":
                    state["jobs"][9]["uuid"] = "wrong"
                elif defect == "parent":
                    state["jobs"][8]["status"] = "failed"
                elif defect == "running":
                    state["jobs"][9]["status"] = "running"
                elif defect == "different-failure":
                    state["jobs"][9]["message"] = "unrelated error"
                else:
                    state["active"] = [{"id": 99, "status": "queued"}]
                with self.assertRaises(RuntimeError):
                    nuclei.selected_pipeline(state, SELECTION)

    def test_real_provision_hook_creates_mountpoint_and_bounds_combined_helper(self):
        backup = self.root / "private-backup"
        backup.mkdir()
        runtime = SimpleNamespace(
            worker_info={"Config": {"Env": []}},
            prefix=["docker"],
            maintenance_args=["run", "--workdir", "/app", "image", "-c"],
        )

        def provision(command, **kwargs):
            cache = self.root / "backend/.scanner-data"
            self.assertTrue(cache.is_dir())
            self.assertIn(f"type=bind,src={cache},dst=/app/.scanner-data", command)
            self.assertEqual(kwargs["timeout"], 300)
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    {"directory": nuclei.CATALOG, "yaml_files": 100, "selected_templates": 50}
                ),
                "",
            )

        with patch.object(nuclei.subprocess, "run", provision):
            with contextlib.redirect_stdout(io.StringIO()):
                nuclei.install_templates(self.root, runtime, backup)
        self.assertTrue((backup / "templates.json").is_file())


if __name__ == "__main__":
    unittest.main()
