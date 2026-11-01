import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

SPEC = importlib.util.spec_from_file_location(
    "reconcile_neptun", Path(__file__).resolve().parents[1] / "reconcile-neptun.py"
)
RECONCILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECONCILE)


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ccvm-reconcile-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "-q", "--initial-branch=development")
        self.git("config", "user.name", "CI fixture")
        self.git("config", "user.email", "ci@example.test")
        self.write("backend/app/main.py", "old application\n")
        self.write("docker-compose.yml", "repository config\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.snapshot_main = "reviewed local application\n"
        self.snapshot_plugin = "reviewed local plugin\n"
        self.write("backend/app/main.py", "formatted reviewed local application\n")
        self.write("backend/app/plugins/feature.py", self.snapshot_plugin)
        self.write("docs/integration.md", "integration documentation\n")
        self.git("add", ".")
        self.git("commit", "-qm", "reviewed integration")
        self.target = self.git("rev-parse", "HEAD").strip()
        self.git("reset", "--hard", self.base)
        self.write("backend/app/main.py", self.snapshot_main)
        self.write("backend/app/plugins/feature.py", self.snapshot_plugin)
        self.write("docker-compose.yml", "private local config stays here\n")
        self.write("nuclei-templates/local.yaml", "local template stays here\n")
        self.manifest = {
            "branch": "development",
            "head": self.base,
            "ci_base": self.base,
            "files": {
                "backend/app/main.py": hashlib.sha256(self.snapshot_main.encode()).hexdigest(),
                "backend/app/plugins/feature.py": hashlib.sha256(
                    self.snapshot_plugin.encode()
                ).hexdigest(),
            },
        }
        self.probe = Mock()

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args], text=True, stderr=subprocess.PIPE
        )

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def state(self):
        return {
            "head": self.git("rev-parse", "HEAD"),
            "index": (self.root / ".git/index").read_bytes(),
            "files": {
                p.relative_to(self.root).as_posix(): p.read_bytes()
                for p in self.root.rglob("*")
                if p.is_file() and ".git" not in p.parts
            },
        }

    def apply(self, apply=True):
        return RECONCILE.reconcile(
            self.root, self.target, self.manifest, apply=apply, probe=self.probe
        )

    def test_apply_preserves_private_configuration_and_untracked_data(self):
        backup = self.apply()
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.target)
        self.assertEqual(
            (self.root / "docker-compose.yml").read_text(), "private local config stays here\n"
        )
        self.assertEqual(
            (self.root / "nuclei-templates/local.yaml").read_text(), "local template stays here\n"
        )
        self.assertEqual((backup / "files/backend/app/main.py").read_text(), self.snapshot_main)
        self.assertEqual(
            (backup / "files/backend/app/plugins/feature.py").read_text(), self.snapshot_plugin
        )
        self.assertTrue((backup / "index").is_file())
        self.assertEqual(self.probe.call_count, 2)
        self.assertNotIn("backend/app", self.git("status", "--short"))
        self.assertEqual(self.git("stash", "list"), "")

    def test_preflight_does_not_modify_checkout(self):
        before = self.state()
        self.apply(apply=False)
        self.assertEqual(self.state(), before)

    def test_source_edit_after_export_is_preserved_and_rejected(self):
        self.write("backend/app/main.py", "changed again after export\n")
        before = self.state()
        with self.assertRaisesRegex(RuntimeError, "Source changed"):
            self.apply()
        self.assertEqual(self.state(), before)
        self.probe.assert_not_called()

    def test_untracked_target_collision_is_preserved_and_rejected(self):
        self.write("docs/integration.md", "unrelated operator document\n")
        before = self.state()
        with self.assertRaisesRegex(RuntimeError, "File changed"):
            self.apply()
        self.assertEqual(self.state(), before)

    def test_additional_source_after_export_is_preserved_and_rejected(self):
        self.write("backend/app/new_feature.py", "new unreviewed source\n")
        before = self.state()
        with self.assertRaisesRegex(RuntimeError, "Additional source"):
            self.apply()
        self.assertEqual(self.state(), before)

    def test_staged_changes_are_rejected(self):
        self.git("add", "docker-compose.yml")
        before = self.state()
        with self.assertRaisesRegex(RuntimeError, "Staged changes"):
            self.apply()
        self.assertEqual(self.state(), before)

    def test_preflight_health_failure_preserves_checkout(self):
        self.probe.side_effect = RuntimeError("health unavailable")
        before = self.state()
        with self.assertRaisesRegex(RuntimeError, "health unavailable"):
            self.apply()
        self.assertEqual(self.state(), before)

    def test_post_update_health_failure_restores_files_index_and_head(self):
        self.probe.side_effect = [None, RuntimeError("health unavailable")]
        before = self.state()
        with self.assertRaisesRegex(RuntimeError, "original files/index were restored"):
            self.apply()
        self.assertEqual(self.state(), before)
        self.assertFalse((self.root / "docs/integration.md").exists())

    def test_repeat_invocation_is_idempotent_and_detects_later_edits(self):
        self.apply()
        before = self.state()
        self.assertIsNone(self.apply())
        self.assertEqual(self.state(), before)
        self.write("backend/app/main.py", "operator edit after deployment\n")
        before = self.state()
        with self.assertRaisesRegex(RuntimeError, "Source changed"):
            self.apply()
        self.assertEqual(self.state(), before)

    def test_protected_configuration_change_in_target_is_rejected(self):
        self.git("reset", "--hard", self.target)
        self.write("docker-compose.yml", "target changes protected config\n")
        self.git("add", "docker-compose.yml")
        self.git("commit", "-qm", "unsafe configuration change")
        self.target = self.git("rev-parse", "HEAD").strip()
        self.git("reset", "--hard", self.base)
        self.write("backend/app/main.py", self.snapshot_main)
        self.write("backend/app/plugins/feature.py", self.snapshot_plugin)
        before = self.state()
        with self.assertRaisesRegex(RuntimeError, "protected configuration"):
            self.apply()
        self.assertEqual(self.state(), before)


if __name__ == "__main__":
    unittest.main()
