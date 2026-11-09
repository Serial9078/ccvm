"""CLI-only publication never replaces services or changes private runtime state."""

import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "enrollment_updater", SCRIPTS / "update-auth-enrollment.py"
)
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)


class GitFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ccvm-enrollment-test-")
        self.root = Path(self.temporary.name)
        self.command("init", "--quiet", "--initial-branch", op.BRANCH)
        self.command("config", "user.email", "fixture@example.test")
        self.command("config", "user.name", "Synthetic CLI fixture")
        self.write("backend/app/auth_admin.py", "OLD CLI\n")
        self.write("docker-compose.yml", "retained compose\n")
        self.write("frontend/default.conf", "retained frontend\n")
        self.command("add", ".")
        self.command("commit", "--quiet", "-m", "Synthetic reviewed baseline")
        self.base = self.command("rev-parse", "HEAD")
        self.base_patch = patch.object(op, "BASE", self.base)
        self.base_patch.start()

    def tearDown(self):
        self.base_patch.stop()
        self.temporary.cleanup()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def command(self, *args):
        result = subprocess.run(
            ["git", "-C", str(self.root), *args], capture_output=True, text=True, check=True
        )
        return result.stdout.strip()

    def target(self, extra=None, *, delete=False):
        self.command("reset", "--quiet", "--hard", self.base)
        for name in op.ASSETS:
            self.write(name, "reviewed enrollment asset\n")
        if extra:
            self.write(extra, "unrelated target\n")
        if delete:
            (self.root / "frontend/default.conf").unlink()
        self.command("add", "--all")
        self.command("commit", "--quiet", "-m", "Synthetic reviewed target")
        target = self.command("rev-parse", "HEAD")
        self.command("update-ref", "refs/remotes/origin/" + op.BRANCH, target)
        self.command("reset", "--quiet", "--hard", self.base)
        return target


class SourceContract(GitFixture):
    def test_exact_cli_assets_are_allowed_and_local_configuration_is_retained(self):
        target = self.target()
        self.write("docker-compose.yml", "retained private compose override\n")
        self.write("frontend/default.conf", "retained private route\n")
        self.assertEqual(set(op.source_plan(self.root, target)), op.ASSETS)
        self.assertEqual(self.command("rev-parse", "HEAD"), self.base)

    def test_app_api_migration_dependency_frontend_and_unrelated_source_are_refused(self):
        for name in (
            "backend/app/main.py",
            "backend/app/services/auth_session.py",
            "backend/app/api/v1/auth.py",
            "backend/alembic/versions/unexpected.py",
            "backend/requirements.txt",
            "frontend/src/App.tsx",
            "docker-compose.yml",
            ".env",
        ):
            with self.subTest(name=name):
                target = self.target(name)
                with self.assertRaisesRegex(RuntimeError, "unrelated source"):
                    op.source_plan(self.root, target)

    def test_missing_assets_source_deletion_and_symlinks_are_refused(self):
        target = self.target(delete=True)
        with self.assertRaises(RuntimeError):
            op.source_plan(self.root, target)
        target = self.target()
        (self.root / "backend/app/auth_admin.py").unlink()
        (self.root / "backend/app/auth_admin.py").symlink_to("/tmp/unexpected")
        with self.assertRaises(RuntimeError):
            op.source_plan(self.root, target)

    def test_pending_login_journal_stops_advance_but_verified_journal_is_untouched(self):
        target = self.target()
        journal = self.write(
            ".git/ccvm-secure-login-deployment.json", json.dumps({"phase": "services"})
        )
        journal.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "publication is unfinished"):
            op.source_plan(self.root, target)
        journal.write_text(json.dumps({"phase": "verified"}))
        saved = journal.read_bytes()
        op.source_plan(self.root, target)
        self.assertEqual(journal.read_bytes(), saved)

    def test_wrong_target_branch_staged_changes_and_untracked_application_source_refused(self):
        target = self.target()
        with self.assertRaises(RuntimeError):
            op.source_plan(self.root, "0" * 40)
        extra = self.write("backend/app/unknown.py", "unknown\n")
        with self.assertRaisesRegex(RuntimeError, "Additional application source"):
            op.source_plan(self.root, target)
        extra.unlink()
        self.command("add", "docker-compose.yml")
        self.write("backend/app/auth_admin.py", "unreviewed source\n")
        self.command("add", "backend/app/auth_admin.py")
        with self.assertRaises(RuntimeError):
            op.source_plan(self.root, target)


class FakeBackend:
    def __init__(self, root):
        self.state = {
            "id": "retained-backend",
            "pid": 1234,
            "started": "initial-process",
            "settings_sha256": "retained",
        }
        self.probes = 0

    def inspect(self):
        return copy.deepcopy(self.state)

    def verify(self, expected):
        if self.inspect() != expected:
            raise RuntimeError("Backend identity changed")

    def probe(self):
        self.probes += 1


class PublicationContract(GitFixture):
    def setUp(self):
        super().setUp()
        self.backend = FakeBackend(self.root)
        self.backend_patch = patch.object(op, "Backend", return_value=self.backend)
        self.backend_patch.start()
        self.lock_calls = []
        self.lock_held = False
        parent = self

        class RootAdminLock:
            def __init__(self, root, *, create=False):
                parent.lock_calls.append(create)

            def __enter__(self):
                parent.lock_held = True

            def __exit__(self, *_args):
                parent.lock_held = False

        self.lock_patch = patch.object(op, "AdminLock", RootAdminLock)
        self.lock_patch.start()
        self.original_git = op.git

        def guarded_git(root, *args):
            if args[0] == "merge":
                self.assertTrue(self.lock_held, "Publication must hold the root CLI lock")
            return self.original_git(root, *args)

        self.git_patch = patch.object(op, "git", guarded_git)
        self.git_patch.start()

    def tearDown(self):
        self.git_patch.stop()
        self.lock_patch.stop()
        self.backend_patch.stop()
        super().tearDown()

    def publish(self, target, **options):
        with contextlib.redirect_stdout(io.StringIO()):
            op.publish(self.root, target, "fixture", **options)

    def record(self):
        return json.loads((self.root / ".git" / op.JOURNAL).read_text())

    def test_readonly_preflight_creates_no_backup_journal_auth_directory_or_git_lock(self):
        target = self.target()
        before = set((self.root / ".git").iterdir())
        self.publish(target)
        self.assertEqual(set((self.root / ".git").iterdir()), before)
        self.assertFalse((self.root / "backend/.ccvm-auth").exists())
        self.assertEqual(self.command("rev-parse", "HEAD"), self.base)
        self.assertEqual(self.lock_calls, [False])
        self.assertEqual(self.backend.probes, 0)

    def test_apply_and_verified_repeat_keep_process_configuration_and_source_exact(self):
        target = self.target()
        self.write("docker-compose.yml", "private retained compose\n")
        original = (self.root / "docker-compose.yml").read_bytes()
        state = self.backend.inspect()
        self.publish(target, apply=True)
        self.assertEqual(self.command("rev-parse", "HEAD"), target)
        self.assertEqual(self.record()["phase"], "verified")
        self.assertEqual((self.root / "docker-compose.yml").read_bytes(), original)
        self.assertEqual(self.backend.inspect(), state)
        self.assertFalse(self.lock_held)
        self.publish(target, apply=True, resume=True)
        self.publish(target)
        self.assertEqual(self.backend.probes, 3)

    def test_busy_enrollment_refuses_before_source_journal_or_backup_publication(self):
        target = self.target()
        with patch.object(op, "AdminLock", side_effect=RuntimeError("Strg+C")):
            with self.assertRaisesRegex(RuntimeError, "Strg.C"):
                self.publish(target, apply=True)
        self.assertEqual(self.command("rev-parse", "HEAD"), self.base)
        self.assertFalse((self.root / ".git" / op.JOURNAL).exists())
        self.assertFalse(list((self.root / ".git").glob(op.BACKUP_PREFIX + "*")))

    def test_published_interruption_requires_resume_and_does_not_remerge(self):
        target = self.target()
        with patch.object(self.backend, "probe", side_effect=RuntimeError("probe failed")):
            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                self.publish(target, apply=True)
        self.assertEqual(self.record()["phase"], "published")
        with self.assertRaisesRegex(RuntimeError, "requires --apply --resume"):
            self.publish(target, apply=True)
        self.publish(target, apply=True, resume=True)
        self.assertEqual(self.record()["phase"], "verified")

    def test_verified_repeat_accepts_a_later_restart_without_rewriting_journal_or_backup(self):
        target = self.target()
        self.publish(target, apply=True)
        marker = self.root / ".git" / op.JOURNAL
        backup = Path(self.record()["backup"]) / "before.json"
        retained = (marker.read_bytes(), backup.read_bytes(), marker.stat().st_ino)
        self.backend.state["pid"] += 1
        self.backend.state["started"] = "legitimately-restarted-process"
        current = self.backend.inspect()
        self.publish(target, apply=True, resume=True)
        self.assertEqual(self.backend.inspect(), current)
        self.assertEqual((marker.read_bytes(), backup.read_bytes(), marker.stat().st_ino), retained)
        self.assertEqual(self.record()["before"]["pid"], 1234)

    def test_verified_repeat_still_rejects_container_or_configuration_changes(self):
        target = self.target()
        self.publish(target, apply=True)
        before = self.backend.inspect()
        for key in ("id", "settings_sha256"):
            self.backend.state = {**before, key: "unexpected-runtime-change"}
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "Retained backend"):
                self.publish(target, apply=True, resume=True)

    def test_pending_recovery_refuses_a_changed_process(self):
        target = self.target()
        with patch.object(self.backend, "probe", side_effect=RuntimeError("probe failed")):
            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                self.publish(target, apply=True)
        record = self.record()
        self.assertEqual(record["phase"], "published")
        self.backend.state["pid"] += 1
        for phase in ("prepared", "published"):
            op.write_json(self.root / ".git" / op.JOURNAL, {**record, "phase": phase})
            with (
                self.subTest(phase=phase),
                self.assertRaisesRegex(RuntimeError, "Retained backend"),
            ):
                self.publish(target, apply=True, resume=True)

    def test_verified_repeat_detects_a_restart_during_its_own_verification(self):
        target = self.target()
        self.publish(target, apply=True)
        self.backend.state["pid"] += 1

        def restart_during_probe():
            self.backend.state["pid"] += 1

        with patch.object(self.backend, "probe", side_effect=restart_during_probe):
            with self.assertRaisesRegex(RuntimeError, "Backend identity changed"):
                self.publish(target, apply=True, resume=True)


class RootHelperContract(unittest.TestCase):
    def test_busy_helper_is_closed_without_killing_any_application_process(self):
        process = Mock()
        process.stdout.readline.return_value = '{"ready":false,"busy":true}\n'
        process.communicate.return_value = ("", "")
        process.returncode = 2
        with patch.object(op.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "Strg.C"):
                with op.AdminLock(Path("/synthetic")):
                    self.fail("Busy enrollment lock was ignored")
        process.communicate.assert_called_once_with(input="release\n", timeout=10)
        process.kill.assert_not_called()

    def test_helper_exit_failure_is_not_silently_accepted(self):
        process = Mock()
        process.stdout.readline.return_value = '{"ready":true}\n'
        process.communicate.return_value = ("", "private error never published")
        process.returncode = 1
        with patch.object(op.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "lock helper failed"):
                with op.AdminLock(Path("/synthetic")):
                    pass

    def test_backend_mount_restart_and_reload_guards_and_private_output(self):
        info = {
            "Id": "retained",
            "State": {"Status": "running", "Pid": 123, "StartedAt": "retained"},
            "Config": {"Cmd": ["uvicorn", "app.main:app"], "Env": ["PRIVATE=never-publish"]},
            "HostConfig": {},
            "Mounts": [
                {"Destination": "/app", "Source": "/synthetic/backend", "Type": "bind", "RW": True}
            ],
        }
        backend = op.Backend(Path("/synthetic"))
        with patch.object(backend, "docker", return_value=json.dumps([info])):
            result = backend.inspect()
        self.assertNotIn("never-publish", json.dumps(result))
        for field in ("paused", "pid", "mount", "reload"):
            changed = copy.deepcopy(info)
            if field == "paused":
                changed["State"]["Paused"] = True
            elif field == "pid":
                changed["State"]["Pid"] = 0
            elif field == "mount":
                changed["Mounts"][0]["RW"] = False
            else:
                changed["Config"]["Cmd"].append("--reload")
            with (
                self.subTest(field=field),
                patch.object(backend, "docker", return_value=json.dumps([changed])),
                self.assertRaisesRegex(RuntimeError, "Expected running retained backend"),
            ):
                backend.inspect()


if __name__ == "__main__":
    unittest.main()
