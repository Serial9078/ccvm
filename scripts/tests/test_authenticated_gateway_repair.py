"""Retained-deployment repair boundaries; no operational addresses or credentials."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


repair = load("gateway_repair_fixture", "repair-authenticated-gateway.py")
operator = load("gateway_operator_fixture", "deploy-authenticated-inventory.py")


class RepairTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        private = root / "private"
        private.mkdir()
        (private / "gateway.conf").write_text("reviewed listener\n")
        attempt = root / "attempt"
        attempt.mkdir()
        after = {
            "identity": {"database": "fixture"},
            "tables": {"jobs": {"count": 1, "sha256": "retained"}},
            "revision": operator.REVISION,
            "active": [],
            "transactions": 0,
        }
        (attempt / "after.json").write_text(json.dumps(after))
        operation = {
            "target": repair.DEPLOYMENT,
            "phase": "services",
            "hostname": "ccvm.example.test",
            "clients": ["192.0.2.0/24"],
            "certificate": "test.pem",
            "pins": {},
            "private": str(private),
            "socket_dir": str(root / "socket"),
            "gateway_address": "192.0.2.254",
            "gateway_hash": repair.hashlib.sha256(b"reviewed listener\n").hexdigest(),
            "attempt_dir": str(attempt),
            "images": {"backend": "backend", "worker": "worker", "frontend": "nginx"},
            "backup": str(root),
            "socket_gid": 0,
            "network": "fixture",
        }
        ingress = SimpleNamespace(
            render_override=lambda *a: b'volumes: [{"target": "/run/ccvm"}]\n'.decode(),
            render_gateway=lambda *a: "reviewed listener\n",
        )
        before, after_overlay = repair.overlay_pair(ingress, operation, root)
        (root / operator.OVERRIDE).write_bytes(before)
        marker = root / "deployment.json"
        operator.write_json(marker, operation)
        original = Mock(OVERRIDE=operator.OVERRIDE, REVISION=operator.REVISION)
        original.private_write = operator.private_write
        original.write_json = operator.write_json
        original.validate_state = operator.validate_state
        runtime = Mock(root=root, prefix=["docker"])
        runtime.state.return_value = after
        runtime.docker.side_effect = lambda *a, **kw: (
            "ccvm-audit-gateway" if a[0] == "ps" else "/run"
        )
        runtime.inspect.side_effect = lambda name: {
            "ccvm-backend": {"Image": "backend", "State": {"Running": False}},
            "ccvm-worker": {"Image": "worker", "State": {"Running": False}},
            "ccvm-audit-gateway": {
                "Image": "nginx",
                "Mounts": [],
                "HostConfig": {"Tmpfs": {"/var/run": "", "/tmp": "", "/var/cache/nginx": ""}},
            },
            "nginx": {"Config": {}},
        }[name]
        args = SimpleNamespace(host="fixture", target="a" * 40, apply=True)
        original.verify_resolved.return_value = {
            "services": {
                "audit-gateway": {
                    "volumes": [
                        {
                            "type": "bind",
                            "source": operation["socket_dir"],
                            "target": "/var/run/ccvm",
                        }
                    ]
                }
            }
        }
        return SimpleNamespace(
            root=root,
            op=operation,
            ingress=ingress,
            marker=marker,
            original=original,
            runtime=runtime,
            args=args,
            before=before,
            after=after_overlay,
            repair_marker=root / repair.REPAIR_JOURNAL,
        )

    def invoke(self, f):
        result = SimpleNamespace(
            returncode=0,
            stdout=b"",
            stderr=(b"bind() to unix:/run/ccvm/gateway.sock failed (2: No such file or directory)"),
        )
        with patch("subprocess.run", return_value=result):
            repair.repair(
                f.original, f.ingress, f.runtime, Mock(), f.args, f.marker, f.op, f.repair_marker
            )

    def test_one_mount_field_changes_and_every_other_byte_stays(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(directory)
            self.assertEqual(f.after.replace(b"/var/run/ccvm", b"/run/ccvm"), f.before)
            f.ingress.render_override = lambda *a: '{"target": "/run/ccvm"} {"target": "/run/ccvm"}'
            with self.assertRaises(RuntimeError):
                repair.overlay_pair(f.ingress, f.op, f.root)

    def test_records_intent_before_write_then_recreates_only_gateway(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(directory)

            def recreate(*args, **kwargs):
                self.assertTrue(f.repair_marker.is_file())
                self.assertEqual((f.root / operator.OVERRIDE).read_bytes(), f.after)
                self.assertEqual(args[-1], "audit-gateway")

            f.runtime.compose.side_effect = recreate
            with patch.object(repair, "wait_gateway"):
                self.invoke(f)
            f.runtime.compose.assert_called_once()
            f.original.activate.assert_called_once()
            self.assertEqual(json.loads(f.repair_marker.read_text())["phase"], "verified")
            f.runtime.helper.assert_not_called()
            self.assertEqual(json.loads(f.marker.read_text())["target"], repair.DEPLOYMENT)

    def test_unrelated_overlay_change_is_retained_without_recreation(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(directory)
            (f.root / operator.OVERRIDE).write_bytes(f.before + b"unrelated edit")
            with self.assertRaisesRegex(RuntimeError, "overlay changed"):
                self.invoke(f)
            f.runtime.compose.assert_not_called()
            self.assertFalse(f.repair_marker.exists())

    def test_new_database_work_blocks_the_correction(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(directory)
            f.runtime.state.return_value = {**f.runtime.state.return_value, "active": [{"id": 7}]}
            with self.assertRaisesRegex(RuntimeError, "Active jobs"):
                self.invoke(f)
            f.runtime.compose.assert_not_called()
            self.assertEqual((f.root / operator.OVERRIDE).read_bytes(), f.before)

    def test_changed_saved_evidence_blocks_the_correction(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(directory)
            f.runtime.state.return_value = {**f.runtime.state.return_value, "tables": {}}
            with self.assertRaisesRegex(RuntimeError, "database evidence changed"):
                self.invoke(f)
            f.runtime.compose.assert_not_called()
            self.assertFalse(f.repair_marker.exists())

    def test_readiness_failure_closes_writers_and_keeps_intent_for_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(directory)
            with patch.object(
                repair, "wait_gateway", side_effect=RuntimeError("fixture unhealthy")
            ):
                with self.assertRaisesRegex(RuntimeError, "unhealthy"):
                    self.invoke(f)
            f.original.recover_failure.assert_called_once_with(f.runtime, f.op, f.marker)
            f.original.activate.assert_not_called()
            self.assertEqual(json.loads(f.repair_marker.read_text())["phase"], "intent")

    def test_verified_repeat_does_not_recreate_or_recheck_old_empty_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(directory)
            with patch.object(repair, "wait_gateway"):
                self.invoke(f)
            f.op["phase"] = "verified"
            f.runtime.reset_mock()
            self.invoke(f)
            f.runtime.compose.assert_not_called()
            f.runtime.state.assert_not_called()

    def test_restarting_gateway_is_never_accepted_as_stable(self):
        runtime = Mock()
        operation = {"network": "fixture", "gateway_address": "192.0.2.254"}
        runtime.inspect.return_value = {
            "Id": "fixture",
            "State": {"Running": True, "Paused": False, "Restarting": True, "StartedAt": "fixture"},
            "NetworkSettings": {"Networks": {"fixture": {"IPAddress": "192.0.2.254"}}},
        }
        with patch.object(repair.time, "sleep"), patch("subprocess.run") as host_check:
            with self.assertRaisesRegex(RuntimeError, "remains unhealthy"):
                repair.wait_gateway(runtime, operation)
            host_check.assert_not_called()

    def test_recorded_intent_accepts_exact_old_live_mount_before_recreation(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(directory)
            gateway = f.runtime.inspect("ccvm-audit-gateway")

            def validate(legacy, config, *args):
                target = config["services"]["audit-gateway"]["volumes"][0]["target"]
                if target != "/run/ccvm":
                    raise RuntimeError("mount differs")

            f.original.validate_service.side_effect = validate
            repair.validate_gateway(
                f.original,
                f.runtime,
                Mock(),
                f.original.verify_resolved.return_value,
                gateway,
                f.op,
                True,
            )
            self.assertEqual(f.original.validate_service.call_count, 2)
            with self.assertRaisesRegex(RuntimeError, "differs from"):
                repair.validate_gateway(
                    f.original,
                    f.runtime,
                    Mock(),
                    f.original.verify_resolved.return_value,
                    gateway,
                    f.op,
                    False,
                )

    def test_interrupted_recreation_with_gateway_absent_can_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(directory)
            with patch.object(
                repair, "wait_gateway", side_effect=RuntimeError("fixture interrupted")
            ):
                with self.assertRaises(RuntimeError):
                    self.invoke(f)
            f.runtime.docker.side_effect = lambda *a, **kw: "" if a[0] == "ps" else "/run"
            with patch.object(repair, "wait_gateway"):
                self.invoke(f)
            self.assertEqual(f.original.activate.call_count, 1)

    def test_repair_journal_write_failure_after_verified_keeps_services_available(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(directory)

            def activated(*args):
                f.op["phase"] = "verified"

            def write(path, value):
                if path == f.repair_marker and value.get("phase") == "verified":
                    raise OSError("fixture disk full")
                operator.write_json(path, value)

            f.original.activate.side_effect = activated
            f.original.write_json = Mock(side_effect=write)
            with patch.object(repair, "wait_gateway"):
                with self.assertRaisesRegex(OSError, "disk full"):
                    self.invoke(f)
            f.original.recover_failure.assert_not_called()


if __name__ == "__main__":
    unittest.main()
