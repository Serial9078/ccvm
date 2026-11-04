"""Regression checks for mutation boundaries; fixtures contain no operational data."""

import base64
import importlib.util
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


op = load("auth_deployment", "deploy-authenticated-inventory.py")
ingress = load("auth_ingress", "authenticated_ingress.py")
EDGE = """global
    master-worker
defaults
    mode tcp
    timeout client 5s
    timeout server 5s
    timeout connect 5s
frontend http
    bind *:80
    mode http
    http-request return status 200 string old-http
frontend tls
    bind *:443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend old_tls if { req.ssl_sni -i old.example.test }
    default_backend old_tls
backend old_tls
    server old 127.0.0.1:4447
"""


def render(source=EDGE):
    return ingress.render_haproxy(
        source,
        "ccvm.example.test",
        ["192.0.2.0/24"],
        "/certs/test.pem",
        "/certs/.ccvm-audit/gateway.sock",
        4448,
        "a" * 12,
    )


class IngressGuards(unittest.TestCase):
    def test_specific_sni_precedes_existing_route(self):
        proposed = render()
        self.assertLess(
            proposed.index("use_backend ccvm_audit_tls"), proposed.index("use_backend old_tls")
        )
        self.assertIn("defaults ccvm_audit_defaults", proposed)
        self.assertEqual(proposed.count("send-proxy-v2"), 2)
        # Removing the marked additions must restore every original byte.
        import re

        original = re.sub(
            r"(?ms)^    # BEGIN CCVM AUTHENTICATED INGRESS (SNI|HTTP)\n.*?"
            r"^    # END CCVM AUTHENTICATED INGRESS \1\n",
            "",
            proposed,
        ).split("\n# BEGIN CCVM AUTHENTICATED INGRESS SECTIONS")[0]
        self.assertEqual(original, EDGE)

    def test_rejects_unsafe_or_ambiguous_edge(self):
        for source in (
            EDGE + "\nfrontend another\n    bind *:443\n",
            EDGE.replace("master-worker", "chroot /tmp"),
            EDGE.replace("bind *:443", "bind *:443 accept-proxy"),
            EDGE.replace("bind *:443", "bind *:443 ssl crt /certs/test.pem"),
            EDGE.replace("req.ssl_hello_type", "unknown"),
            EDGE + "# ccvm.example.test already managed\n",
            render(),
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                render(source)

    def test_rejects_configuration_injection(self):
        for hostname in ("https://example.test", "example.test\nlisten bad", "a.test:443"):
            with self.assertRaises(ValueError):
                ingress.selection(hostname, ["192.0.2.0/24"])
        for clients in ([], ["0.0.0.0/0"], ["192.0.2.1/24"], ["127.0.0.1/8"]):
            with self.assertRaises(ValueError):
                ingress.selection("ccvm.example.test", clients)

    def test_address_does_not_reuse_live_container_or_gateway(self):
        network = {
            "IPAM": {"Config": [{"Subnet": "192.0.2.0/29", "Gateway": "192.0.2.6"}]},
            "Containers": {"other": {"IPv4Address": "192.0.2.5/29"}},
        }
        self.assertEqual(ingress.gateway_address(network), "192.0.2.4")
        self.assertEqual(ingress.free_tls_port(EDGE + "\nbind 127.0.0.1:4448\n"), 4449)


class PrivateState(unittest.TestCase):
    def test_secret_creation_reuse_and_rotation_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private"
            operation = {}
            op.make_secrets(path, operation)
            before = {p.name: p.read_bytes() for p in path.iterdir()}
            hashes = dict(operation["secret_hashes"])
            op.make_secrets(path, operation)
            self.assertEqual(before, {p.name: p.read_bytes() for p in path.iterdir()})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            for name in before:
                self.assertEqual(stat.S_IMODE((path / name).stat().st_mode), 0o600)
            op.private_write(
                path / "vault.env", b"CCVM_AUDIT_VAULT_KEY=" + base64.b64encode(b"x" * 32) + b"\n"
            )
            with self.assertRaisesRegex(RuntimeError, "changed"):
                op.validate_secrets(path, operation)
            self.assertEqual(operation["secret_hashes"], hashes)

    def test_secret_permissions_and_symlinks_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private"
            op.make_secrets(path, {})
            (path / "operator.env").chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "permissions"):
                op.validate_secrets(path, {})
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                op.make_secrets(link, {})

    def test_root_file_protocol_keeps_bind_inode_and_rejects_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "edge.cfg"
            path.write_bytes(b"original")
            path.chmod(0o640)

            def root_io(payload):
                return subprocess.run(
                    [sys.executable, "-I", "-c", ingress.ROOT_IO],
                    input=json.dumps({**payload, "path": str(path)}).encode(),
                    capture_output=True,
                    check=False,
                )

            before = path.stat()
            snapshot = json.loads(root_io({"action": "read"}).stdout)
            payload = {
                **snapshot,
                "action": "inplace",
                "before": ingress.sha256(b"original"),
                "data": base64.b64encode(b"replacement").decode(),
            }
            self.assertEqual(root_io(payload).returncode, 0)
            after = path.stat()
            self.assertEqual(
                (before.st_ino, before.st_mode, before.st_uid, before.st_gid),
                (after.st_ino, after.st_mode, after.st_uid, after.st_gid),
            )
            self.assertNotEqual(root_io(payload).returncode, 0)
            self.assertEqual(path.read_bytes(), b"replacement")
            path.unlink()
            path.symlink_to(Path(directory) / "other")
            self.assertNotEqual(root_io({"action": "read"}).returncode, 0)


class MigrationBoundaries(unittest.TestCase):
    def test_null_inherits_image_command_but_empty_list_and_runtime_drift_do_not(self):
        legacy = load("legacy_validate_fixture", "deploy-network-scans.py")
        image = {"Config": {"Cmd": ["nginx"], "Entrypoint": ["/docker-entrypoint.sh"]}}
        spec = {
            "image": "fixture:nginx",
            "command": None,
            "entrypoint": None,
            "networks": {"default": {}},
        }
        config = {"services": {"frontend": spec}, "networks": {"default": {"name": "fixture"}}}
        container = {
            "Config": {"Image": "fixture:nginx", **image["Config"]},
            "HostConfig": {
                "Privileged": False,
                "ReadonlyRootfs": False,
                "RestartPolicy": {"Name": "no"},
            },
            "Mounts": [],
            "NetworkSettings": {"Networks": {"fixture": {}}},
        }
        op.validate_service(legacy, config, "frontend", container, image)
        spec["command"] = []
        with self.assertRaisesRegex(RuntimeError, "command"):
            op.validate_service(legacy, config, "frontend", container, image)
        spec["command"] = None
        container["Config"]["Cmd"] = ["unexpected"]
        with self.assertRaisesRegex(RuntimeError, "command"):
            op.validate_service(legacy, config, "frontend", container, image)

    def test_exact_existing_row_preservation(self):
        before = {
            "identity": {"database": "fixture"},
            "tables": {"jobs": {"count": 1, "sha256": "retained"}},
        }
        after = json.loads(json.dumps(before))
        after["tables"].update(
            {name: {"count": 0} for name in ("audit_credentials", "host_audits")}
        )
        op.assert_preserved(before, after)
        for mutation in ("row", "table", "new-data", "identity"):
            broken = json.loads(json.dumps(after))
            if mutation == "row":
                broken["tables"]["jobs"]["sha256"] = "changed"
            if mutation == "table":
                broken["tables"]["unexpected"] = {"count": 0}
            if mutation == "new-data":
                broken["tables"]["host_audits"]["count"] = 1
            if mutation == "identity":
                broken["identity"]["database"] = "other"
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                op.assert_preserved(before, broken)

    def test_active_work_blocks_migration(self):
        with self.assertRaisesRegex(RuntimeError, "Active jobs"):
            op.validate_state({"revision": op.OLD_REVISION, "active": [{"id": 1}]}, op.OLD_REVISION)

    def test_pre_migration_failure_restores_original_services(self):
        runtime = Mock()
        operation = {"phase": "quiesced"}
        with (
            patch.object(op, "restore_original_services") as restore,
            patch.object(op, "write_phase") as phase,
        ):
            op.recover_failure(runtime, operation, Path("unused"))
        restore.assert_called_once_with(runtime, operation)
        phase.assert_called_once_with(Path("unused"), operation, "built")
        runtime.helper.assert_not_called()

    def test_pause_during_idle_transaction_retries_before_backup(self):
        runtime = Mock()
        runtime.inspect.side_effect = [
            {"Id": "worker", "State": {"Running": True, "Paused": False}},
            {"Id": "backend", "State": {"Running": True}},
        ]
        stable = {"revision": op.OLD_REVISION, "active": [], "transactions": 0, "tables": {}}
        runtime.state.side_effect = [{**stable, "transactions": 1}, stable, stable]
        with tempfile.TemporaryDirectory() as directory:
            operation = {"backup": directory, "phase": "built"}
            with (
                patch.object(op, "close_application") as close,
                patch.object(op, "backup_database") as backup,
                patch.object(op.time, "sleep") as sleep,
            ):
                op.quiesce(runtime, operation, Path(directory) / "journal.json")
            close.assert_called_once_with(runtime)
            backup.assert_called_once_with(runtime, operation)
            sleep.assert_called_once_with(0.3)
            self.assertIn(unittest.mock.call("unpause", "worker"), runtime.docker.call_args_list)
            self.assertEqual(operation["phase"], "quiesced")

    def test_queue_race_keeps_job_and_never_stops_worker_or_backs_up(self):
        runtime = Mock()
        runtime.inspect.side_effect = [
            {"Id": "worker", "State": {"Running": True, "Paused": False}},
            {"Id": "backend", "State": {"Running": True}},
        ]
        runtime.state.return_value = {
            "revision": op.OLD_REVISION,
            "active": [{"id": 7}],
            "transactions": 0,
        }
        with (
            patch.object(op, "close_application") as close,
            patch.object(op, "backup_database") as backup,
        ):
            with self.assertRaisesRegex(RuntimeError, "Active jobs"):
                op.quiesce(runtime, {}, Path("unused"))
            close.assert_not_called()
            backup.assert_not_called()

    def test_post_migration_failure_retains_concurrent_edge_edit(self):
        runtime = Mock()
        runtime.root_io.return_value = {"data": base64.b64encode(b"concurrent-edit").decode()}
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "haproxy.proposed.cfg").write_bytes(b"ours")
            operation = {
                "phase": "migrated",
                "backup": directory,
                "edge_path": "/fixture",
                "edge_original": {"data": base64.b64encode(b"before").decode()},
            }
            with (
                patch.object(op, "edge_install") as install,
                patch.object(op, "close_application") as close,
            ):
                op.recover_failure(runtime, operation, Path("unused"))
            install.assert_not_called()
            close.assert_called_once_with(runtime)
            runtime.helper.assert_not_called()

    def test_database_identity_compares_exact_ip_objects(self):
        state = {
            "identity": {
                "database": "fixture",
                "address": "192.0.2.2/32",
                "port": 5432,
                "version": 160012,
            }
        }
        pg = {
            "Config": {"Env": ["POSTGRES_DB=fixture"]},
            "NetworkSettings": {"Networks": {"fixture": {"IPAddress": "192.0.2.2"}}},
        }
        op.database_identity(state, pg)
        state["identity"]["address"] = "192.0.2.3/32"
        with self.assertRaises(RuntimeError):
            op.database_identity(state, pg)

    def test_failed_command_does_not_print_private_configuration(self):
        with self.assertRaises(RuntimeError) as error:
            op.run([sys.executable, "-c", "import sys;print('private-value');sys.exit(1)"])
        self.assertNotIn("private-value", str(error.exception))


class JournalGuards(unittest.TestCase):
    def test_changed_parameters_do_not_resume(self):
        args = SimpleNamespace(
            hostname="ccvm.example.test",
            clients=["192.0.2.0/24"],
            certificate="test.pem",
            host="fixture",
            **{
                n + "_image": "sha256:" + "a" * 64
                for n in ("backend", "worker", "frontend", "edge")
            },
        )
        runtime = SimpleNamespace(target="b" * 40)
        with self.assertRaisesRegex(RuntimeError, "parameters differ"):
            op.validate_journal(runtime, args, {"target": "c" * 40}, Path("unused"))


if __name__ == "__main__":
    unittest.main()
