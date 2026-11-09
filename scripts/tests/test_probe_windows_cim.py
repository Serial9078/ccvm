"""Read-only CIM readiness never uses WinRS or publishes raw transport data."""

import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cim_probe", SCRIPTS / "probe-windows-cim.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

SOAP = "http://www.w3.org/2003/05/soap-envelope"
ADDR = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
ENUM = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
RESOURCE = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_OperatingSystem"
ENDPOINT = "http://192.0.2.10:5985/wsman"
PRIVATE = "synthetic-private-upstream-response-and-password"
OS = {
    "CSName": "TEST-CLIENT",
    "Caption": "Microsoft Windows 11 Pro",
    "Version": "10.0.26300",
    "BuildNumber": "26300",
    "OSArchitecture": "64-bit",
    "ProductType": "1",
    "OperatingSystemSKU": "48",
}


def worker_namespace():
    namespace = {"__name__": "cim_probe_worker_tests"}
    exec(compile(probe.WORKER_CODE, "<cim-probe-worker>", "exec"), namespace)
    return namespace


def response(operation="Enumerate", *, rows=None, context=None, complete=True, item_ns=None):
    root = ET.Element(f"{{{SOAP}}}Envelope")
    header = ET.SubElement(root, f"{{{SOAP}}}Header")
    ET.SubElement(header, f"{{{ADDR}}}Action").text = f"{ENUM}/{operation}Response"
    body = ET.SubElement(root, f"{{{SOAP}}}Body")
    result = ET.SubElement(body, f"{{{ENUM}}}{operation}Response")
    if context is not None:
        ET.SubElement(result, f"{{{ENUM}}}EnumerationContext").text = context
    extension_ns = WSMAN if operation == "Enumerate" else ENUM
    if rows is not None:
        items = ET.SubElement(result, f"{{{extension_ns}}}Items")
        for values in rows:
            row = ET.SubElement(items, f"{{{item_ns or RESOURCE}}}Win32_OperatingSystem")
            for key, value in values.items():
                ET.SubElement(row, f"{{{item_ns or RESOURCE}}}{key}").text = value
    if complete:
        ET.SubElement(result, f"{{{extension_ns}}}EndOfSequence")
    return ET.tostring(root, encoding="utf-8")


class FakeProtocol:
    def __init__(self, responses):
        self.responses = deque(responses)
        self.calls = []

    def build_wsman_header(self, action, resource_uri):
        return {
            "@xmlns:env": SOAP,
            "@xmlns:a": ADDR,
            "@xmlns:n": ENUM,
            "@xmlns:w": WSMAN,
            "env:Header": {
                "a:To": "http://windows-host:5985/wsman",
                "a:Action": {"#text": action},
                "w:ResourceURI": {"#text": resource_uri},
            },
        }

    def send_message(self, document):
        self.calls.append(copy.deepcopy(document))
        value = self.responses.popleft()
        if isinstance(value, BaseException):
            raise value
        return value

    def open_shell(self, *_args, **_kwargs):
        raise AssertionError("A read-only CIM probe must not open a shell")

    run_command = open_shell
    get_command_output = open_shell
    close_shell = open_shell


class CimResponseTests(unittest.TestCase):
    def setUp(self):
        self.worker = worker_namespace()
        self.parse = self.worker["parse_os_response"]

    def test_optimized_enumeration_only_returns_allowlisted_os_properties(self):
        values = dict(OS, RegisteredUser=PRIVATE)
        row, context, complete = self.parse(response(rows=[values]), "Enumerate")
        self.assertEqual(set(row), set(OS))
        self.assertEqual(str(row["ProductType"]), "1")
        self.assertEqual(row["BuildNumber"], "26300")
        self.assertNotIn(PRIVATE, json.dumps(row))
        self.assertIsNone(context)
        self.assertTrue(complete)

    def test_pull_uses_the_enumeration_namespace_for_items(self):
        row, context, complete = self.parse(response("Pull", rows=[OS]), "Pull")
        self.assertEqual(row["CSName"], "TEST-CLIENT")
        self.assertIsNone(context)
        self.assertTrue(complete)

    def test_unoptimized_enumeration_returns_only_bounded_context(self):
        row, context, complete = self.parse(
            response(context="opaque-context-1", complete=False), "Enumerate"
        )
        self.assertIsNone(row)
        self.assertEqual(context, "opaque-context-1")
        self.assertFalse(complete)

    def test_wrong_operation_and_foreign_class_namespace_are_rejected(self):
        for xml, operation in (
            (response("Pull", rows=[OS]), "Enumerate"),
            (response(rows=[OS], item_ns="https://untrusted.example/OS"), "Enumerate"),
            (b"<Envelope><Body/></Envelope>", "Enumerate"),
        ):
            with self.subTest(operation=operation, xml=xml[:80]):
                with self.assertRaises(self.worker["ProbeFailure"]):
                    self.parse(xml, operation)

    def test_multiple_os_instances_are_rejected(self):
        with self.assertRaises(self.worker["ProbeFailure"]):
            self.parse(response(rows=[OS, OS]), "Enumerate")

    def test_dtd_entities_and_oversized_xml_are_rejected(self):
        malicious = b'<!DOCTYPE x [<!ENTITY secret "private">]><x>&secret;</x>'
        utf16 = malicious.decode("ascii").encode("utf-16")
        for xml in (malicious, utf16, b"x" * (2 * 1024 * 1024)):
            with self.subTest(length=len(xml)):
                with self.assertRaises(self.worker["ProbeFailure"]):
                    self.parse(xml, "Enumerate")


class CimProtocolTests(unittest.TestCase):
    def setUp(self):
        self.worker = worker_namespace()
        # Preserve request dictionaries for assertions; transport serialization
        # itself belongs to the already-used pywinrm/xmltodict dependency.
        self.serializer = patch.dict(
            sys.modules, {"xmltodict": SimpleNamespace(unparse=copy.deepcopy)}
        )
        self.serializer.start()
        self.addCleanup(self.serializer.stop)

    def collect(self, replies):
        protocol = FakeProtocol(replies)
        result = self.worker["collect_os"](protocol, ENDPOINT)
        return result, protocol

    def assert_fixed_requests(self, protocol):
        for call in protocol.calls:
            envelope = call["env:Envelope"]
            header = envelope["env:Header"]
            self.assertEqual(header["a:To"], ENDPOINT)
            self.assertEqual(header["w:ResourceURI"]["#text"], RESOURCE)
            self.assertNotIn("w:SelectorSet", header)
            self.assertNotIn("shell", header["a:Action"]["#text"])

    def test_single_completed_os_response_never_creates_a_shell(self):
        result, protocol = self.collect([response(rows=[OS])])
        self.assertEqual(result["CSName"], "TEST-CLIENT")
        self.assertEqual(len(protocol.calls), 1)
        self.assert_fixed_requests(protocol)

    def test_one_continuation_reads_only_the_existing_context(self):
        result, protocol = self.collect(
            [response(context="context-1", complete=False), response("Pull", rows=[OS])]
        )
        self.assertEqual(result["BuildNumber"], "26300")
        self.assertEqual(len(protocol.calls), 2)
        pull = protocol.calls[1]["env:Envelope"]["env:Body"]["n:Pull"]
        self.assertEqual(pull["n:EnumerationContext"], "context-1")
        self.assertIn("n:MaxElements", pull)
        self.assertNotIn("w:MaxElements", pull)
        self.assert_fixed_requests(protocol)

    def test_failed_pull_releases_context_and_preserves_original_exception(self):
        original = RuntimeError(PRIVATE)
        protocol = FakeProtocol(
            [response(context="context-1", complete=False), original, RuntimeError("cleanup")]
        )
        with self.assertRaises(RuntimeError) as caught:
            self.worker["collect_os"](protocol, ENDPOINT)
        self.assertIs(caught.exception, original)
        self.assertEqual(len(protocol.calls), 3)
        release = protocol.calls[-1]["env:Envelope"]["env:Body"]["n:Release"]
        self.assertEqual(release["n:EnumerationContext"], "context-1")
        self.assert_fixed_requests(protocol)

    def test_unfinished_pull_is_released_without_an_unbounded_loop(self):
        protocol = FakeProtocol(
            [
                response(context="context-1", complete=False),
                response("Pull", context="context-2", complete=False),
                b"",
            ]
        )
        with self.assertRaises(self.worker["ProbeFailure"]):
            self.worker["collect_os"](protocol, ENDPOINT)
        self.assertEqual(len(protocol.calls), 3)
        release = protocol.calls[-1]["env:Envelope"]["env:Body"]["n:Release"]
        self.assertEqual(release["n:EnumerationContext"], "context-2")


@unittest.skipUnless(importlib.util.find_spec("xmltodict"), "backend XML dependency unavailable")
class CimWireSerializationTests(unittest.TestCase):
    def test_real_serializer_emits_one_namespaced_soap_envelope(self):
        worker = worker_namespace()
        protocol = FakeProtocol([response(rows=[OS])])
        result = worker["collect_os"](protocol, ENDPOINT)
        self.assertEqual(result["CSName"], "TEST-CLIENT")
        self.assertEqual(len(protocol.calls), 1)
        wire = protocol.calls[0]
        root = ET.fromstring(wire)
        self.assertEqual(root.tag, f"{{{SOAP}}}Envelope")
        header = root.find(f"{{{SOAP}}}Header")
        self.assertEqual(header.find(f"{{{ADDR}}}To").text, ENDPOINT)
        self.assertEqual(header.find(f"{{{WSMAN}}}ResourceURI").text, RESOURCE)
        self.assertEqual(header.find(f"{{{ADDR}}}Action").text, f"{ENUM}/Enumerate")
        body = root.find(f"{{{SOAP}}}Body")
        self.assertEqual(len(body), 1)
        query = body.find(f"{{{ENUM}}}Enumerate")
        self.assertIsNotNone(query.find(f"{{{WSMAN}}}OptimizeEnumeration"))
        self.assertEqual(query.find(f"{{{WSMAN}}}MaxElements").text, "1")

    @unittest.skipUnless(
        importlib.util.find_spec("winrm"), "backend pywinrm dependency unavailable"
    )
    def test_real_pywinrm_header_is_serialized_without_shell_or_secret_material(self):
        from winrm.protocol import Protocol

        worker = worker_namespace()
        protocol = Protocol(
            endpoint=ENDPOINT,
            transport="ntlm",
            username=PRIVATE,
            password=PRIVATE,
            message_encryption="always",
            operation_timeout_sec=15,
            read_timeout_sec=20,
        )
        protocol.send_message = Mock(return_value=response(rows=[OS]))
        protocol.open_shell = Mock(side_effect=AssertionError("No shell allowed"))
        protocol.run_command = Mock(side_effect=AssertionError("No remote command allowed"))
        worker["collect_os"](protocol, ENDPOINT)
        wire = protocol.send_message.call_args.args[0]
        self.assertNotIn(PRIVATE, wire)
        root = ET.fromstring(wire)
        self.assertEqual(root.tag, f"{{{SOAP}}}Envelope")
        self.assertEqual(root.find(f"{{{SOAP}}}Header/{{{ADDR}}}To").text, ENDPOINT)
        self.assertEqual(root.find(f"{{{SOAP}}}Header/{{{WSMAN}}}ResourceURI").text, RESOURCE)
        protocol.open_shell.assert_not_called()
        protocol.run_command.assert_not_called()


class CimCredentialTests(unittest.TestCase):
    def setUp(self):
        self.worker = worker_namespace()
        self.worker["signal"] = SimpleNamespace(SIGALRM=14, signal=Mock(), alarm=Mock())
        self.worker["logging"] = SimpleNamespace(CRITICAL=50, disable=Mock())
        self.worker["resource"] = SimpleNamespace(RLIMIT_CORE=4, RLIMIT_AS=9, setrlimit=Mock())
        self.record = {
            "id": 5,
            "uuid": "98bf164a-ce11-4417-a88d-fde6da3f8cdb",
            "customer_id": 1,
            "kind": "winrm",
            "username": "EXAMPLE\\scanner",
            "allowed_cidrs": ["192.0.2.0/24"],
            "ciphertext": b"private-encrypted-fixture",
            "enabled": True,
        }
        self.connection = Mock()
        self.connection.execute.return_value.mappings.return_value.one_or_none.side_effect = (
            lambda: self.record
        )
        self.connection_context = contextlib.nullcontext(self.connection)
        self.engine = SimpleNamespace(connect=Mock(return_value=self.connection_context))
        self.steps = []

        def verify(credential, target, customer):
            self.steps.append("verify")
            if not credential.enabled or credential.customer_id != customer:
                raise ValueError(PRIVATE)
            if target != "192.0.2.10":
                raise ValueError(PRIVATE)

        def decrypt(_credential):
            self.steps.append("decrypt")
            return {"password": PRIVATE}

        self.verify = Mock(side_effect=verify)
        self.decrypt = Mock(side_effect=decrypt)
        self.protocol = Mock()
        self.session = Mock()
        self.winrm_protocol = Mock(return_value=(self.protocol, ENDPOINT))
        self.winrm_session = Mock(return_value=self.session)
        self.modules = {
            "sqlalchemy": SimpleNamespace(text=lambda value: value),
            "app.database.session": SimpleNamespace(engine=self.engine),
            "app.services.audit_vault": SimpleNamespace(
                decrypt=self.decrypt, verify_credential_target=self.verify
            ),
            "app.services.host_audit_transport": SimpleNamespace(
                winrm_protocol=self.winrm_protocol,
                winrm_session=self.winrm_session,
                transport_failure_code=lambda _error: "connection_or_collection_failed",
            ),
        }
        self.worker["collect_os"] = Mock(return_value=dict(OS))

    def invoke(self):
        output = io.StringIO()
        with patch.dict(sys.modules, self.modules), contextlib.redirect_stdout(output):
            self.worker["worker_main"]({"customer_id": 1, "target": "192.0.2.10"})
        text = output.getvalue()
        self.assertNotIn(PRIVATE, text)
        self.assertNotIn("ciphertext", text)
        return json.loads(text)

    def test_saved_credential_is_read_only_scope_checked_and_not_rewritten(self):
        result = self.invoke()
        self.assertEqual(result["status"], "os_read_success")
        self.assertEqual(self.steps, ["verify", "decrypt"])
        statements = [call.args[0] for call in self.connection.exec_driver_sql.call_args_list]
        self.assertEqual(statements[0], "SET TRANSACTION READ ONLY")
        self.assertIn("statement_timeout", statements[1])
        query, parameters = self.connection.execute.call_args.args
        self.assertEqual(parameters, {"customer": 1, "target": "192.0.2.10"})
        self.assertIn("LIMIT 1", query)
        self.assertIn("ORDER BY", query)
        self.assertNotIn("UPDATE ", query.upper())
        payload = self.winrm_protocol.call_args.args[0]
        self.assertEqual(payload["username"], "EXAMPLE\\scanner")
        self.assertEqual(payload["port"], 5985)
        self.assertEqual(payload["winrm_transport"], "http_ntlm")
        self.assertEqual(result["assessment"], "not_performed")
        self.session.close.assert_called_once_with()

    def test_missing_revoked_wrong_customer_or_wrong_kind_never_falls_back(self):
        for change in (None, {"enabled": False}, {"customer_id": 2}, {"kind": "ssh_password"}):
            with self.subTest(change=change):
                self.setUp()
                if change is None:
                    self.record = None
                else:
                    self.record.update(change)
                result = self.invoke()
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["phase"], "credential")
                self.winrm_protocol.assert_not_called()
                self.decrypt.assert_not_called()
                self.connection.execute.assert_called_once()

    def test_credential_scope_denial_does_not_decrypt_or_authenticate(self):
        self.verify.side_effect = ValueError(PRIVATE)
        result = self.invoke()
        self.assertEqual(result["status"], "failed")
        self.decrypt.assert_not_called()
        self.winrm_session.assert_not_called()

    def test_only_bounded_numeric_fault_fields_are_emitted(self):
        class PrivateFault(Exception):
            code = 500
            wsman_fault_code = 2150858770
            wmierror_code = -(2**31) - 1
            response = PRIVATE

            def __str__(self):
                raise AssertionError("A raw upstream exception must not be printed")

        self.worker["collect_os"].side_effect = PrivateFault()
        result = self.invoke()
        self.assertEqual(result["code"], 500)
        self.assertEqual(result["wsman_fault_code"], 2150858770)
        self.assertNotIn("wmierror_code", result)
        self.assertNotIn("response", result)
        self.session.close.assert_called_once_with()


class CimHostGuardTests(unittest.TestCase):
    def worker(self):
        return {
            "id": "1" * 64,
            "state": {
                "Status": "running",
                "Running": True,
                "Paused": False,
                "Restarting": False,
            },
            "mounts": [
                {
                    "Type": "bind",
                    "Source": "/opt/ccvm/backend",
                    "Destination": "/app",
                    "RW": True,
                }
            ],
        }

    def inspect(self, info):
        with (
            patch.object(probe.Path, "cwd", return_value=Path("/opt/ccvm")),
            patch.object(probe, "run_docker", return_value=json.dumps(info)),
        ):
            return probe.inspect_worker()

    def test_only_expected_running_unpaused_worker_bind_is_accepted(self):
        info = self.worker()
        self.assertEqual(self.inspect(info), "1" * 64)
        for change in (
            {"Status": "exited"},
            {"Running": False},
            {"Paused": True},
            {"Restarting": True},
        ):
            with self.subTest(change=change):
                info = self.worker()
                info["state"].update(change)
                with self.assertRaises(probe.ProbeFailure):
                    self.inspect(info)

    def test_altered_readonly_and_absent_bind_mounts_are_rejected(self):
        for mounts in (
            [],
            [{"Type": "volume", "Source": "/opt/ccvm/backend", "Destination": "/app", "RW": True}],
            [{"Type": "bind", "Source": "/elsewhere", "Destination": "/app", "RW": True}],
            [{"Type": "bind", "Source": "/opt/ccvm/backend", "Destination": "/app", "RW": False}],
        ):
            with self.subTest(mounts=mounts):
                info = self.worker()
                info["mounts"] = mounts
                with self.assertRaises(probe.ProbeFailure):
                    self.inspect(info)

    def test_docker_timeout_is_safe_and_does_not_echo_private_error(self):
        error = subprocess.TimeoutExpired([PRIVATE], 1, output=PRIVATE, stderr=PRIVATE)
        with patch.object(probe.subprocess, "run", side_effect=error):
            with self.assertRaises(probe.ProbeFailure) as caught:
                probe.run_docker(["inspect", "ccvm-worker"])
        self.assertNotIn(PRIVATE, str(caught.exception))

    def test_docker_output_is_bounded_and_stderr_discarded(self):
        def oversized(_argv, **kwargs):
            self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 10)
            kwargs["stdout"].write(b"x" * (probe.MAX_OUTPUT + 1))
            return SimpleNamespace(returncode=0)

        with patch.object(probe.subprocess, "run", side_effect=oversized):
            with self.assertRaises(probe.ProbeFailure):
                probe.run_docker(["inspect", "ccvm-worker"])

    def success(self):
        return {
            "status": "os_read_success",
            "target": "192.0.2.10",
            "port": 5985,
            "transport": "http_ntlm",
            "os": dict(OS),
            "assessment": "not_performed",
            "inventory_persisted": False,
        }

    def test_public_result_refuses_raw_extras_and_unperformed_assessment_claims(self):
        for change in (
            {"raw_response": PRIVATE},
            {"target": "192.0.2.99"},
            {"assessment": "patched"},
            {"inventory_persisted": True},
            {"transport": "unencrypted"},
            {"os": dict(OS, RegisteredUser=PRIVATE)},
        ):
            with self.subTest(change=change):
                result = self.success()
                result.update(change)
                with self.assertRaises(probe.ProbeFailure):
                    probe.public_response(result, "192.0.2.10")

    def test_public_failure_fields_are_typed_bounded_and_allowlisted(self):
        failure = {
            "status": "failed",
            "phase": "authenticate",
            "category": "authentication_failed",
            "code": 401,
        }
        self.assertEqual(probe.public_response(failure, "192.0.2.10"), failure)
        for change in (
            {"reason": PRIVATE},
            {"category": PRIVATE},
            {"phase": PRIVATE},
            {"code": True},
            {"wsman_fault_code": 2**32},
            {"wmierror_code": PRIVATE},
        ):
            with self.subTest(change=change):
                result = dict(failure, **change)
                with self.assertRaises(probe.ProbeFailure):
                    probe.public_response(result, "192.0.2.10")

    def test_wrong_host_never_inspects_or_executes_docker(self):
        output = io.StringIO()
        with (
            patch.object(probe.socket, "gethostname", return_value="other-host"),
            patch.object(probe, "inspect_worker") as inspect,
            patch.object(probe, "run_docker") as docker,
            contextlib.redirect_stdout(output),
        ):
            result = probe.main(["--customer-id", "1", "--target", "192.0.2.10"])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "failed")
        inspect.assert_not_called()
        docker.assert_not_called()

    def test_worker_identity_change_stops_result_publication(self):
        output = io.StringIO()
        with (
            patch.object(probe.socket, "gethostname", return_value="neptun"),
            patch.object(probe.Path, "cwd", return_value=Path("/opt/ccvm")),
            patch.object(probe, "inspect_worker", side_effect=["1" * 64, "2" * 64]),
            patch.object(probe, "run_docker", return_value=json.dumps(self.success())),
            contextlib.redirect_stdout(output),
        ):
            result = probe.main(["--customer-id", "1", "--target", "192.0.2.10"])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "failed")
        self.assertNotIn("TEST-CLIENT", output.getvalue())


if __name__ == "__main__":
    unittest.main()
