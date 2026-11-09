"""Read one OS record over encrypted WS-Man; no shell, writes or raw SOAP output."""

import argparse
import ipaddress
import json
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_OUTPUT = 16384
WORKER_CODE = r'''
import ipaddress
import json
import logging
import resource
import signal
import time
import xml.etree.ElementTree as ET
from types import SimpleNamespace

SOAP = "http://www.w3.org/2003/05/soap-envelope"
ADDR = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
ENUM = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
RESOURCE = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_OperatingSystem"
OS_FIELDS = (
    "Caption",
    "Version",
    "BuildNumber",
    "OSArchitecture",
    "CSName",
    "ProductType",
    "OperatingSystemSKU",
)
PHASE = "preflight"
DEADLINE = None


class ProbeFailure(ValueError):
    def __init__(self, category):
        self.category = category
        super().__init__(category)


def parse_os_response(response, expected_operation):
    if expected_operation not in {"Enumerate", "Pull"}:
        raise ProbeFailure("invalid_response")
    if isinstance(response, str):
        response = response.encode("utf-8")
    if not isinstance(response, bytes) or len(response) > 65536:
        raise ProbeFailure("invalid_response")
    try:
        document = response.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ProbeFailure("invalid_response") from None
    if "\x00" in document or "<!DOCTYPE" in document.upper() or "<!ENTITY" in document.upper():
        raise ProbeFailure("invalid_response")
    try:
        root = ET.fromstring(document)
    except (ET.ParseError, ValueError):
        raise ProbeFailure("invalid_response") from None
    nodes = list(root.iter())
    if root.tag != "{" + SOAP + "}Envelope" or len(nodes) > 512:
        raise ProbeFailure("invalid_response")
    headers = root.findall("{" + SOAP + "}Header")
    bodies = root.findall("{" + SOAP + "}Body")
    expected = ENUM + "/" + expected_operation + "Response"
    if len(headers) != 1 or len(bodies) != 1 or len(bodies[0]) != 1:
        raise ProbeFailure("invalid_response")
    actions = headers[0].findall("{" + ADDR + "}Action")
    body = bodies[0][0]
    if (
        len(actions) != 1
        or actions[0].text != expected
        or body.tag != "{" + ENUM + "}" + expected_operation + "Response"
    ):
        raise ProbeFailure("invalid_response")
    contexts = body.findall("{" + ENUM + "}EnumerationContext")
    ends = [
        node
        for node in body
        if node.tag in {"{" + ENUM + "}EndOfSequence", "{" + WSMAN + "}EndOfSequence"}
    ]
    groups = [node for node in body if node.tag in {"{" + ENUM + "}Items", "{" + WSMAN + "}Items"}]
    if len(contexts) > 1 or len(ends) > 1 or len(groups) > 1:
        raise ProbeFailure("invalid_response")
    complete = bool(ends)
    context = (contexts[0].text or None) if contexts else None
    if contexts and (len(contexts[0]) or (not context and not complete)):
        raise ProbeFailure("invalid_response")
    if context and (len(context) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in context)):
        raise ProbeFailure("invalid_response")
    if not complete and context is None:
        raise ProbeFailure("invalid_response")
    items = list(groups[0]) if groups else []
    if len(items) > 1 or (items and items[0].tag != "{" + RESOURCE + "}Win32_OperatingSystem"):
        raise ProbeFailure("invalid_response")
    row = None
    if items:
        row = {}
        for key in OS_FIELDS:
            values = items[0].findall("{" + RESOURCE + "}" + key)
            if len(values) != 1 or len(values[0]):
                raise ProbeFailure("invalid_response")
            value = values[0].text or ""
            if (
                not value
                or len(value) > 500
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
            ):
                raise ProbeFailure("invalid_response")
            row[key] = value
        if row["ProductType"] not in {"1", "2", "3"} or any(
            not row[key].isascii() or not row[key].isdigit()
            for key in ("BuildNumber", "OperatingSystemSKU")
        ):
            raise ProbeFailure("invalid_response")
    return row, context, complete


def collect_os(protocol, endpoint):
    import xmltodict

    global PHASE
    context = None
    complete = False
    primary = None

    def send(operation, body):
        message = protocol.build_wsman_header(action=ENUM + "/" + operation, resource_uri=RESOURCE)
        message["env:Header"]["a:To"] = endpoint
        message["env:Body"] = {"n:" + operation: body}
        return protocol.send_message(xmltodict.unparse({"env:Envelope": message}))

    try:
        PHASE = "enumerate"
        row, context, complete = parse_os_response(
            send(
                "Enumerate",
                {
                    "w:OptimizeEnumeration": None,
                    "w:MaxElements": "1",
                },
            ),
            "Enumerate",
        )
        if not complete:
            PHASE = "pull"
            second, next_context, complete = parse_os_response(
                send(
                    "Pull",
                    {
                        "n:EnumerationContext": context,
                        "n:MaxElements": "1",
                    },
                ),
                "Pull",
            )
            context = next_context or context
            if row is not None and second is not None:
                raise ProbeFailure("invalid_response")
            row = row if row is not None else second
        if not complete or row is None:
            raise ProbeFailure("incomplete_response")
        return row
    except BaseException as error:
        primary = error
        raise
    finally:
        if context and not complete and (DEADLINE is None or time.monotonic() < DEADLINE):
            try:
                send("Release", {"n:EnumerationContext": context})
            except Exception:
                if primary is None:
                    raise ProbeFailure("enumeration_release_failed") from None


def worker_main(config):
    global PHASE, DEADLINE
    logging.disable(logging.CRITICAL)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    session = None
    DEADLINE = time.monotonic() + 45

    def timed_out(*_):
        raise ProbeFailure("probe_timeout")

    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(45)
    try:
        from sqlalchemy import text
        from app.database.session import engine
        from app.services.audit_vault import decrypt, verify_credential_target
        from app.services.host_audit_transport import (
            transport_failure_code,
            winrm_protocol,
            winrm_session,
        )

        target = str(ipaddress.ip_address(config["target"]))
        customer = config["customer_id"]
        if type(customer) is not int or customer <= 0:
            raise ProbeFailure("invalid_request")
        PHASE = "credential"
        with engine.connect() as connection:
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
            connection.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
            record = (
                connection.execute(
                    text("""
                SELECT c.id, c.uuid, c.customer_id, c.kind, c.username,
                       c.allowed_cidrs, c.ciphertext, c.enabled
                FROM (SELECT credential_id FROM host_audits
                      WHERE customer_id = :customer AND target = :target
                      ORDER BY created_at DESC, id DESC LIMIT 1) AS latest
                JOIN audit_credentials c ON c.id = latest.credential_id
            """),
                    {"customer": customer, "target": target},
                )
                .mappings()
                .one_or_none()
            )
        if record is None or record["kind"] != "winrm":
            raise ProbeFailure("credential_unavailable")
        credential = SimpleNamespace(**dict(record))
        verify_credential_target(credential, target, customer)
        secrets = decrypt(credential)
        PHASE = "authenticate"
        protocol, endpoint = winrm_protocol(
            {
                "target": target,
                "port": 5985,
                "winrm_transport": "http_ntlm",
                "username": credential.username,
                "secrets": secrets,
            }
        )
        session = winrm_session(protocol.transport, endpoint, None)
        row = collect_os(protocol, endpoint)
        result = {
            "status": "os_read_success",
            "target": target,
            "port": 5985,
            "transport": "http_ntlm",
            "os": row,
            "assessment": "not_performed",
            "inventory_persisted": False,
        }
    except Exception as error:
        classify = locals().get("transport_failure_code", lambda _: "probe_failed")
        category = error.category if isinstance(error, ProbeFailure) else classify(error)
        result = {"status": "failed", "phase": PHASE, "category": category}
        for name in ("wsman_fault_code", "wmierror_code", "code"):
            value = getattr(error, name, None)
            if type(value) is int and -(2**31) <= value <= 2**32 - 1:
                result[name] = value
    finally:
        signal.alarm(0)
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
    print(json.dumps(result, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    worker_main(CONFIG)
'''


class ProbeFailure(RuntimeError):
    pass


def run_docker(args, input_text=None, timeout=10):
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(
                ["sudo", "-n", "docker", *args],
                input=None if input_text is None else input_text.encode("utf-8"),
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ProbeFailure("docker_unavailable_or_timeout") from None
        output.seek(0)
        data = output.read(MAX_OUTPUT + 1)
    if result.returncode != 0 or len(data) > MAX_OUTPUT:
        raise ProbeFailure("docker_failed_or_output_exceeded")
    return data.decode("utf-8", errors="strict")


def inspect_worker():
    template = '{"id":{{json .Id}},"state":{{json .State}},"mounts":{{json .Mounts}}}'
    info = json.loads(run_docker(["inspect", "--format", template, "ccvm-worker"]))
    state = info["state"]
    if (
        state.get("Status") != "running"
        or state.get("Running") is not True
        or state.get("Paused") is not False
        or state.get("Restarting") is not False
    ):
        raise ProbeFailure("worker_not_running_unpaused")
    expected = str((Path.cwd() / "backend").resolve())
    if not any(
        m.get("Type") == "bind"
        and m.get("Source") == expected
        and m.get("Destination") == "/app"
        and m.get("RW") is True
        for m in info["mounts"]
    ):
        raise ProbeFailure("worker_bind_mismatch")
    if (
        not isinstance(info["id"], str)
        or len(info["id"]) != 64
        or any(c not in "0123456789abcdef" for c in info["id"])
    ):
        raise ProbeFailure("worker_identity_invalid")
    return info["id"]


def public_response(response, target):
    """Project only fixed diagnostics or the seven explicitly selected OS fields."""
    if not isinstance(response, dict):
        raise ProbeFailure("invalid_worker_response")
    if response.get("status") == "os_read_success":
        expected = {
            "status",
            "target",
            "port",
            "transport",
            "os",
            "assessment",
            "inventory_persisted",
        }
        fields = (
            "Caption",
            "Version",
            "BuildNumber",
            "OSArchitecture",
            "CSName",
            "ProductType",
            "OperatingSystemSKU",
        )
        row = response.get("os")
        if (
            set(response) != expected
            or response.get("target") != target
            or type(response.get("port")) is not int
            or response.get("port") != 5985
            or response.get("transport") != "http_ntlm"
            or response.get("assessment") != "not_performed"
            or response.get("inventory_persisted") is not False
            or not isinstance(row, dict)
            or set(row) != set(fields)
        ):
            raise ProbeFailure("invalid_worker_response")
        if any(
            not isinstance(value, str)
            or not value
            or len(value) > 500
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
            for value in row.values()
        ):
            raise ProbeFailure("invalid_worker_response")
        if row["ProductType"] not in {"1", "2", "3"} or any(
            not row[key].isascii() or not row[key].isdigit()
            for key in ("BuildNumber", "OperatingSystemSKU")
        ):
            raise ProbeFailure("invalid_worker_response")
        return {
            **{key: response[key] for key in expected - {"os"}},
            "os": {key: row[key] for key in fields},
        }
    required = {"status", "phase", "category"}
    numeric = {"wsman_fault_code", "wmierror_code", "code"}
    categories = {
        "invalid_request",
        "invalid_response",
        "incomplete_response",
        "probe_timeout",
        "credential_unavailable",
        "enumeration_release_failed",
        "probe_failed",
        "host_key_mismatch",
        "invalid_private_key",
        "output_limit",
        "redirect_rejected",
        "message_encryption_required",
        "collector_command_limit",
        "remote_command_too_long",
        "remote_powershell_parse_failed",
        "remote_permission_denied",
        "remote_command_unavailable",
        "remote_command_failed",
        "authentication_failed",
        "winrm_access_denied",
        "winrm_endpoint_unavailable",
        "winrm_http_error",
        "connection_or_collection_failed",
        "tls_verification_failed",
        "winrm_service_fault",
        "connection_refused",
        "network_unreachable",
        "connection_interrupted",
        "response_timeout",
        "winrm_operation_timeout",
        "network_timeout",
        "connection_failed",
    }
    if (
        not required <= set(response) <= required | numeric
        or response.get("status") != "failed"
        or not isinstance(response.get("phase"), str)
        or response["phase"] not in {"preflight", "credential", "authenticate", "enumerate", "pull"}
        or not isinstance(response.get("category"), str)
        or response["category"] not in categories
        or any(
            type(response[key]) is not int or not -(2**31) <= response[key] <= 2**32 - 1
            for key in numeric & set(response)
        )
    ):
        raise ProbeFailure("invalid_worker_response")
    return {key: response[key] for key in required | (numeric & set(response))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--customer-id", type=int, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--host", choices=("neptun",), default="neptun")
    args = parser.parse_args(argv)
    try:
        target = str(ipaddress.ip_address(args.target))
        if args.customer_id <= 0 or "%" in args.target:
            raise ProbeFailure("invalid_request")
        if socket.gethostname().split(".")[0] != args.host:
            raise ProbeFailure("wrong_host")
        if Path.cwd().resolve() != Path("/opt/ccvm"):
            raise ProbeFailure("wrong_directory")
        worker_id = inspect_worker()
        config = json.dumps({"customer_id": args.customer_id, "target": target})
        source = "CONFIG = " + config + "\n" + WORKER_CODE
        response = json.loads(
            run_docker(
                ["exec", "-i", "--workdir", "/app", worker_id, "python", "-"],
                source,
                timeout=60,
            )
        )
        if inspect_worker() != worker_id:
            raise ProbeFailure("worker_identity_changed")
        response = public_response(response, target)
        print(json.dumps(response, ensure_ascii=False, indent=2))
        return 0 if response["status"] == "os_read_success" else 1
    except (ProbeFailure, ValueError, KeyError, TypeError):
        print(json.dumps({"status": "failed", "category": "probe_preflight_or_runtime_failed"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
