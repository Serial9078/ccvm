"""Isolated, bounded transport. Receives secrets on stdin, never argv or files.

This script imports no application configuration or database credentials. Its
parent enforces a wall-clock deadline and discards all raw transport errors.
"""

import base64
import errno
import hashlib
import hmac
import importlib.util
import io
import ipaddress
import json
import logging
import os
import resource
import signal
import sys
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path
from time import monotonic

import paramiko
import requests
from urllib3.exceptions import (
    ConnectTimeoutError,
    MaxRetryError,
    NewConnectionError,
    ReadTimeoutError,
)
from winrm.exceptions import (
    InvalidCredentialsError,
    WinRMOperationTimeoutError,
    WinRMTransportError,
    WSManFaultError,
)
from winrm.protocol import Protocol

MAX_OUTPUT = 8 * 1024 * 1024
NTLM_ENCRYPTED_TYPE = 'protocol="application/HTTP-SPNEGO-session-encrypted"'


class TransportFailure(Exception):
    pass


FIXED_FAILURES = frozenset(
    {
        "host_key_mismatch",
        "invalid_private_key",
        "invalid_request",
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
        "cim_invalid_response",
        "cim_incomplete_response",
    }
)


def http_failure_code(status):
    """Classify status only; never parse or return an HTTP error body."""
    if status == 401:
        return "authentication_failed"
    if status == 403:
        return "winrm_access_denied"
    if status in {404, 405, 410}:
        return "winrm_endpoint_unavailable"
    return "winrm_http_error"


def exception_chain(error):
    """Bounded typed causes from requests/urllib3 and Paramiko; no string parsing."""
    pending = [error]
    seen = set()
    while pending and len(seen) < 16:
        current = pending.pop(0)
        if not isinstance(current, BaseException) or id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        cause = current.__cause__
        if cause is not None:
            pending.append(cause)
        elif not current.__suppress_context__:
            pending.append(current.__context__)
        pending.extend(value for value in current.args[:4] if isinstance(value, BaseException))
        if isinstance(current, MaxRetryError):
            pending.append(current.reason)
        if isinstance(current, paramiko.ssh_exception.NoValidConnectionsError):
            pending.extend(islice(current.errors.values(), 4))


def transport_failure_code(error):
    """Return only allowlisted diagnostics, even when upstream errors contain secrets."""
    if isinstance(error, TransportFailure):
        code = error.args[0] if len(error.args) == 1 else None
        if isinstance(code, str) and code in FIXED_FAILURES:
            return code
        return "connection_or_collection_failed"
    errors = tuple(exception_chain(error))
    if any(isinstance(item, requests.exceptions.SSLError) for item in errors):
        return "tls_verification_failed"
    if any(
        isinstance(item, (paramiko.AuthenticationException, InvalidCredentialsError))
        for item in errors
    ):
        return "authentication_failed"
    if any(isinstance(item, WSManFaultError) for item in errors):
        return "winrm_service_fault"
    for item in errors:
        if isinstance(item, WinRMTransportError):
            return http_failure_code(item.code)
        if isinstance(item, requests.exceptions.HTTPError) and item.response is not None:
            return http_failure_code(item.response.status_code)
    # urllib3's NewConnectionError is ALSO a ConnectTimeoutError. Prefer the
    # actual socket errno so refused/unroutable connections are not called timeouts.
    for item in errors:
        if isinstance(item, OSError):
            if item.errno == errno.ECONNREFUSED:
                return "connection_refused"
            if item.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN}:
                return "network_unreachable"
            if item.errno in {errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE}:
                return "connection_interrupted"
    if any(
        isinstance(item, (requests.exceptions.ReadTimeout, ReadTimeoutError)) for item in errors
    ):
        return "response_timeout"
    if any(isinstance(item, WinRMOperationTimeoutError) for item in errors):
        return "winrm_operation_timeout"
    if any(
        isinstance(item, (requests.exceptions.Timeout, TimeoutError))
        or (isinstance(item, ConnectTimeoutError) and not isinstance(item, NewConnectionError))
        or (isinstance(item, OSError) and item.errno == errno.ETIMEDOUT)
        for item in errors
    ):
        return "network_timeout"
    if any(
        isinstance(item, (requests.exceptions.ConnectionError, NewConnectionError))
        for item in errors
    ):
        return "connection_failed"
    return "connection_or_collection_failed"


class PinnedHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, fingerprint):
        self.fingerprint = fingerprint

    def missing_host_key(self, client, hostname, key):
        actual = "SHA256:" + base64.b64encode(
            hashlib.sha256(key.asbytes()).digest()
        ).decode().rstrip("=")
        if not hmac.compare_digest(actual, self.fingerprint):
            # SSHClient invokes this policy before attempting authentication.
            raise TransportFailure("host_key_mismatch")


def private_key(value, passphrase):
    for kind in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return kind.from_private_key(io.StringIO(value), password=passphrase)
        except (paramiko.SSHException, ValueError):
            continue
    raise TransportFailure("invalid_private_key")


def ssh_collect(payload):
    mode = payload["mode"]
    if mode not in {"connection", "inventory"}:
        raise TransportFailure("invalid_request")
    secrets = payload["secrets"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedHostKey(payload["ssh_fingerprint"]))
    try:
        client.connect(
            hostname=payload["target"],
            port=payload["port"],
            username=payload["username"],
            password=secrets.get("password"),
            pkey=(
                private_key(secrets["private_key"], secrets.get("passphrase"))
                if payload["kind"] == "ssh_key"
                else None
            ),
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            channel_timeout=10,
        )
        # The only variable is a validated enum, not a target-supplied command.
        source = Path(__file__).with_name("linux_inventory.py").read_bytes()
        stdin, stdout, stderr = client.exec_command(f"python3 -I - {mode}", timeout=70)
        stdin.write(source)
        stdin.flush()
        stdin.channel.shutdown_write()
        data = stdout.read(MAX_OUTPUT + 1)
        # Do not return remote stderr: it may contain account/secret material.
        if len(data) > MAX_OUTPUT:
            raise TransportFailure("output_limit")
        if stdout.channel.recv_exit_status() != 0:
            raise TransportFailure("remote_command_failed")
        return json.loads(data)
    finally:
        client.close()


def restricted_session(session, endpoint, ca_bundle, require_encryption=False):
    """Block proxy/netrc environment credentials and all redirect destinations."""
    session.trust_env = False
    session.proxies = {}
    session.verify = ca_bundle or True
    original_send = session.send

    def send(request, **kwargs):
        if request.url != endpoint:
            raise TransportFailure("redirect_rejected")
        # pywinrm starts NTLM with an empty POST. Every subsequent WSMan
        # message over HTTP must be wrapped, including server responses.
        # Its normal response parser otherwise also accepts plaintext SOAP.
        encrypted_message = require_encryption and bool(request.body)
        if encrypted_message and NTLM_ENCRYPTED_TYPE not in request.headers.get("Content-Type", ""):
            raise TransportFailure("message_encryption_required")
        kwargs.update(allow_redirects=False, verify=ca_bundle or True, proxies={})
        response = original_send(request, **kwargs)
        if response.is_redirect or response.is_permanent_redirect:
            raise TransportFailure("redirect_rejected")
        if len(response.content) > MAX_OUTPUT:
            raise TransportFailure("output_limit")
        if encrypted_message and NTLM_ENCRYPTED_TYPE not in response.headers.get(
            "Content-Type", ""
        ):
            if response.status_code >= 400:
                # Discard plaintext error bodies without accepting SOAP/evidence.
                # An HTTP failure still identifies auth, endpoint or access errors.
                raise TransportFailure(http_failure_code(response.status_code))
            raise TransportFailure("message_encryption_required")
        return response

    session.send = send
    return session


def winrm_protocol(payload):
    winrm_transport = payload.get("winrm_transport", "https")
    if winrm_transport not in {"https", "http_ntlm"}:
        raise TransportFailure("invalid_request")
    target = str(ipaddress.ip_address(payload["target"]))
    if ":" in target:
        target = f"[{target}]"
    http_ntlm = winrm_transport == "http_ntlm"
    scheme = "http" if http_ntlm else "https"
    endpoint = f"{scheme}://{target}:{payload['port']}/wsman"
    # Session's convenience URL parser rewrites bracketed IPv6 URLs in pywinrm
    # 0.5.0. Protocol preserves the selected literal-IP endpoint and scheme.
    protocol = Protocol(
        endpoint=endpoint,
        username=payload["username"],
        password=payload["secrets"]["password"],
        transport="ntlm",
        server_cert_validation="validate",
        ca_trust_path=None if http_ntlm else payload.get("ca_bundle"),
        proxy=None,
        send_cbt=True,
        message_encryption="always" if http_ntlm else "auto",
        operation_timeout_sec=15,
        read_timeout_sec=20,
    )
    if protocol.transport.endpoint != endpoint:
        raise TransportFailure("invalid_request")
    return protocol, endpoint


def winrm_session(transport, endpoint, ca_bundle):
    """Restrict even the first HTTP NTLM handshake before it reaches the wire."""
    http_ntlm = endpoint.startswith("http://")
    hardened = None
    if http_ntlm:
        # build_session() invokes setup_encryption(), which authenticates with
        # an empty POST before returning. Harden its session at that boundary;
        # wrapping only the returned session would be too late.
        setup_encryption = transport.setup_encryption

        def secured_setup(session):
            nonlocal hardened
            hardened = restricted_session(session, endpoint, None, require_encryption=True)
            return setup_encryption(hardened)

        transport.setup_encryption = secured_setup
    try:
        session = transport.build_session()
        if session is hardened:
            return session
        return restricted_session(
            session, endpoint, None if http_ntlm else ca_bundle, require_encryption=http_ntlm
        )
    except Exception:
        session = getattr(transport, "session", None)
        if session is not None:
            session.close()
        raise


def remote_command_failure(stderr, stdout=b""):
    """Classify only fixed Windows failure categories; never expose remote text."""
    # PowerShell CLIXML and cmd.exe messages can contain account names, paths or
    # command text. Inspect bounded data locally and return allowlisted codes.
    data = b" ".join(value[:32768] for value in (stderr, stdout) if isinstance(value, bytes))
    text = data.decode("utf-8", errors="ignore").replace("\x00", "").casefold()
    if any(
        value in text
        for value in (
            "the command line is too long",
            "die befehlszeile ist zu lang",
            "die eingabezeile ist zu lang",
        )
    ):
        return "remote_command_too_long"
    if any(value in text for value in ("parsererror", "parseexception", "missingendcurlybrace")):
        return "remote_powershell_parse_failed"
    if any(
        value in text
        for value in (
            "unauthorizedaccessexception",
            "permissiondenied",
            "access is denied",
            "zugriff verweigert",
        )
    ):
        return "remote_permission_denied"
    if "commandnotfoundexception" in text or any(
        value in text
        for value in ("'powershell' is not recognized", "'powershell.exe' is not recognized")
    ):
        return "remote_command_unavailable"
    return "remote_command_failed"


def windows_inventory_command(mode):
    # The isolated process runs Python -I from / and does not import the app.
    # Load only this reviewed stdlib-only sibling, never an environment path.
    path = Path(__file__).with_name("windows_inventory_command.py")
    spec = importlib.util.spec_from_file_location("ccvm_fixed_windows_command", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.build_command(mode)
    except module.CommandLimitError:
        raise TransportFailure("collector_command_limit") from None
    except ValueError:
        raise TransportFailure("invalid_request") from None


def winrm_collect(payload):
    started = monotonic()
    # Validate and bound BOTH separate launches before authentication. Ordinary
    # inventory/connection paths remain exactly one fixed command.
    updates = payload["mode"] == "windows_updates"
    inventory_mode = "inventory" if updates else payload["mode"]
    inventory_command = windows_inventory_command(inventory_mode)
    update_command = windows_inventory_command("windows_updates") if updates else None
    protocol, endpoint = winrm_protocol(payload)
    transport = protocol.transport
    http = winrm_session(transport, endpoint, payload.get("ca_bundle"))
    shell = None
    data = None

    def run_fixed(fixed):
        command = None
        try:
            executable, arguments = fixed
            command = protocol.run_command(shell, executable, arguments, skip_cmd_shell=True)
            stdout, stderr, status = protocol.get_command_output(shell, command)
            if status != 0:
                raise TransportFailure(remote_command_failure(stderr, stdout))
            if len(stdout) > MAX_OUTPUT:
                raise TransportFailure("output_limit")
            return json.loads(stdout.decode("utf-8-sig"))
        finally:
            if command:
                try:
                    protocol.cleanup_command(shell, command)
                except Exception:
                    if not updates:
                        raise

    try:
        shell = protocol.open_shell(noprofile=True, codepage=65001, idle_timeout="PT60S")
        data = run_fixed(inventory_command)
        if updates:
            if not isinstance(data, dict):
                raise TransportFailure("invalid_request")
            if monotonic() - started > 90:
                # Keep room for the fixed 60s job plus WSMan cleanup inside the
                # existing 180s global deadline; never extend it for this mode.
                data["windows_updates"] = unavailable_windows_updates("timeout")
            else:
                try:
                    data["windows_updates"] = run_fixed(update_command)
                except Exception:
                    # Base evidence survives a second-command/COM/format failure.
                    # No remote stderr, account, URL, or exception crosses this boundary.
                    data["windows_updates"] = unavailable_windows_updates("update_query_failed")
        return data
    finally:
        try:
            if shell:
                try:
                    protocol.close_shell(shell, close_session=False)
                except Exception:
                    if not (updates and data is not None):
                        raise
        finally:
            try:
                http.close()
            except Exception:
                if not (updates and data is not None):
                    raise


def cim_collect(payload):
    """Use only reviewed WMI enumeration; never fall back to a shell."""
    started = monotonic()
    if payload.get("kind") != "winrm" or payload.get("mode") not in {
        "cim_connection",
        "cim_inventory",
    }:
        raise TransportFailure("invalid_request")
    path = Path(__file__).with_name("windows_cim.py")
    spec = importlib.util.spec_from_file_location("ccvm_windows_cim", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    protocol, endpoint = winrm_protocol(payload)
    http = winrm_session(protocol.transport, endpoint, payload.get("ca_bundle"))
    try:
        try:
            return module.collect(
                protocol,
                endpoint,
                payload["mode"],
                deadline=started + (40 if payload["mode"] == "cim_connection" else 165),
            )
        except module.CimError as error:
            raise TransportFailure(error.code) from None
    finally:
        try:
            http.close()
        except Exception:
            pass


def unavailable_windows_updates(error_code):
    return {
        "schema_version": 1,
        "source": "windows-update-agent",
        "mode": "online",
        "server_selection": "default",
        "queried_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "unavailable",
        "result_code": None,
        "total": 0,
        "items": [],
        "truncated": False,
        "hidden_updates": "not_assessed",
        "drivers": "not_assessed",
        "superseded": "excluded",
        "reboot_required": None,
        "error_code": error_code,
    }


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    logging.disable(logging.CRITICAL)
    try:
        incoming = sys.stdin.buffer.read(512 * 1024 + 1)
        if len(incoming) > 512 * 1024:
            raise TransportFailure("invalid_request")
        payload = json.loads(incoming)
        # Independent wall-clock enforcement still stops remote authentication
        # if the parent is blocked while checking database cancellation state.
        signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
        signal.alarm(45 if payload["mode"] in {"connection", "cim_connection"} else 180)
        if payload["mode"] in {"cim_connection", "cim_inventory"}:
            data = cim_collect(payload)
        else:
            data = winrm_collect(payload) if payload["kind"] == "winrm" else ssh_collect(payload)
        output = json.dumps({"inventory": data}, ensure_ascii=True).encode()
        if len(output) > MAX_OUTPUT:
            raise TransportFailure("output_limit")
        sys.stdout.buffer.write(output)
    except Exception as error:
        # Never serialize exceptions, stdout/stderr, requests, or payloads.
        print(json.dumps({"error": transport_failure_code(error)}))


if __name__ == "__main__":
    main()
