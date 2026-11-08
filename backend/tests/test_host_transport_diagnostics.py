"""Actionable transport failures without publishing upstream or remote material."""

import errno
import io
import json
from types import SimpleNamespace

import paramiko
import pytest
import requests
from urllib3.exceptions import MaxRetryError, NewConnectionError, ReadTimeoutError
from winrm.exceptions import InvalidCredentialsError, WinRMTransportError, WSManFaultError

from app.services import host_audit_transport as transport
from app.services import host_inventory

PRIVATE = "synthetic-account-password-url-or-response-material"


def wrapped_socket_error(number):
    socket_error = OSError(number, PRIVATE)
    connection_error = NewConnectionError(None, PRIVATE)
    connection_error.__cause__ = socket_error
    retries = MaxRetryError(None, PRIVATE, reason=connection_error)
    return requests.exceptions.ConnectionError(retries)


def http_error(status):
    response = requests.Response()
    response.status_code = status
    response._content = PRIVATE.encode()
    return requests.exceptions.HTTPError(PRIVATE, response=response)


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (wrapped_socket_error(errno.ECONNREFUSED), "connection_refused"),
        (wrapped_socket_error(errno.EHOSTUNREACH), "network_unreachable"),
        (wrapped_socket_error(errno.ENETUNREACH), "network_unreachable"),
        (wrapped_socket_error(errno.ECONNRESET), "connection_interrupted"),
        (wrapped_socket_error(errno.ETIMEDOUT), "network_timeout"),
        (requests.exceptions.ConnectTimeout(PRIVATE), "network_timeout"),
        (requests.exceptions.ReadTimeout(PRIVATE), "response_timeout"),
        (
            requests.exceptions.ConnectionError(ReadTimeoutError(None, PRIVATE, PRIVATE)),
            "response_timeout",
        ),
        (requests.exceptions.ConnectionError(PRIVATE), "connection_failed"),
        (requests.exceptions.SSLError(PRIVATE), "tls_verification_failed"),
        (InvalidCredentialsError(PRIVATE), "authentication_failed"),
        (paramiko.AuthenticationException(PRIVATE), "authentication_failed"),
        (http_error(401), "authentication_failed"),
        (http_error(403), "winrm_access_denied"),
        (http_error(404), "winrm_endpoint_unavailable"),
        (WinRMTransportError("http", 405, PRIVATE), "winrm_endpoint_unavailable"),
        (WinRMTransportError("http", 503, PRIVATE), "winrm_http_error"),
        (WSManFaultError(500, PRIVATE, PRIVATE, PRIVATE), "winrm_service_fault"),
        (transport.TransportFailure("message_encryption_required"), "message_encryption_required"),
        (transport.TransportFailure(PRIVATE), "connection_or_collection_failed"),
        (RuntimeError(PRIVATE), "connection_or_collection_failed"),
    ],
)
def test_isolated_failure_boundary_outputs_only_a_fixed_code(monkeypatch, capsys, error, code):
    def fail(_payload):
        raise error

    monkeypatch.setattr(transport, "winrm_collect", fail)
    monkeypatch.setattr(transport.resource, "setrlimit", lambda *_args: None)
    monkeypatch.setattr(transport.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(transport.signal, "alarm", lambda *_args: None)
    monkeypatch.setattr(transport.logging, "disable", lambda *_args: None)
    monkeypatch.setattr(
        transport.sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(b'{"kind":"winrm","mode":"connection"}')),
    )
    transport.main()
    output = capsys.readouterr()
    assert json.loads(output.out) == {"error": code}
    assert output.err == ""
    assert PRIVATE not in output.out
    assert code in host_inventory.ERRORS


def test_unknown_new_connection_error_is_not_misreported_as_a_timeout():
    error = requests.exceptions.ConnectionError(
        MaxRetryError(None, PRIVATE, NewConnectionError(None, PRIVATE))
    )
    assert transport.transport_failure_code(error) == "connection_failed"


def test_ssh_connection_errors_are_classified_without_returning_addresses():
    error = paramiko.ssh_exception.NoValidConnectionsError(
        {("192.0.2.1", 22): ConnectionRefusedError(errno.ECONNREFUSED, PRIVATE)}
    )
    assert transport.transport_failure_code(error) == "connection_refused"


def test_exception_graph_is_bounded_and_does_not_call_exception_string():
    class Unprintable(Exception):
        def __str__(self):
            pytest.fail("Raw upstream error was converted to text")

    error = Unprintable(PRIVATE)
    error.__cause__ = error
    assert transport.transport_failure_code(error) == "connection_or_collection_failed"


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (401, "authentication_failed"),
        (403, "winrm_access_denied"),
        (404, "winrm_endpoint_unavailable"),
        (405, "winrm_endpoint_unavailable"),
        (500, "winrm_http_error"),
    ],
)
def test_plaintext_http_failure_is_classified_but_never_returned_as_soap(status, code):
    response = requests.Response()
    response.status_code = status
    response._content = PRIVATE.encode()
    calls = []
    session = SimpleNamespace(send=lambda _request, **kwargs: calls.append(kwargs) or response)
    endpoint = "http://192.0.2.1:5985/wsman"
    transport.restricted_session(session, endpoint, None, require_encryption=True)
    request = requests.Request(
        "POST",
        endpoint,
        data=b"encrypted-fixture",
        headers={"Content-Type": transport.NTLM_ENCRYPTED_TYPE},
    ).prepare()
    with pytest.raises(transport.TransportFailure) as caught:
        session.send(request, verify=False, proxies={"http": PRIVATE})
    assert caught.value.args == (code,)
    assert session.trust_env is False and session.proxies == {} and session.verify is True
    assert calls == [{"verify": True, "proxies": {}, "allow_redirects": False}]


@pytest.mark.parametrize("status", [200, 202, 204])
def test_plaintext_success_still_cannot_be_used_as_encrypted_evidence(status):
    response = requests.Response()
    response.status_code = status
    response._content = PRIVATE.encode()
    session = SimpleNamespace(send=lambda *_args, **_kwargs: response)
    endpoint = "http://192.0.2.1:5985/wsman"
    transport.restricted_session(session, endpoint, None, require_encryption=True)
    request = requests.Request(
        "POST",
        endpoint,
        data=b"encrypted-fixture",
        headers={"Content-Type": transport.NTLM_ENCRYPTED_TYPE},
    ).prepare()
    with pytest.raises(transport.TransportFailure, match="message_encryption_required"):
        session.send(request)


@pytest.mark.parametrize("code", ["connection_refused", "authentication_failed", PRIVATE])
def test_parent_only_publishes_reviewed_diagnostic_messages(monkeypatch, code):
    class Process:
        returncode = 0
        stdin = SimpleNamespace(close=lambda: None)

        def communicate(self, input=None, timeout=None):
            output.write(json.dumps({"error": code}).encode())

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            return self.returncode

    def launch(_args, **kwargs):
        nonlocal output
        output = kwargs["stdout"]
        return Process()

    output = None
    monkeypatch.setattr(host_inventory.subprocess, "Popen", launch)
    with pytest.raises(host_inventory.CollectionError) as caught:
        host_inventory.collect({"mode": "connection"})
    assert str(caught.value) == host_inventory.ERRORS.get(code, "Inventory transport failed")
    assert PRIVATE not in str(caught.value)
