"""Exercise the real HTTP/NTLM handshake against bounded loopback fixtures."""

import base64
import io
import json
import socket
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
import requests
import spnego
from requests_ntlm.requests_ntlm import ShimSessionSecurity
from winrm.encryption import Encryption
from winrm.exceptions import InvalidCredentialsError, WinRMError

from app.services import host_audit_transport as transport

ORIGINAL_CONNECT = socket.socket.connect
PASSWORD = "synthetic-loopback-inventory-password"


def payload(**changes):
    return {
        "target": "192.0.2.1",
        "port": 5985,
        "username": "EXAMPLE\\inventory",
        "secrets": {"password": PASSWORD},
        "winrm_transport": "http_ntlm",
        "ca_bundle": "/untrusted/environment/ca.pem",
        **changes,
    }


@pytest.fixture
def loopback_only(monkeypatch):
    def connect(sock, address):
        assert address[0] == "127.0.0.1", "Fixture attempted non-loopback network access"
        return ORIGINAL_CONNECT(sock, address)

    # The suite forbids external I/O. This fixture permits only its local peer.
    monkeypatch.setattr(socket.socket, "connect", connect)


@contextmanager
def http_peer(callback):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.server.observed.append((self.path, dict(self.headers), body))
            try:
                status, headers, data = callback(self, body)
            except Exception as error:
                self.server.errors.append(error)
                status, headers, data = 500, {}, b"fixture failed"
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.observed = []
    server.errors = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not server.errors, server.errors


@pytest.mark.parametrize("target", ["192.0.2.1", "2001:db8::1"])
@pytest.mark.parametrize("mode", ["https", "http_ntlm"])
def test_real_protocol_explicit_mode_preserves_ip_and_required_protection(target, mode):
    protocol, endpoint = transport.winrm_protocol(payload(target=target, winrm_transport=mode))
    expected = f"[{target}]" if ":" in target else target
    scheme = "https" if mode == "https" else "http"
    assert endpoint == protocol.transport.endpoint == f"{scheme}://{expected}:5985/wsman"
    assert protocol.transport.auth_method == "ntlm"
    assert protocol.transport.server_cert_validation == "validate"
    assert protocol.transport.send_cbt is True
    assert protocol.transport.message_encryption == ("always" if mode == "http_ntlm" else "auto")
    assert protocol.transport.ca_trust_path == (
        None if mode == "http_ntlm" else "/untrusted/environment/ca.pem"
    )


def test_missing_mode_still_constructs_verified_https():
    data = payload(port=5986)
    del data["winrm_transport"]
    protocol, endpoint = transport.winrm_protocol(data)
    assert endpoint == "https://192.0.2.1:5986/wsman"
    assert protocol.transport.server_cert_validation == "validate"
    assert protocol.transport.message_encryption == "auto"


@pytest.mark.parametrize("mode", [None, "http", "basic", "plaintext", "ignore", ""])
def test_unknown_transport_rejected_before_protocol_creation(monkeypatch, mode):
    monkeypatch.setattr(transport, "Protocol", lambda **_kw: pytest.fail("Protocol created"))
    with pytest.raises(transport.TransportFailure, match="invalid_request"):
        transport.winrm_protocol(payload(winrm_transport=mode))


def test_http_first_probe_rejects_redirect_and_ignores_proxy_and_netrc(
    loopback_only, monkeypatch, tmp_path
):
    with http_peer(lambda *_args: (200, {}, b"trap")) as trap:
        trap_url = f"http://127.0.0.1:{trap.server_port}/stolen"
        monkeypatch.setenv("HTTP_PROXY", trap_url)
        monkeypatch.setenv("ALL_PROXY", trap_url)
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/missing/environment/ca.pem")
        netrc = tmp_path / "synthetic.netrc"
        netrc.write_text("machine 127.0.0.1 login netrc-user password netrc-password\n")
        monkeypatch.setenv("NETRC", str(netrc))
        with http_peer(lambda *_args: (307, {"Location": trap_url}, b"")) as peer:
            protocol, endpoint = transport.winrm_protocol(
                payload(target="127.0.0.1", port=peer.server_port)
            )
            with pytest.raises(transport.TransportFailure, match="redirect_rejected"):
                transport.winrm_session(protocol.transport, endpoint, payload()["ca_bundle"])
            session = protocol.transport.session
            assert session.trust_env is False and session.proxies == {}
            assert session.verify is True
            assert len(peer.observed) == 1
            path, headers, body = peer.observed[0]
            assert path == "/wsman" and body == b""
            assert "Authorization" not in headers
        assert trap.observed == []


@pytest.mark.parametrize("response_mode", ["encrypted", "plaintext", "tampered"])
def test_real_ntlm_seals_http_messages_and_rejects_unprotected_or_tampered_responses(
    loopback_only, monkeypatch, tmp_path, response_mode
):
    users = tmp_path / "synthetic-ntlm-users"
    users.write_text(f"EXAMPLE:inventory:{PASSWORD}\n")
    monkeypatch.setenv("NTLM_USER_FILE", str(users))
    request_data = b"<Envelope>synthetic inventory request</Envelope>"
    response_data = b"<Envelope>synthetic inventory evidence</Envelope>"
    decrypted = []

    def handle(handler, body):
        authorization = handler.headers.get("Authorization")
        if not body:
            if not authorization:
                return 401, {"WWW-Authenticate": "NTLM"}, b""
            if not hasattr(handler, "context"):
                handler.context = spnego.server(protocol="ntlm")
            token = base64.b64decode(authorization.split(" ", 1)[1])
            challenge = handler.context.step(token)
            if not handler.context.complete:
                return (
                    401,
                    {"WWW-Authenticate": "NTLM " + base64.b64encode(challenge).decode()},
                    b"",
                )
            handler.codec = Encryption(
                SimpleNamespace(
                    auth=SimpleNamespace(session_security=ShimSessionSecurity(handler.context))
                ),
                "ntlm",
            )
            return 200, {}, b""
        received = requests.Response()
        received._content = body
        received.headers["Content-Type"] = handler.headers["Content-Type"]
        endpoint = f"http://127.0.0.1:{handler.server.server_port}/wsman"
        received.request = requests.Request("POST", endpoint).prepare()
        decrypted.append(handler.codec.parse_encrypted_response(received))
        if response_mode == "plaintext":
            return 200, {"Content-Type": "application/soap+xml"}, response_data
        with requests.Session() as encoder:
            encrypted = handler.codec.prepare_encrypted_request(encoder, endpoint, response_data)
        data = encrypted.body
        if response_mode == "tampered":
            data = bytearray(data)
            data[-30] ^= 1
            data = bytes(data)
        return 200, {"Content-Type": encrypted.headers["Content-Type"]}, data

    with http_peer(handle) as peer:
        protocol, endpoint = transport.winrm_protocol(
            payload(target="127.0.0.1", port=peer.server_port)
        )
        session = transport.winrm_session(protocol.transport, endpoint, None)
        try:
            if response_mode == "encrypted":
                assert protocol.transport.send_message(request_data) == response_data
            elif response_mode == "plaintext":
                with pytest.raises(transport.TransportFailure, match="message_encryption_required"):
                    protocol.transport.send_message(request_data)
            else:
                with pytest.raises(spnego.exceptions.BadMICError):
                    protocol.transport.send_message(request_data)
            assert decrypted == [request_data]
            wire = b"".join(body for _, _, body in peer.observed)
            assert request_data not in wire and PASSWORD.encode() not in wire
            assert "multipart/encrypted" in peer.observed[-1][1]["Content-Type"]
            assert session.trust_env is False and session.proxies == {}
        finally:
            session.close()


def test_http_refuses_unencrypted_outgoing_soap_before_send():
    session = SimpleNamespace(send=lambda *_a, **_kw: pytest.fail("Unencrypted SOAP sent"))
    endpoint = "http://192.0.2.1:5985/wsman"
    transport.restricted_session(session, endpoint, None, require_encryption=True)
    request = requests.Request(
        "POST",
        endpoint,
        data=b"<Envelope>plaintext</Envelope>",
        headers={"Content-Type": "text/xml"},
    ).prepare()
    with pytest.raises(transport.TransportFailure, match="message_encryption_required"):
        session.send(request)


def test_http_does_not_fall_back_when_encryption_is_unavailable(monkeypatch):
    monkeypatch.setattr("winrm.transport.HAVE_NTLM", False)
    protocol, endpoint = transport.winrm_protocol(payload())
    with pytest.raises(WinRMError, match="ntlm"):
        transport.winrm_session(protocol.transport, endpoint, None)


def test_rejected_http_credentials_are_classified_without_returning_exception_details(
    monkeypatch, capsys
):
    def rejected(_payload):
        raise InvalidCredentialsError(f"synthetic upstream exception contains {PASSWORD}")

    monkeypatch.setattr(transport, "winrm_collect", rejected)
    monkeypatch.setattr(transport.resource, "setrlimit", lambda *_args: None)
    monkeypatch.setattr(transport.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(transport.signal, "alarm", lambda *_args: None)
    monkeypatch.setattr(transport.logging, "disable", lambda *_args: None)
    monkeypatch.setattr(
        transport.sys,
        "stdin",
        SimpleNamespace(
            buffer=io.BytesIO(json.dumps(payload(kind="winrm", mode="connection")).encode())
        ),
    )
    transport.main()
    output = capsys.readouterr()
    assert json.loads(output.out) == {"error": "authentication_failed"}
    assert PASSWORD not in output.out + output.err
    assert "upstream" not in output.out + output.err
