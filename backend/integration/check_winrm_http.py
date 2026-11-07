"""Real loopback NTLM sealing with a synthetic WSMan peer, not a Windows host.

The production isolated collector negotiates NTLM and encrypts every SOAP
request/response. The peer checks the fixed command but returns fixture evidence;
native Windows collector coverage is provided by check_windows_inventory.ps1.
"""

import base64
import gzip
import json
import os
import re
import struct
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import spnego

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.services import host_inventory  # noqa: E402

PASSWORD = "loopback-synthetic-password-only"
BOUNDARY = b"--Encrypted Boundary"
TYPE = 'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";'
TYPE += 'boundary="Encrypted Boundary"'
NS = {
    "env": "http://www.w3.org/2003/05/soap-envelope",
    "a": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "rsp": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
    "w": "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
}
EVIDENCE = {
    "schema_version": 1,
    "os": {
        "family": "Windows",
        "name": "Synthetic Windows protocol fixture",
        "version": "10.0",
        "kernel": "1.0",
        "architecture": "64-bit",
        "hostname": "LOOPBACK-FIXTURE",
    },
    "packages": {"status": "not_requested", "source": "registry-uninstall", "items": []},
    "hotfixes": {"status": "not_requested", "source": "Get-HotFix", "items": []},
}
UPDATE_EVIDENCE = {
    "schema_version": 1,
    "source": "windows-update-agent",
    "mode": "online",
    "server_selection": "default",
    "queried_at": "2026-11-07T12:00:00Z",
    "status": "complete",
    "result_code": 2,
    "total": 0,
    "items": [],
    "truncated": False,
    "hidden_updates": "not_assessed",
    "drivers": "not_assessed",
    "superseded": "excluded",
    "reboot_required": None,
}


def unwrap(context, data):
    assert data.startswith(BOUNDARY + b"\r\n")
    assert data.endswith(BOUNDARY + b"--\r\n")
    header, payload = data.split(b"\tContent-Type: application/octet-stream\r\n", 1)
    payload = payload[: -(len(BOUNDARY) + 4)]
    length = struct.unpack("<i", payload[:4])[0]
    assert length == 16
    signature, encrypted = payload[4 : 4 + length], payload[4 + length :]
    unsealed = context.unwrap(signature + encrypted)
    assert unsealed.encrypted
    plaintext = unsealed.data
    assert len(plaintext) == int(re.search(rb"Length=(\d+)\r\n", header).group(1))
    assert plaintext not in data
    return plaintext


def wrap(context, data):
    sealed = context.wrap(data, encrypt=True)
    assert sealed.encrypted
    result = (
        BOUNDARY
        + b"\r\n\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n"
        + b"\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length="
        + str(len(data)).encode()
        + b"\r\n"
        + BOUNDARY
        + b"\r\n\tContent-Type: application/octet-stream\r\n"
        + struct.pack("<i", 16)
        + sealed.data
        + BOUNDARY
        + b"--\r\n"
    )
    assert data not in result
    return result


def soap_reply(plaintext, actions, mode):
    request = ET.fromstring(plaintext)
    action = request.find("env:Header/a:Action", NS).text.rsplit("/", 1)[1]
    actions.append(action)
    reply = ET.Element(f"{{{NS['env']}}}Envelope")
    header = ET.SubElement(reply, f"{{{NS['env']}}}Header")
    ET.SubElement(header, f"{{{NS['a']}}}RelatesTo").text = request.find(
        "env:Header/a:MessageID", NS
    ).text
    body = ET.SubElement(reply, f"{{{NS['env']}}}Body")
    if action == "Create":
        ET.SubElement(body, f"{{{NS['w']}}}Selector", Name="ShellId").text = "fixture-shell"
    elif action == "Command":
        assert request.find("env:Body/rsp:CommandLine/rsp:Command", NS).text == "powershell"
        arguments = request.find("env:Body/rsp:CommandLine/rsp:Arguments", NS).text.split()
        assert arguments[:-1] == ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"]
        bootstrap = base64.b64decode(arguments[-1], validate=True).decode("utf-16-le")
        compressed = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", bootstrap)
        assert compressed is not None
        command = gzip.decompress(base64.b64decode(compressed[1], validate=True)).decode("utf-8")
        update_command = mode == "windows_updates" and actions.count("Command") == 2
        source_mode = (
            "windows_updates"
            if update_command
            else ("inventory" if mode == "windows_updates" else "connection")
        )
        filename = "windows_update_inventory.ps1" if update_command else "windows_inventory.ps1"
        source = (BACKEND / "app/services" / filename).read_text()
        assert command == f"$ccvmMode = '{source_mode}'\n" + source
        assert len(" ".join(["powershell", *arguments])) < 8000
        assert request.find(".//w:Option[@Name='WINRS_SKIP_CMD_SHELL']", NS).text == "TRUE"
        ET.SubElement(body, f"{{{NS['rsp']}}}CommandId").text = (
            f"fixture-{actions.count('Command')}"
        )
    elif action == "Receive":
        evidence = EVIDENCE
        if mode == "windows_updates":
            if actions.count("Command") == 2:
                evidence = UPDATE_EVIDENCE
            else:
                evidence = {
                    **EVIDENCE,
                    "packages": {**EVIDENCE["packages"], "status": "complete"},
                    "hotfixes": {**EVIDENCE["hotfixes"], "status": "complete"},
                }
        ET.SubElement(body, f"{{{NS['rsp']}}}Stream", Name="stdout").text = base64.b64encode(
            json.dumps(evidence).encode()
        ).decode()
        state = ET.SubElement(
            body,
            f"{{{NS['rsp']}}}CommandState",
            State=f"{NS['rsp']}/CommandState/Done",
        )
        ET.SubElement(state, f"{{{NS['rsp']}}}ExitCode").text = "0"
    else:
        assert action in {"Signal", "Delete"}
    return ET.tostring(reply)


class Peer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.context = None

    def log_message(self, *args):
        pass

    def respond(self, code, body=b"", **headers):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", TYPE if body else "application/soap+xml")
        for key, value in headers.items():
            self.send_header(key.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            self.handle_post()
        except Exception as error:
            self.server.errors.append(error)
            self.respond(500)

    def handle_post(self):
        assert self.path == "/wsman"
        data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if not self.context or not self.context.complete:
            # Only pywinrm's empty authentication probe is allowed in plaintext.
            assert not data
            authorization = self.headers.get("Authorization")
            if not authorization:
                self.respond(401, WWW_Authenticate="NTLM")
                return
            assert authorization.startswith("NTLM ")
            if self.context is None:
                self.context = spnego.server(
                    protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm
                )
            token = self.context.step(base64.b64decode(authorization[5:], validate=True))
            if token:
                self.respond(401, WWW_Authenticate="NTLM " + base64.b64encode(token).decode())
            else:
                assert self.context.complete
                self.server.authenticated += 1
                self.respond(200)
            return
        assert self.headers["Content-Type"] == TYPE
        plaintext = unwrap(self.context, data)
        response = soap_reply(plaintext, self.server.actions, self.server.mode)
        self.respond(200, wrap(self.context, response))
        self.server.encrypted_messages += 1


def main():
    # The server credential file exists only in this parent process environment;
    # the production transport subprocess deliberately inherits none of it.
    previous = os.environ.get("NTLM_USER_FILE")
    with tempfile.TemporaryDirectory(prefix="ccvm-ntlm-loopback-") as directory:
        credentials = Path(directory) / "credentials"
        credentials.write_text(f"FIXTURE:inventory:{PASSWORD}\n")
        credentials.chmod(0o600)
        os.environ["NTLM_USER_FILE"] = str(credentials)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for mode in ("connection", "windows_updates"):
                server.mode = mode
                server.errors, server.actions = [], []
                server.authenticated, server.encrypted_messages = 0, 0
                result = host_inventory.collect(
                    {
                        "target": "127.0.0.1",
                        "port": server.server_address[1],
                        "kind": "winrm",
                        "winrm_transport": "http_ntlm",
                        "mode": mode,
                        "username": "FIXTURE\\inventory",
                        "secrets": {"password": PASSWORD},
                        "ca_bundle": None,
                    }
                )
                if mode == "windows_updates":
                    assert result.pop("windows_updates") == UPDATE_EVIDENCE
                    assert result["os"] == EVIDENCE["os"]
                    assert result["packages"]["status"] == "complete"
                    assert server.actions == [
                        "Create",
                        "Command",
                        "Receive",
                        "Signal",
                        "Command",
                        "Receive",
                        "Signal",
                        "Delete",
                    ]
                    assert server.encrypted_messages == 8
                    host_inventory.normalize_inventory(
                        {**result, "windows_updates": UPDATE_EVIDENCE}, "winrm", mode
                    )
                else:
                    assert result == EVIDENCE
                    assert server.actions == ["Create", "Command", "Receive", "Signal", "Delete"]
                    assert server.encrypted_messages == 5
                assert server.authenticated == 1
                assert not server.errors, server.errors
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            if previous is None:
                os.environ.pop("NTLM_USER_FILE", None)
            else:
                os.environ["NTLM_USER_FILE"] = previous
        print("VERIFIED: real NTLM handshake and sealed one/two-command WSMan sessions on loopback")
        print(
            "Verified exact fixed collectors; evidence is synthetic and no host search was executed"
        )


if __name__ == "__main__":
    main()
