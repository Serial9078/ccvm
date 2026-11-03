"""Real loopback SSH handshake and isolated collector; no external scan targets."""

import base64
import hashlib
import socket
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import paramiko

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.services import host_inventory  # noqa: E402

PASSWORD = "local-fixture-password-only"
SERVER_KEY = paramiko.RSAKey.generate(2048)
CLIENT_KEY = paramiko.RSAKey.generate(2048)
FINGERPRINT = "SHA256:" + base64.b64encode(
    hashlib.sha256(SERVER_KEY.asbytes()).digest()
).decode().rstrip("=")


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.authentications = []
        self.command = None
        self.ready = threading.Event()

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        self.authentications.append("password")
        return (
            paramiko.AUTH_SUCCESSFUL
            if (username, password) == ("fixture", PASSWORD)
            else paramiko.AUTH_FAILED
        )

    def check_auth_publickey(self, username, key):
        self.authentications.append("key")
        return (
            paramiko.AUTH_SUCCESSFUL
            if username == "fixture" and key == CLIENT_KEY
            else paramiko.AUTH_FAILED
        )

    def check_channel_request(self, kind, channel_id):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_exec_request(self, channel, command):
        self.command = command
        self.ready.set()
        return True


@contextmanager
def server():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(15)
    state = Server()
    errors = []

    def serve():
        transport = None
        try:
            connection, _ = listener.accept()
            transport = paramiko.Transport(connection)
            transport.add_server_key(SERVER_KEY)
            transport.start_server(server=state)
            channel = transport.accept(timeout=15)
            if channel is None:
                return
            if not state.ready.wait(10):
                raise RuntimeError("No fixture command")
            assert state.command in {
                b"python3 -I - inventory",
                b"python3 -I - connection",
            }
            command_source = bytearray()
            while chunk := channel.recv(32768):
                command_source.extend(chunk)
                assert len(command_source) < 32768
            # Execute exactly the production, fixed collector received on stdin,
            # using this CI host's real package database. No arbitrary commands.
            expected = (BACKEND / "app/services/linux_inventory.py").read_bytes()
            assert bytes(command_source) == expected
            mode = state.command.decode().split()[-1]
            result = subprocess.run(
                [sys.executable, "-I", "-", mode],
                input=command_source,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=70,
                check=False,
            )
            channel.sendall(result.stdout)
            channel.send_exit_status(result.returncode)
            channel.close()
        except (EOFError, paramiko.SSHException):
            # Expected when pin validation or authentication deliberately fails.
            pass
        except Exception as error:
            errors.append(error)
        finally:
            if transport:
                transport.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], state
    finally:
        thread.join(timeout=20)
        listener.close()
        assert not thread.is_alive(), "Fixture server did not terminate"
        assert not errors, errors


def payload(port, **changes):
    return {
        "target": "127.0.0.1",
        "port": port,
        "kind": "ssh_password",
        "username": "fixture",
        "mode": "inventory",
        "ssh_fingerprint": FINGERPRINT,
        "secrets": {"password": PASSWORD},
        **changes,
    }


def main():
    import io

    with server() as (port, state):
        result = host_inventory.collect(payload(port))
        normalized = host_inventory.normalize_inventory(result, "ssh_password", "inventory")
        assert normalized["os"]["family"] == "Linux"
        assert normalized["packages"]["status"] == "complete"
        assert normalized["packages"]["items"]
        assert state.authentications == ["password"]
    print(
        "Native SSH: verified pin, password authentication, OS and real installed package inventory"
    )
    with server() as (port, state):
        try:
            host_inventory.collect(payload(port, ssh_fingerprint="SHA256:" + "A" * 43))
            raise AssertionError("Mismatched pin was accepted")
        except host_inventory.CollectionError as error:
            assert "authentication was not attempted" in str(error)
        assert state.authentications == []
    print("Native SSH: mismatched host key rejected before any authentication")
    with server() as (port, state):
        try:
            host_inventory.collect(payload(port, secrets={"password": "wrong-fixture-password"}))
            raise AssertionError("Wrong password was accepted")
        except host_inventory.CollectionError as error:
            assert "rejected authentication" in str(error)
            assert PASSWORD not in str(error)
        assert state.authentications == ["password"]
    private = io.StringIO()
    CLIENT_KEY.write_private_key(private, password="synthetic-key-passphrase")
    with server() as (port, state):
        result = host_inventory.collect(
            payload(
                port,
                kind="ssh_key",
                mode="connection",
                secrets={
                    "private_key": private.getvalue(),
                    "passphrase": "synthetic-key-passphrase",
                },
            )
        )
        host_inventory.normalize_inventory(result, "ssh_key", "connection")
        assert state.authentications == ["key"]
    print("Native SSH: encrypted private key and connection-only mode")


if __name__ == "__main__":
    main()
