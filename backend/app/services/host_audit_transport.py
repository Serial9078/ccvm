"""Isolated, bounded transport. Receives secrets on stdin, never argv or files.

This script imports no application configuration or database credentials. Its
parent enforces a wall-clock deadline and discards all raw transport errors.
"""

import base64
import hashlib
import hmac
import io
import json
import logging
import resource
import sys
from pathlib import Path

import paramiko
import requests
import winrm

MAX_OUTPUT = 8 * 1024 * 1024


class TransportFailure(Exception):
    pass


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
        mode = payload["mode"]
        if mode not in {"connection", "inventory"}:
            raise TransportFailure("invalid_request")
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


def restricted_session(session, endpoint, ca_bundle):
    """Block proxy/netrc environment credentials and all redirect destinations."""
    session.trust_env = False
    session.proxies = {}
    session.verify = ca_bundle or True
    original_send = session.send

    def send(request, **kwargs):
        if request.url != endpoint:
            raise TransportFailure("redirect_rejected")
        kwargs.update(allow_redirects=False, verify=ca_bundle or True, proxies={})
        response = original_send(request, **kwargs)
        if response.is_redirect or response.is_permanent_redirect:
            raise TransportFailure("redirect_rejected")
        if len(response.content) > MAX_OUTPUT:
            raise TransportFailure("output_limit")
        return response

    session.send = send
    return session


def winrm_collect(payload):
    target = payload["target"]
    if ":" in target:
        target = f"[{target}]"
    endpoint = f"https://{target}:{payload['port']}/wsman"
    session = winrm.Session(
        endpoint,
        auth=(payload["username"], payload["secrets"]["password"]),
        transport="ntlm",
        server_cert_validation="validate",
        ca_trust_path=payload.get("ca_bundle"),
        proxy=None,
        send_cbt=True,
        operation_timeout_sec=15,
        read_timeout_sec=20,
    )
    transport = session.protocol.transport
    http = restricted_session(transport.build_session(), endpoint, payload.get("ca_bundle"))
    source = Path(__file__).with_name("windows_inventory.ps1").read_text()
    mode = payload["mode"]
    if mode not in {"connection", "inventory"}:
        raise TransportFailure("invalid_request")
    try:
        result = session.run_ps(f"$ccvmMode = '{mode}'\n" + source)
        if result.status_code != 0:
            raise TransportFailure("remote_command_failed")
        if len(result.std_out) > MAX_OUTPUT:
            raise TransportFailure("output_limit")
        return json.loads(result.std_out.decode("utf-8-sig"))
    finally:
        http.close()


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
        data = winrm_collect(payload) if payload["kind"] == "winrm" else ssh_collect(payload)
        output = json.dumps({"inventory": data}, ensure_ascii=True).encode()
        if len(output) > MAX_OUTPUT:
            raise TransportFailure("output_limit")
        sys.stdout.buffer.write(output)
    except TransportFailure as error:
        print(json.dumps({"error": str(error)}))
    except paramiko.AuthenticationException:
        print('{"error":"authentication_failed"}')
    except requests.exceptions.SSLError:
        print('{"error":"tls_verification_failed"}')
    except Exception:
        # Never serialize exceptions, stdout/stderr, requests, or payloads.
        print('{"error":"connection_or_collection_failed"}')


if __name__ == "__main__":
    main()
