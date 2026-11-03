"""Inventory validation and hard process lifecycle limits."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_OUTPUT = 8 * 1024 * 1024
ERRORS = {
    "host_key_mismatch": (
        "SSH host key does not match the approved fingerprint; authentication was not attempted"
    ),
    "authentication_failed": "The target rejected authentication",
    "tls_verification_failed": "WinRM TLS certificate validation failed",
    "invalid_private_key": "SSH private key or passphrase could not be read",
    "remote_command_failed": (
        "The fixed inventory command failed; verify Python 3 / PowerShell and account permissions"
    ),
    "connection_or_collection_failed": (
        "Connection or collection failed; verify reachability, TLS/SSH settings and permissions"
    ),
    "output_limit": "Inventory exceeded the output limit",
    "redirect_rejected": "WinRM redirect was rejected",
}


class CollectionError(Exception):
    pass


class CollectionCancelled(CollectionError):
    pass


def collect(payload, cancelled=lambda: False):
    timeout = 45 if payload["mode"] == "connection" else 180
    script = Path(__file__).with_name("host_audit_transport.py")
    # No inherited DB passwords, vault keys, tokens, agents, proxies, netrc, or
    # Python search-path settings in the transport process.
    environment = {"PATH": os.defpath, "LANG": "C.UTF-8"}
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(
            [sys.executable, "-I", str(script)],
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=subprocess.DEVNULL,
            env=environment,
            cwd="/",
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout
        try:
            # communicate() retains input across TimeoutExpired retries. Secrets
            # pass through a pipe only; no file or command-line interpolation.
            pending = json.dumps(payload).encode()
            while True:
                if cancelled():
                    raise CollectionCancelled("Host audit cancelled or credential revoked")
                if time.monotonic() >= deadline:
                    raise CollectionError(f"Host audit exceeded its {timeout}s hard deadline")
                if os.fstat(output.fileno()).st_size > MAX_OUTPUT:
                    raise CollectionError(ERRORS["output_limit"])
                try:
                    process.communicate(input=pending, timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    pending = None
            if process.returncode != 0:
                raise CollectionError("Inventory transport stopped without a valid result")
            output.seek(0)
            data = output.read(MAX_OUTPUT + 1)
            if len(data) > MAX_OUTPUT:
                raise CollectionError(ERRORS["output_limit"])
            try:
                result = json.loads(data)
            except (ValueError, UnicodeDecodeError) as error:
                raise CollectionError("Inventory transport returned an invalid result") from error
            if not isinstance(result, dict):
                raise CollectionError("Inventory transport returned an invalid result")
            if "error" in result:
                raise CollectionError(ERRORS.get(result["error"], "Inventory transport failed"))
            return result.get("inventory")
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=5)
            if process.stdin:
                process.stdin.close()


def text(value):
    if not isinstance(value, str) or len(value) > 500 or any(ord(c) < 32 for c in value):
        raise CollectionError("Invalid inventory text field")
    return value


def normalize_inventory(data, kind, mode):
    """Accept bounded typed evidence, never arbitrary remote JSON or error text."""
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise CollectionError("Unsupported inventory format")
    os_data = data.get("os")
    family = "Windows" if kind == "winrm" else "Linux"
    if not isinstance(os_data, dict) or os_data.get("family") != family:
        raise CollectionError("Unexpected operating system in inventory")
    result = {
        "schema_version": 1,
        "os": {
            key: text(os_data.get(key))
            for key in (
                "family",
                "name",
                "version",
                "kernel",
                "architecture",
                "hostname",
            )
        },
    }
    for name, columns, sources in (
        (
            "packages",
            ("name", "version", "architecture"),
            {"dpkg", "rpm", "registry-uninstall", "none"},
        ),
        ("hotfixes", ("id", "description"), {"Get-HotFix", "none"}),
    ):
        section = data.get(name)
        if not isinstance(section, dict) or section.get("source") not in sources:
            raise CollectionError("Invalid inventory section")
        status = section.get("status")
        expected = {"complete", "unavailable", "truncated"}
        if mode == "connection":
            expected = {"not_requested"}
        if name == "hotfixes" and family == "Linux":
            expected = {"not_applicable"}
        if status not in expected:
            raise CollectionError("Invalid inventory coverage status")
        rows = section.get("items")
        if not isinstance(rows, list) or len(rows) > 10000:
            raise CollectionError("Invalid inventory row count")
        normalized = []
        for row in rows:
            if not isinstance(row, dict):
                raise CollectionError("Invalid inventory row")
            normalized.append({key: text(row.get(key)) for key in columns})
        if status in {"unavailable", "not_requested", "not_applicable"} and normalized:
            raise CollectionError("Inventory rows contradict coverage status")
        result[name] = {
            "status": status,
            "source": section["source"],
            "items": normalized,
        }
    return result
