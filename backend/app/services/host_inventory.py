"""Inventory validation and hard process lifecycle limits."""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

MAX_OUTPUT = 8 * 1024 * 1024
ERRORS = {
    "host_key_mismatch": (
        "SSH host key does not match the approved fingerprint; authentication was not attempted"
    ),
    "authentication_failed": "The target rejected authentication",
    "tls_verification_failed": "WinRM TLS certificate validation failed",
    "message_encryption_required": "WinRM requires encrypted NTLM messages and responses",
    "invalid_private_key": "SSH private key or passphrase could not be read",
    "collector_command_limit": "The fixed Windows collector exceeds its safe command-line budget",
    "remote_command_too_long": "The Windows remote shell rejected the collector command length",
    "remote_powershell_parse_failed": "PowerShell could not parse the fixed Windows collector",
    "remote_permission_denied": "The Windows collector was denied permission to run",
    "remote_command_unavailable": "The Windows collector requires an available PowerShell command",
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


def _update_text(value, limit=500):
    if (
        not isinstance(value, str)
        or len(value) > limit
        or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
    ):
        raise CollectionError("Invalid Windows update evidence")
    return value


def _update_guid(value):
    try:
        parsed = uuid.UUID(_update_text(value, 36))
    except (ValueError, AttributeError) as error:
        raise CollectionError("Invalid Windows update evidence") from error
    if str(parsed) != value.lower():
        raise CollectionError("Invalid Windows update evidence")
    return str(parsed)


def _update_integer(value, maximum=2147483647):
    if type(value) is not int or not 0 <= value <= maximum:
        raise CollectionError("Invalid Windows update evidence")
    return value


def normalize_windows_updates(data):
    """Only typed configured-source evidence; no raw transport/COM errors."""
    expected = {
        "schema_version": 1,
        "source": "windows-update-agent",
        "mode": "online",
        "server_selection": "default",
        "hidden_updates": "not_assessed",
        "drivers": "not_assessed",
        "superseded": "excluded",
    }
    if not isinstance(data, dict) or any(data.get(key) != value for key, value in expected.items()):
        raise CollectionError("Invalid Windows update evidence")
    if type(data.get("schema_version")) is not int:
        raise CollectionError("Invalid Windows update evidence")
    queried_at = _update_text(data.get("queried_at"), 60)
    try:
        stamp = datetime.fromisoformat(queried_at.replace("Z", "+00:00"))
        if stamp.utcoffset() is None or stamp.utcoffset().total_seconds() != 0:
            raise ValueError("UTC timestamp required")
    except ValueError as error:
        raise CollectionError("Invalid Windows update evidence") from error
    status = data.get("status")
    code = data.get("result_code")
    total = _update_integer(data.get("total"), 100000)
    rows = data.get("items")
    truncated = data.get("truncated")
    reboot = data.get("reboot_required")
    if (
        not isinstance(status, str)
        or status not in {"complete", "partial", "unavailable", "timeout"}
        or not isinstance(rows, list)
        or len(rows) > 200
        or type(truncated) is not bool
        or total < len(rows)
        or truncated != (total > len(rows))
        or (reboot is not None and type(reboot) is not bool)
    ):
        raise CollectionError("Invalid Windows update evidence")
    if status in {"complete", "partial"}:
        if type(code) is not int or code not in {2, 3}:
            raise CollectionError("Invalid Windows update evidence")
        if (status == "complete") != (code == 2 and not truncated):
            raise CollectionError("Invalid Windows update evidence")
    elif code is not None or total or rows or truncated:
        raise CollectionError("Invalid Windows update evidence")
    normalized, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise CollectionError("Invalid Windows update evidence")
        identity = (_update_guid(row.get("update_id")), _update_integer(row.get("revision")))
        if (
            identity in seen
            or row.get("is_installed") is not False
            or row.get("is_hidden") is not False
        ):
            raise CollectionError("Invalid Windows update evidence")
        seen.add(identity)
        kbs, categories = row.get("kbs"), row.get("categories")
        if not isinstance(kbs, list) or len(kbs) > 64 or not isinstance(categories, list):
            raise CollectionError("Invalid Windows update evidence")
        if len(categories) > 100 or any(
            not isinstance(kb, str) or not re.fullmatch(r"KB[0-9]{1,12}", kb) for kb in kbs
        ):
            raise CollectionError("Invalid Windows update evidence")
        normalized_categories = []
        for category in categories:
            if not isinstance(category, dict):
                raise CollectionError("Invalid Windows update evidence")
            normalized_categories.append(
                {
                    "id": _update_guid(category.get("id")),
                    "name": _update_text(category.get("name")),
                    "type": _update_text(category.get("type"), 64),
                }
            )
        severity = row.get("msrc_severity")
        if severity is not None:
            severity = _update_text(severity, 32)
            if severity not in {"Critical", "Important", "Moderate", "Low", ""}:
                raise CollectionError("Invalid Windows update evidence")
        optional = row.get("is_optional")
        mandatory = row.get("is_mandatory")
        if any(value is not None and type(value) is not bool for value in (optional, mandatory)):
            raise CollectionError("Invalid Windows update evidence")
        normalized.append(
            {
                "update_id": identity[0],
                "revision": identity[1],
                "title": _update_text(row.get("title"), 1000),
                "kbs": list(dict.fromkeys(kbs)),
                "categories": normalized_categories,
                "msrc_severity": severity or None,
                "is_installed": False,
                "is_hidden": False,
                "is_optional": optional,
                "is_mandatory": mandatory,
            }
        )
    result = {
        **expected,
        "queried_at": stamp.isoformat().replace("+00:00", "Z"),
        "status": status,
        "result_code": code,
        "total": total,
        "items": normalized,
        "truncated": truncated,
        "reboot_required": reboot,
    }
    if status in {"unavailable", "timeout"}:
        error_code = data.get("error_code")
        if not isinstance(error_code, str) or error_code not in {
            "update_query_failed",
            "invalid_evidence",
            "timeout",
        }:
            raise CollectionError("Invalid Windows update evidence")
        result["error_code"] = error_code
    return result


def _unavailable_windows_updates():
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
        "error_code": "invalid_evidence",
    }


def normalize_inventory(data, kind, mode):
    """Accept bounded typed evidence, never arbitrary remote JSON or error text."""
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise CollectionError("Unsupported inventory format")
    if mode == "windows_updates" and kind != "winrm":
        raise CollectionError("Windows update searches require WinRM")
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
    if family == "Windows":
        # New collectors supply explicit identity fields for product/branch
        # matching. Retained inventories stay valid and are never rewritten.
        for key in (
            "product_type",
            "sku",
            "installation_type",
            "edition_id",
            "display_version",
            "native_architecture",
        ):
            if key in os_data:
                result["os"][key] = text(os_data[key])
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
            item = {key: text(row.get(key)) for key in columns}
            if name == "packages" and section["source"] == "registry-uninstall":
                # These optional registry facts identify the recorded uninstall
                # entry; neither registry view proves a program's architecture.
                # Older evidence stays valid without inventing missing identity.
                for key in ("publisher", "registry_key", "registry_view", "install_scope"):
                    if key in row:
                        item[key] = text(row[key])
                        if any(127 <= ord(character) <= 159 for character in item[key]):
                            raise CollectionError("Invalid inventory text field")
                if "registry_view" in item and item["registry_view"] not in {"native", "wow6432"}:
                    raise CollectionError("Invalid inventory registry view")
                if "install_scope" in item and item["install_scope"] != "machine":
                    raise CollectionError("Invalid inventory install scope")
            normalized.append(item)
        if status in {"unavailable", "not_requested", "not_applicable"} and normalized:
            raise CollectionError("Inventory rows contradict coverage status")
        result[name] = {
            "status": status,
            "source": section["source"],
            "items": normalized,
        }
    if mode == "windows_updates":
        try:
            result["windows_updates"] = normalize_windows_updates(data.get("windows_updates"))
        except CollectionError:
            # A malformed or unavailable update provider never erases the
            # independently collected OS, registry and hotfix snapshot.
            result["windows_updates"] = _unavailable_windows_updates()
    return result
