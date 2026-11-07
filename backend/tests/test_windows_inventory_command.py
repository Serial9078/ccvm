"""Exact fixed-source transport, command budgets and pre-authentication guards."""

import base64
import gzip
import json
import random
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import host_audit_transport
from app.services import windows_inventory_command as command

SOURCE = Path(command.__file__).with_name("windows_inventory.ps1")


def unpack(arguments):
    assert arguments[:-1] == list(command.OPTIONS)
    bootstrap = base64.b64decode(arguments[-1], validate=True).decode("utf-16-le")
    compressed = re.findall(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", bootstrap)
    assert len(compressed) == 1
    return gzip.decompress(base64.b64decode(compressed[0], validate=True)), bootstrap


@pytest.mark.parametrize("mode", ["connection", "inventory"])
def test_fixed_collector_survives_compression_byte_for_byte_with_launch_headroom(mode):
    executable, arguments = command.build_command(mode)
    source, bootstrap = unpack(arguments)
    assert source == f"$ccvmMode = '{mode}'\n".encode() + SOURCE.read_bytes()
    assert executable == "powershell"
    assert len(" ".join([executable, *arguments])) < command.MAX_COMMAND_CHARACTERS < 8191
    assert "ScriptBlock]::Create($r.ReadToEnd())" in bootstrap
    assert "[Text.UTF8Encoding]::new($false,$true)" in bootstrap
    assert "$r.Dispose();$z.Dispose();$m.Dispose()" in bootstrap
    assert command.build_command(mode) == (executable, arguments)


def test_regression_uncompressed_current_collector_exceeds_cmd_launch_budget():
    source = b"$ccvmMode = 'inventory'\n" + SOURCE.read_bytes()
    encoded = base64.b64encode(source.decode("utf-8").encode("utf-16-le")).decode()
    assert len(" ".join([command.EXECUTABLE, *command.OPTIONS, encoded])) > 8191
    assert len(" ".join([command.EXECUTABLE, *command.build_command("inventory")[1]])) < 8000


@pytest.mark.parametrize("mode", ["connection", "inventory"])
def test_compression_roundtrip_preserves_non_ascii_comments_and_json_strings(mode):
    source = "$value = 'Grüße 東京'; $value | ConvertTo-Json\n".encode()
    executable, arguments = command._fixed_command(source, mode)
    assert executable == "powershell"
    assert unpack(arguments)[0] == f"$ccvmMode = '{mode}'\n".encode() + source


@pytest.mark.parametrize("mode", ["", "inventory;whoami", "Inventory", None, [], 1])
def test_invalid_mode_cannot_reach_remote_authentication(mode, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("An invalid mode must fail before protocol creation")

    monkeypatch.setattr(host_audit_transport, "winrm_protocol", forbidden)
    with pytest.raises(host_audit_transport.TransportFailure, match="invalid_request"):
        host_audit_transport.winrm_collect({"mode": mode})


def test_oversized_or_uncompressible_source_is_rejected_before_remote_authentication(monkeypatch):
    # Random printable ASCII remains valid PowerShell comment text while its
    # compressed encoded launch cannot hide beyond the command budget.
    source = b"#" + base64.b64encode(random.Random(1).randbytes(12000)) + b"\n"
    with pytest.raises(command.CommandLimitError, match="command-line budget"):
        command._fixed_command(source, "inventory")
    with pytest.raises(command.CommandLimitError, match="source exceeds"):
        command._fixed_command(b"#" * (command.MAX_SOURCE_BYTES + 1), "inventory")
    monkeypatch.setattr(Path, "read_bytes", lambda _self: source)
    monkeypatch.setattr(
        host_audit_transport,
        "winrm_protocol",
        lambda *_args: pytest.fail("A command over budget must fail before authentication"),
    )
    with pytest.raises(host_audit_transport.TransportFailure, match="collector_command_limit"):
        host_audit_transport.winrm_collect({"mode": "inventory"})


def test_invalid_utf8_collector_cannot_be_remotely_executed():
    with pytest.raises(UnicodeError):
        command._fixed_command(b"\xff\xfe", "inventory")


def test_builder_cli_emits_only_the_fixed_command_manifest(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [command.__file__, "--mode", "connection"])
    command.main()
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload == dict(
        zip(("executable", "arguments"), command.build_command("connection"), strict=True)
    )
    assert "password" not in captured.out and "token" not in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    "message,expected",
    [
        (b"The command line is too long.", "remote_command_too_long"),
        (b"Die Eingabezeile ist zu lang.", "remote_command_too_long"),
        (b"Die Befehlszeile ist zu lang.", "remote_command_too_long"),
        (b"#< CLIXML <S>ParserError: missing expression</S>", "remote_powershell_parse_failed"),
        (b"System.Management.Automation.ParseException", "remote_powershell_parse_failed"),
        (b"UnauthorizedAccessException", "remote_permission_denied"),
        (b"Access is denied", "remote_permission_denied"),
        (b"Zugriff verweigert", "remote_permission_denied"),
        (b"CommandNotFoundException", "remote_command_unavailable"),
        (b"'powershell' is not recognized", "remote_command_unavailable"),
        (b"Unknown private error", "remote_command_failed"),
        (b"", "remote_command_failed"),
    ],
)
def test_remote_failure_classification_never_returns_remote_account_path_or_secret(
    message, expected
):
    secret = b" private-account synthetic-password C:\\Users\\private-profile"
    for stderr, stdout in ((message + secret, b""), (b"", message + secret)):
        category = host_audit_transport.remote_command_failure(stderr, stdout)
        assert category == expected
        assert "synthetic" not in category and "private" not in category


def test_remote_error_classification_is_bounded_and_handles_utf16_ascii_errors():
    assert (
        host_audit_transport.remote_command_failure(
            "The command line is too long".encode("utf-16-le")
        )
        == "remote_command_too_long"
    )
    assert (
        host_audit_transport.remote_command_failure(b"x" * 32768 + b"The command line is too long")
        == "remote_command_failed"
    )
    assert host_audit_transport.remote_command_failure(None, object()) == "remote_command_failed"


@pytest.mark.parametrize(
    "stderr,category",
    [
        (b"The command line is too long.", "remote_command_too_long"),
        (b"ParserError", "remote_powershell_parse_failed"),
        (b"Access is denied", "remote_permission_denied"),
        (b"Unknown remote failure", "remote_command_failed"),
    ],
)
def test_failed_winrm_command_exposes_only_fixed_category_and_cleans_session(
    monkeypatch, stderr, category
):
    events = []
    protocol = SimpleNamespace(
        transport=object(),
        open_shell=lambda **_kwargs: "shell",
        run_command=lambda *_args, **_kwargs: "command",
        get_command_output=lambda *_args: (
            b"private-account synthetic-secret",
            stderr + b" C:\\Users\\private-account synthetic-secret",
            1,
        ),
        cleanup_command=lambda *_args: events.append("command-cleaned"),
        close_shell=lambda *_args, **_kwargs: events.append("shell-closed"),
    )
    http = SimpleNamespace(close=lambda: events.append("http-closed"))
    monkeypatch.setattr(
        host_audit_transport, "winrm_protocol", lambda _payload: (protocol, "fixed")
    )
    monkeypatch.setattr(host_audit_transport, "winrm_session", lambda *_args: http)
    with pytest.raises(host_audit_transport.TransportFailure) as error:
        host_audit_transport.winrm_collect({"mode": "inventory"})
    assert str(error.value) == category
    assert "private" not in str(error.value) and "secret" not in str(error.value)
    assert events == ["command-cleaned", "shell-closed", "http-closed"]
