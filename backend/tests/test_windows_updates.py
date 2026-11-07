"""Configured-source update searches never alter the ordinary inventory path."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import host_audit_transport as transport
from app.services import host_inventory
from app.services import windows_inventory_command as command


def evidence():
    return {
        "schema_version": 1,
        "source": "windows-update-agent",
        "mode": "online",
        "server_selection": "default",
        "queried_at": "2026-11-07T12:00:00Z",
        "status": "complete",
        "result_code": 2,
        "total": 1,
        "truncated": False,
        "items": [
            {
                "update_id": "11111111-1111-4111-8111-111111111111",
                "revision": 201,
                "title": "Fixture security update",
                "kbs": ["KB1234567"],
                "categories": [
                    {
                        "id": "0fa1201d-4330-4fa8-8ae9-b877473b6441",
                        "name": "Localized label must not classify an update",
                        "type": "UpdateClassification",
                    }
                ],
                "msrc_severity": "Important",
                "is_hidden": False,
                "is_installed": False,
                "is_optional": False,
                "is_mandatory": False,
            }
        ],
        "hidden_updates": "not_assessed",
        "drivers": "not_assessed",
        "superseded": "excluded",
        "reboot_required": None,
    }


def inventory():
    return {
        "schema_version": 1,
        "os": {
            name: "Windows" if name == "family" else "fixture"
            for name in ("family", "name", "version", "kernel", "architecture", "hostname")
        },
        "packages": {"status": "complete", "source": "registry-uninstall", "items": []},
        "hotfixes": {"status": "complete", "source": "Get-HotFix", "items": []},
    }


def test_typed_update_evidence_retains_ids_and_bounds_and_drops_unknown_remote_fields():
    data = evidence()
    data["private_remote_error"] = "private-account synthetic-password"
    data["items"][0]["private_remote_error"] = "synthetic-secret"
    result = host_inventory.normalize_windows_updates(data)
    assert result == evidence()
    assert "synthetic" not in json.dumps(result)
    data["items"][0]["is_optional"] = None
    assert host_inventory.normalize_windows_updates(data)["items"][0]["is_optional"] is None


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"status": "complete", "result_code": 3},
        {"status": "complete", "total": 2, "truncated": True},
        {"status": "partial", "result_code": 2},
        {"result_code": True},
        {"queried_at": "2026-11-07T12:00:00"},
        {"queried_at": "private-account synthetic-secret"},
        {"mode": "cached"},
        {"server_selection": "windows_update"},
        {"hidden_updates": "complete"},
        {"drivers": "complete"},
        {"superseded": "included"},
        {"total": True},
        {"reboot_required": "false"},
    ],
)
def test_contradictory_or_untrusted_update_scope_cannot_be_complete(change):
    data = {**evidence(), **change}
    with pytest.raises(host_inventory.CollectionError):
        host_inventory.normalize_windows_updates(data)


@pytest.mark.parametrize(
    "change",
    [
        {"is_installed": True},
        {"is_hidden": True},
        {"is_hidden": 0},
        {"is_optional": "false"},
        {"is_mandatory": 1},
        {"revision": True},
        {"update_id": "not-a-guid"},
        {"kbs": ["https://private.example/"]},
        {"title": "x" * 1001},
        {"title": "private\nexception"},
        {"msrc_severity": "Not vulnerable"},
        {"categories": [{"id": "invalid"}]},
    ],
)
def test_contradictory_or_unbounded_update_items_are_rejected(change):
    data = evidence()
    data["items"][0].update(change)
    with pytest.raises(host_inventory.CollectionError):
        host_inventory.normalize_windows_updates(data)


def test_partial_results_and_empty_success_are_scoped_without_inventing_missing_rows():
    partial = evidence()
    partial.update(status="partial", result_code=3)
    assert host_inventory.normalize_windows_updates(partial)["status"] == "partial"
    partial.update(result_code=2, total=3, truncated=True)
    assert host_inventory.normalize_windows_updates(partial)["truncated"] is True
    empty = evidence()
    empty.update(total=0, items=[])
    assert host_inventory.normalize_windows_updates(empty)["items"] == []
    assert host_inventory.normalize_windows_updates(empty)["hidden_updates"] == "not_assessed"


def test_bad_update_evidence_preserves_independent_inventory_and_never_leaks_errors():
    base = inventory()
    assert host_inventory.normalize_inventory(base, "winrm", "inventory") == base
    for value in (
        None,
        {},
        {"error": "private-account synthetic-secret"},
        {**evidence(), "status": []},
        {**transport.unavailable_windows_updates("update_query_failed"), "error_code": []},
    ):
        data = {**base, "windows_updates": value}
        normalized = host_inventory.normalize_inventory(data, "winrm", "windows_updates")
        section = normalized.pop("windows_updates")
        assert normalized == base
        assert section["status"] == "unavailable" and section["error_code"] == "invalid_evidence"
        assert "private" not in json.dumps(section) and "synthetic" not in json.dumps(section)
    with pytest.raises(host_inventory.CollectionError, match="require WinRM"):
        host_inventory.normalize_inventory(base, "ssh_password", "windows_updates")


def test_item_cap_and_duplicate_identity_are_enforced():
    data = evidence()
    data.update(items=[copy.deepcopy(data["items"][0])] * 201, total=201)
    with pytest.raises(host_inventory.CollectionError):
        host_inventory.normalize_windows_updates(data)
    data.update(items=data["items"][:2], total=2)
    with pytest.raises(host_inventory.CollectionError):
        host_inventory.normalize_windows_updates(data)


@pytest.mark.parametrize("failure", [False, True])
def test_update_search_uses_same_session_after_inventory_and_retains_snapshot_on_failure(
    monkeypatch, failure
):
    events = []
    outputs = [json.dumps(inventory()).encode(), json.dumps(evidence()).encode()]

    def run(shell, executable, arguments, **kwargs):
        events.append("run")
        assert shell == "shell" and executable == "powershell" and kwargs["skip_cmd_shell"]
        assert len(" ".join([executable, *arguments])) < 8000
        return str(len(events))

    def output(*_args):
        if len(outputs) == 1 and failure:
            return b"private-account synthetic-secret", b"private-account synthetic-password", 1
        return outputs.pop(0), b"", 0

    protocol = SimpleNamespace(
        transport=object(),
        open_shell=lambda **_kwargs: "shell",
        run_command=run,
        get_command_output=output,
        cleanup_command=lambda *_args: events.append("clean"),
        close_shell=lambda *_args, **_kwargs: events.append("close"),
    )
    monkeypatch.setattr(transport, "winrm_protocol", lambda _payload: (protocol, "fixed"))
    monkeypatch.setattr(
        transport,
        "winrm_session",
        lambda *_args: SimpleNamespace(close=lambda: events.append("http-close")),
    )
    result = transport.winrm_collect({"mode": "windows_updates"})
    update = result.pop("windows_updates")
    assert result == inventory()
    assert events == ["run", "clean", "run", "clean", "close", "http-close"]
    if failure:
        assert update["status"] == "unavailable"
        assert "private" not in json.dumps(update) and "synthetic" not in json.dumps(update)
    else:
        assert update == evidence()


def test_both_commands_are_bounded_before_any_authentication(monkeypatch):
    original = command.build_command
    seen = []

    def build(mode):
        seen.append(mode)
        if mode == "windows_updates":
            raise transport.TransportFailure("collector_command_limit")
        return original(mode)

    monkeypatch.setattr(transport, "windows_inventory_command", build)
    monkeypatch.setattr(transport, "winrm_protocol", lambda *_args: pytest.fail("pre-auth only"))
    with pytest.raises(transport.TransportFailure, match="collector_command_limit"):
        transport.winrm_collect({"mode": "windows_updates"})
    assert seen == ["inventory", "windows_updates"]
    with pytest.raises(transport.TransportFailure, match="invalid_request"):
        transport.ssh_collect({"mode": "windows_updates"})


@pytest.mark.parametrize("fault", ["query_and_close", "cleanup", "http_close"])
def test_update_transport_cleanup_faults_do_not_erase_collected_inventory(monkeypatch, fault):
    outputs = [json.dumps(inventory()).encode(), json.dumps(evidence()).encode()]

    def broken(*_args, **_kwargs):
        raise RuntimeError("private-account synthetic-secret")

    def output(*_args):
        if fault == "query_and_close" and len(outputs) == 1:
            return broken()
        return outputs.pop(0), b"", 0

    protocol = SimpleNamespace(
        transport=object(),
        open_shell=lambda **_kwargs: "shell",
        run_command=lambda *_args, **_kwargs: "command",
        get_command_output=output,
        cleanup_command=broken if fault == "cleanup" else lambda *_args: None,
        close_shell=broken if fault == "query_and_close" else lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(transport, "winrm_protocol", lambda _payload: (protocol, "fixed"))
    monkeypatch.setattr(
        transport,
        "winrm_session",
        lambda *_args: SimpleNamespace(close=broken if fault == "http_close" else lambda: None),
    )
    result = transport.winrm_collect({"mode": "windows_updates"})
    updates = result.pop("windows_updates")
    assert result == inventory()
    assert updates["status"] == ("unavailable" if fault == "query_and_close" else "complete")
    assert "private" not in json.dumps(updates) and "synthetic" not in json.dumps(updates)


def test_slow_base_inventory_skips_second_query_within_existing_global_budget(monkeypatch):
    events = []
    times = iter((100.0, 191.0))
    monkeypatch.setattr(transport, "monotonic", lambda: next(times))
    protocol = SimpleNamespace(
        transport=object(),
        open_shell=lambda **_kwargs: "shell",
        run_command=lambda *_args, **_kwargs: events.append("command") or "command",
        get_command_output=lambda *_args: (json.dumps(inventory()).encode(), b"", 0),
        cleanup_command=lambda *_args: events.append("cleanup"),
        close_shell=lambda *_args, **_kwargs: events.append("close"),
    )
    monkeypatch.setattr(transport, "winrm_protocol", lambda _payload: (protocol, "fixed"))
    monkeypatch.setattr(
        transport,
        "winrm_session",
        lambda *_args: SimpleNamespace(close=lambda: events.append("http-close")),
    )
    result = transport.winrm_collect({"mode": "windows_updates"})
    updates = result.pop("windows_updates")
    assert result == inventory()
    assert updates["status"] == "unavailable" and updates["error_code"] == "timeout"
    assert events == ["command", "cleanup", "close", "http-close"]
    assert host_inventory.normalize_windows_updates(updates) == updates


def test_update_collector_launch_is_separate_and_no_mutation_api_is_used():
    executable, arguments = command.build_command("windows_updates")
    assert len(" ".join([executable, *arguments])) < 8000
    source = Path(command.__file__).with_name("windows_update_inventory.ps1").read_text()
    for prohibited in (
        ".CreateUpdateDownloader(",
        ".CreateUpdateInstaller(",
        ".AcceptEula(",
        ".AddService(",
        "Set-ItemProperty",
        "Start-Service",
        "Set-Service",
    ):
        assert prohibited not in source
    assert "$searcher.ServerSelection = 0" in source
    assert "$searcher.Online = $online" in source
    assert "$searcher.CanAutomaticallyUpgradeService = $false" in source
    assert "-ArgumentList $true" in source
    assert "Wait-Job -Job $job -Timeout 60" in source
    assert "Stop-Job -Job $job" in source and "Remove-Job -Job $job" in source
