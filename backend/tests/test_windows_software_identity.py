"""Bound registry identity facts without rewriting retained schema-one evidence."""

import copy

import pytest

from app.services.host_inventory import CollectionError, normalize_inventory


def evidence():
    return {
        "schema_version": 1,
        "os": {
            "family": "Windows",
            "name": "Microsoft Windows Server 2022 Standard",
            "version": "10.0.20348",
            "kernel": "20348.1",
            "architecture": "64-bit",
            "hostname": "fixture-server",
        },
        "packages": {
            "status": "complete",
            "source": "registry-uninstall",
            "items": [{"name": "Fixture Software", "version": "1.2.3", "architecture": "unknown"}],
        },
        "hotfixes": {
            "status": "complete",
            "source": "Get-HotFix",
            "items": [{"id": "KB1234567", "description": "Fixture update"}],
        },
    }


def identified_evidence():
    data = evidence()
    data["packages"]["items"][0].update(
        publisher="Fixture Publisher",
        registry_key="{00000000-0000-0000-0000-000000000001}",
        registry_view="native",
        install_scope="machine",
    )
    return data


def test_old_software_evidence_keeps_missing_identity_missing():
    data = evidence()
    original = copy.deepcopy(data)
    normalized = normalize_inventory(data, "winrm", "inventory")
    assert normalized == original == data
    assert set(normalized["packages"]["items"][0]) == {"name", "version", "architecture"}


@pytest.mark.parametrize("view", ["native", "wow6432"])
def test_registry_identity_is_retained_without_inventing_architecture(view):
    data = identified_evidence()
    data["packages"]["items"][0]["registry_view"] = view
    original = copy.deepcopy(data)
    normalized = normalize_inventory(data, "winrm", "inventory")
    assert normalized == original == data
    assert normalized["packages"]["items"][0]["architecture"] == "unknown"


def test_optional_identity_fields_can_be_missing_independently():
    data = evidence()
    data["packages"]["items"][0]["publisher"] = "Fixture Publisher"
    assert normalize_inventory(data, "winrm", "inventory") == data


@pytest.mark.parametrize("key", ["publisher", "registry_key", "registry_view", "install_scope"])
@pytest.mark.parametrize(
    "value", [None, True, 3, 1.5, [], {}, "x" * 501, "a\nb", "a\x00b", "a\x7fb", "a\x85b"]
)
def test_registry_identity_is_bounded_typed_and_rejects_controls(key, value):
    data = identified_evidence()
    data["packages"]["items"][0][key] = value
    with pytest.raises(CollectionError, match="text field"):
        normalize_inventory(data, "winrm", "inventory")


@pytest.mark.parametrize("key", ["publisher", "registry_key"])
@pytest.mark.parametrize("value", ["", "x" * 500])
def test_absent_registry_property_values_and_maximum_text_are_retained(key, value):
    data = identified_evidence()
    data["packages"]["items"][0][key] = value
    assert normalize_inventory(data, "winrm", "inventory") == data


@pytest.mark.parametrize("view", ["", "x64", "x86", "Native", "HKCU"])
def test_registry_view_cannot_claim_architecture_or_an_unknown_view(view):
    data = identified_evidence()
    data["packages"]["items"][0]["registry_view"] = view
    with pytest.raises(CollectionError, match="registry view"):
        normalize_inventory(data, "winrm", "inventory")


@pytest.mark.parametrize("scope", ["", "user", "current_user", "Machine"])
def test_current_collector_only_supports_machine_install_scope(scope):
    data = identified_evidence()
    data["packages"]["items"][0]["install_scope"] = scope
    with pytest.raises(CollectionError, match="install scope"):
        normalize_inventory(data, "winrm", "inventory")


def test_truncated_registry_evidence_retains_identity_and_coverage():
    data = identified_evidence()
    data["packages"]["status"] = "truncated"
    data["packages"]["items"] *= 10000
    original = copy.deepcopy(data)
    assert normalize_inventory(data, "winrm", "inventory") == original == data
    data["packages"]["items"].append(copy.deepcopy(data["packages"]["items"][0]))
    with pytest.raises(CollectionError, match="row count"):
        normalize_inventory(data, "winrm", "inventory")


@pytest.mark.parametrize("section", ["packages", "hotfixes"])
def test_partial_collector_failure_preserves_other_section_and_os(section):
    data = identified_evidence()
    data[section].update(status="unavailable", items=[])
    assert normalize_inventory(data, "winrm", "inventory") == data


def test_unavailable_registry_section_cannot_hide_returned_rows():
    data = identified_evidence()
    data["packages"]["status"] = "unavailable"
    with pytest.raises(CollectionError, match="coverage status"):
        normalize_inventory(data, "winrm", "inventory")


def test_connection_mode_still_omits_software_enumeration():
    data = evidence()
    for section in ("packages", "hotfixes"):
        data[section].update(status="not_requested", items=[])
    assert normalize_inventory(data, "winrm", "connection") == data


def test_registry_metadata_is_not_reinterpreted_as_linux_package_identity():
    data = evidence()
    data["os"]["family"] = "Linux"
    data["packages"]["source"] = "dpkg"
    data["packages"]["items"][0]["publisher"] = "Untrusted extra property"
    data["hotfixes"] = {"status": "not_applicable", "source": "none", "items": []}
    normalized = normalize_inventory(data, "ssh_password", "inventory")
    assert "publisher" not in normalized["packages"]["items"][0]
