"""Retain explicit Windows identity without rewriting older inventory evidence."""

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
        "packages": {"status": "complete", "source": "registry-uninstall", "items": []},
        "hotfixes": {"status": "complete", "source": "Get-HotFix", "items": []},
    }


def test_old_windows_inventory_stays_identical_and_missing_identity_is_not_invented():
    original = evidence()
    before = copy.deepcopy(original)
    assert normalize_inventory(original, "winrm", "inventory") == before
    assert original == before


def test_new_identity_is_retained_for_exact_product_and_installation_mapping():
    original = evidence()
    original["os"].update(
        product_type="2",
        sku="7",
        installation_type="Server Core",
        edition_id="ServerStandard",
        display_version="21H2",
        native_architecture="AMD64",
    )
    assert normalize_inventory(original, "winrm", "inventory") == original


@pytest.mark.parametrize(
    "key",
    [
        "product_type",
        "sku",
        "installation_type",
        "edition_id",
        "display_version",
        "native_architecture",
    ],
)
@pytest.mark.parametrize("value", [None, 3, "x" * 501, "Server\nCore"])
def test_identity_fields_share_the_same_bounded_text_contract(key, value):
    original = evidence()
    original["os"][key] = value
    with pytest.raises(CollectionError, match="text field"):
        normalize_inventory(original, "winrm", "inventory")
