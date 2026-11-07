"""Configured-source offer evidence is never a universal patch compliance claim."""

import copy
from datetime import UTC, datetime, timedelta

import pytest

from app.services.windows_update_assessment import ENGINE_VERSION, assess_windows_updates

NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)
SECURITY = "0fa1201d-4330-4fa8-8ae9-b877473b6441"
QUALITY = "cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83"
FEATURE = "3689bdc8-b205-4af4-8d4a-a63924c5e9d5"
DEFINITION = "e0789628-ce08-4437-be74-2495b842f43b"


def offer(number=1, category=SECURITY, optional=False):
    return {
        "update_id": f"00000000-0000-4000-8000-{number:012d}",
        "revision": 200,
        "title": f"Synthetic offer {number}",
        "kbs": ["KB5127648"],
        "categories": [{"id": category, "name": "Localized title", "type": "UpdateClassification"}],
        "msrc_severity": "Critical",
        "is_hidden": False,
        "is_installed": False,
        "is_optional": optional,
        "is_mandatory": False,
    }


def evidence(items=None):
    items = [offer()] if items is None else items
    return {
        "schema_version": 1,
        "os": {"family": "Windows", "product_type": "1", "name": "Windows 11 Pro"},
        "windows_updates": {
            "schema_version": 1,
            "source": "windows-update-agent",
            "mode": "online",
            "server_selection": "default",
            "queried_at": (NOW - timedelta(minutes=2)).isoformat(),
            "status": "complete",
            "result_code": 2,
            "total": len(items),
            "items": items,
            "truncated": False,
            "hidden_updates": "not_assessed",
            "drivers": "not_assessed",
            "superseded": "excluded",
            "reboot_required": False,
        },
    }


def assess(data, **kwargs):
    return assess_windows_updates(
        data,
        now=NOW,
        evidence_collected_at=NOW - timedelta(minutes=1),
        evidence_mode=kwargs.pop("evidence_mode", "windows_updates"),
        **kwargs,
    )


def test_offers_use_guid_classification_optional_flags_and_reboot_separately():
    data = evidence(
        [
            offer(1),
            offer(2, QUALITY),
            offer(3, QUALITY, True),
            offer(4, FEATURE),
            offer(5, DEFINITION),
            offer(6, "00000000-0000-4000-8000-000000000099", None),
        ]
    )
    data["windows_updates"]["reboot_required"] = True
    before = copy.deepcopy(data)
    result = assess(data)
    assert data == before
    assert result["status"] == "updates_offered"
    assert result["provider"] == "windows-update-agent" and result["catalog_applicable"] is False
    report = result["windows_updates"]
    assert report["summary"] == {
        "offers": 6,
        "security": 1,
        "quality": 2,
        "feature": 1,
        "definition": 1,
        "other": 1,
        "optional": 1,
        "optional_unknown": 1,
        "actionable": 2,
    }
    assert report["reboot_required"] is True
    assert report["items"][0]["actionable"] and not report["items"][2]["actionable"]
    assert result["engine_version"] == ENGINE_VERSION
    assert "cve_references" not in result and "baseline_build" not in result


def test_no_offers_is_neutral_and_keeps_visibility_and_source_limits():
    result = assess(evidence([]))
    assert result["status"] == "no_update_offers"
    assert "does not establish" in result["reason"]
    assert result["windows_updates"]["summary"]["offers"] == 0
    assert result["windows_updates"]["hidden_updates"] == "not_assessed"
    assert result["windows_updates"]["drivers"] == "not_assessed"
    assert any("ESU" in text for text in result["limitations"])


def test_ordinary_inventory_cannot_be_promoted_to_online_query():
    result = assess(evidence(), evidence_mode="inventory")
    assert result["status"] == "update_query_required" and result["windows_updates"] is None
    data = evidence()
    del data["windows_updates"]
    assert assess(data)["status"] == "update_query_required"


@pytest.mark.parametrize(
    "family,product", [("Linux", "1"), ("Windows", "3"), ("Windows", True), ("Windows", None)]
)
def test_only_reported_windows_workstation_identity_is_accepted(family, product):
    data = evidence()
    data["os"].update(family=family, product_type=product)
    assert assess(data)["status"] == "update_query_required"


@pytest.mark.parametrize(
    "key,value",
    [
        ("status", "partial"),
        ("status", "unavailable"),
        ("status", "timeout"),
        ("result_code", 3),
        ("result_code", True),
        ("result_code", None),
        ("truncated", True),
        ("total", 3),
        ("total", True),
        ("schema_version", True),
        ("source", "offline-cache"),
        ("mode", "offline"),
        ("server_selection", "public"),
        ("drivers", "assessed"),
        ("hidden_updates", "assessed"),
        ("superseded", "included"),
    ],
)
def test_incomplete_or_changed_query_contract_never_establishes_no_offers(key, value):
    data = evidence([])
    data["windows_updates"][key] = value
    assert assess(data)["status"] == "update_query_incomplete"


@pytest.mark.parametrize(
    "delta", [timedelta(hours=-24), timedelta(hours=-25), timedelta(seconds=1)]
)
def test_query_time_is_not_future_or_at_least_24_hours_old(delta):
    data = evidence()
    data["windows_updates"]["queried_at"] = (NOW + delta).isoformat()
    assert assess(data)["status"] == "stale_evidence"


@pytest.mark.parametrize("stamp", [None, "not-a-date", "2026-11-07T11:00:00"])
def test_missing_invalid_or_naive_query_date_is_stale(stamp):
    data = evidence([])
    data["windows_updates"]["queried_at"] = stamp
    assert assess(data)["status"] == "stale_evidence"


@pytest.mark.parametrize(
    "change", ["hidden", "installed", "invalid_uuid", "invalid_kb", "duplicate"]
)
def test_malformed_offer_does_not_discard_valid_offers_or_establish_completion(change):
    data = evidence([offer(), offer(2)])
    other = data["windows_updates"]["items"][1]
    if change == "hidden":
        other["is_hidden"] = True
    elif change == "installed":
        other["is_installed"] = True
    elif change == "invalid_uuid":
        other["update_id"] = "not-a-guid"
    elif change == "invalid_kb":
        other["kbs"] = ["https://untrusted.example"]
    else:
        other["update_id"] = data["windows_updates"]["items"][0]["update_id"]
    result = assess(data)
    assert result["status"] == "update_query_incomplete"
    assert result["windows_updates"]["summary"]["offers"] == 1
    assert result["windows_updates"]["items_truncated"]


def test_severity_title_localized_name_and_product_category_do_not_imply_security():
    item = offer()
    item["title"] = "Critical Security Update"
    item["categories"][0]["type"] = "Product"
    result = assess(evidence([item]))
    assert result["windows_updates"]["summary"]["security"] == 0
    assert result["windows_updates"]["summary"]["other"] == 1
    assert not result["windows_updates"]["items"][0]["actionable"]


def test_unknown_optionality_and_conflicting_categories_are_not_required_updates():
    item = offer(optional=None)
    item["categories"].append({"id": FEATURE, "name": "Feature", "type": "UpdateClassification"})
    result = assess(evidence([item]))
    assert result["windows_updates"]["summary"]["actionable"] == 0
    assert result["windows_updates"]["items"][0]["classification"] == "other"


def test_oversized_list_is_bounded_and_partial():
    result = assess(evidence([offer(i) for i in range(201)]))
    assert result["status"] == "update_query_incomplete"
    assert len(result["windows_updates"]["items"]) == 200
