"""Exact registry identity, numeric applicability and visible coverage limits."""

import copy
import json
from datetime import UTC, datetime, timedelta

import pytest

from app.services.software_assessment import (
    ENGINE_VERSION,
    MAX_PRODUCT_VERSIONS,
    assess_software,
)

NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)


def package(**changes):
    return {
        "name": "Microsoft Edge",
        "version": "150.0.1.2",
        "architecture": "unknown",
        "publisher": "Microsoft Corporation",
        "registry_key": "Microsoft Edge",
        "registry_view": "wow6432",
        "install_scope": "machine",
        **changes,
    }


def inventory(items=None, **changes):
    return {
        "schema_version": 1,
        "os": {"family": "Windows"},
        "packages": {
            "source": "registry-uninstall",
            "status": "complete",
            "items": [package()] if items is None else items,
        },
        **changes,
    }


def entry(**changes):
    product = changes.get("product_key", "edge-windows")
    cve = changes.get("cve", "CVE-2025-55188" if product == "7zip-windows" else "CVE-2026-10001")
    from app.services.software_catalog import cve_url

    return {
        "cve": cve,
        "product_key": product,
        "source_product": "Microsoft Edge for Windows",
        "title": "Synthetic product advisory",
        "severity": "high",
        "affected_ranges": [{"introduced": "1.0.0.0", "fixed": "151.0.0.1"}],
        "source_urls": [cve_url(cve)],
        "document_ids": [
            "cve:" + cve,
            "source:7zip-history" if product == "7zip-windows" else "msrc:2026-Nov",
        ],
        **changes,
    }


def catalog(entries=None, unavailable=None, **changes):
    from app.services.software_catalog import API, HISTORY_URL, cve_url

    entries = [entry()] if entries is None else entries
    missing = {**(unavailable or {})}
    if not any(row["product_key"] == "7zip-windows" for row in entries):
        missing.setdefault("7zip-windows", ["CVE-2025-55188"])
    documents = [
        {"id": "msrc:" + month, "url": API + "/cvrf/" + month, "sha256": "a" * 64}
        for month in ("2026-Sep", "2026-Oct", "2026-Nov")
    ] + [{"id": "source:7zip-history", "url": HISTORY_URL, "sha256": "b" * 64}]
    cves = {row["cve"] for row in entries} | {cve for values in missing.values() for cve in values}
    documents.extend(
        {"id": "cve:" + cve, "url": cve_url(cve), "sha256": "c" * 64} for cve in sorted(cves)
    )
    return {
        "schema_version": 1,
        "source": "vendor-software-ranges",
        "rules_version": "windows-registry-v1",
        "retrieved_at": NOW.isoformat(),
        "coverage_start": "2026-09-01",
        "coverage_end": "2026-11-07",
        "documents": documents,
        "entries": entries,
        "coverage": [
            {
                "product_key": key,
                "discovered": sum(item["product_key"] == key for item in entries)
                + len(missing.get(key, [])),
                "parsed": sum(item["product_key"] == key for item in entries),
                "unavailable_cves": missing.get(key, []),
                "scope": "Synthetic explicit advisory scope",
            }
            for key in ("edge-windows", "7zip-windows")
        ],
        **changes,
    }


def assess(evidence=None, snapshot=None, **changes):
    return assess_software(
        inventory() if evidence is None else evidence,
        catalog() if snapshot is None else snapshot,
        evidence_collected_at=changes.pop("evidence_collected_at", NOW - timedelta(hours=1)),
        now=changes.pop("now", NOW),
        **changes,
    )


def test_affected_range_is_explicit_and_input_evidence_is_immutable():
    evidence, snapshot = inventory(), catalog()
    before = copy.deepcopy((evidence, snapshot))
    result = assess(evidence, snapshot)
    assert result["status"] == "version_matches_found"
    assert result["engine_version"] == ENGINE_VERSION
    assert result["summary"] == {
        "inventory_entries": 1,
        "identified_entries": 1,
        "assessed_entries": 1,
        "unassessed_entries": 0,
        "product_versions": 1,
        "matched_product_versions": 1,
        "cve_matches": 1,
    }
    product = result["products"][0]
    assert product["status"] == "version_matches_affected_range"
    assert product["evidence_basis"] == "registry-uninstall"
    assert product["matches"][0]["affected_ranges"] == [
        {"introduced": "1.0.0.0", "fixed": "151.0.0.1"}
    ]
    assert product["matches"][0]["source_product"] == "Microsoft Edge for Windows"
    assert result["coverage"]["exploitability"] == "not_verified"
    assert result["valid_until"] == "2026-11-14T11:00:00Z"
    assert (evidence, snapshot) == before


@pytest.mark.parametrize(
    ("version", "matched"),
    [
        ("1.0.0.0", True),
        ("0.9.9999.9999", False),
        ("150.0.9999.9999", True),
        ("151.0.0.0", True),
        ("151.0.0.1", False),
        ("151.0.0.2", False),
        ("1000.0.0.0", False),
    ],
)
def test_numeric_boundaries_are_lower_inclusive_and_fixed_exclusive(version, matched):
    result = assess(inventory([package(version=version)]))
    assert bool(result["summary"]["cve_matches"]) is matched
    if not matched:
        assert result["status"] == "no_matches_in_checked_ranges"
        assert result["products"][0]["status"] == "no_match_in_catalog"
        assert "not a claim" in " ".join(result["limitations"])


@pytest.mark.parametrize("field", ["publisher", "registry_key", "registry_view", "install_scope"])
def test_legacy_or_incomplete_entry_is_unknown_instead_of_assumed(field):
    row = package()
    del row[field]
    result = assess(inventory([row]))
    assert result["status"] == "coverage_unavailable"
    assert result["summary"]["unassessed_entries"] == 1
    assert result["products"] == []
    assert len(result["unassessed"]) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "Microsoft Edge Beta"},
        {"name": "Microsoft Edge WebView2 Runtime"},
        {"name": "Microsoft Edge Update"},
        {"publisher": "Not Microsoft Corporation"},
        {"publisher": "Microsoft"},
        {"name": "Microsoft Edge enterprise repackaged"},
        {"registry_view": "x64"},
        {"install_scope": "user"},
        {"registry_key": ""},
        {"version": "150.0.1"},
        {"version": "150.0.1.2-beta"},
        {"version": "150.0.1.2 "},
        {"version": ""},
    ],
)
def test_unknown_names_publishers_views_and_versions_never_match(changes):
    result = assess(inventory([package(**changes)]))
    assert result["summary"]["cve_matches"] == 0
    assert result["summary"]["assessed_entries"] == 0
    assert result["summary"]["unassessed_entries"] == 1


def test_identical_installations_in_two_registry_views_do_not_duplicate_cve_matches():
    result = assess(
        inventory([package(), package(registry_view="native", registry_key="synthetic-other-key")])
    )
    assert result["summary"]["inventory_entries"] == 2
    assert result["summary"]["assessed_entries"] == 2
    assert result["summary"]["product_versions"] == 1
    assert result["summary"]["cve_matches"] == 1
    assert result["products"][0]["evidence_count"] == 2


def test_different_installed_versions_remain_separate_evidence():
    result = assess(inventory([package(), package(version="151.0.0.1")]))
    assert result["summary"]["product_versions"] == 2
    assert result["summary"]["matched_product_versions"] == 1
    assert len(result["products"]) == 2


def test_unmapped_software_and_truncated_collection_have_visible_coverage():
    evidence = inventory(
        [package(), package(name="Synthetic unsupported app", publisher="Example Vendor")]
    )
    evidence["packages"]["status"] = "truncated"
    result = assess(evidence)
    assert result["status"] == "version_matches_found"
    assert result["summary"]["unassessed_entries"] == 1
    assert result["coverage"]["package_status"] == "truncated"
    assert result["coverage"]["status"] == "limited"
    assert result["unassessed"][0]["name"] == "Synthetic unsupported app"


def test_missing_ranges_for_recognized_product_never_become_no_match():
    result = assess(snapshot=catalog([], {"edge-windows": ["CVE-2026-10001"]}))
    assert result["status"] == "coverage_unavailable"
    assert result["products"][0]["status"] == "catalog_incomplete"
    assert result["products"][0]["checked_cves"] == 0
    assert result["summary"]["unassessed_entries"] == 1


def test_partially_parsed_catalog_keeps_unknown_advisories_visible():
    result = assess(
        inventory([package(version="151.0.0.1")]),
        catalog(unavailable={"edge-windows": ["CVE-2026-10002"]}),
    )
    assert result["status"] == "no_matches_in_checked_ranges"
    assert result["products"][0]["status"] == "catalog_incomplete"
    assert next(
        row for row in result["coverage"]["vendor_catalog"] if row["product_key"] == "edge-windows"
    )["unavailable_cves"] == ["CVE-2026-10002"]


@pytest.mark.parametrize(
    "collected",
    [None, "invalid", "2026-11-07T11:00:00", NOW + timedelta(seconds=1), NOW - timedelta(days=7)],
)
def test_unusable_inventory_time_has_no_current_applicability(collected):
    result = assess(evidence_collected_at=collected)
    assert result["status"] == "stale_evidence"
    assert result["products"] == []
    assert result["valid_until"] is None


def test_catalog_and_inventory_freshness_expire_independently():
    result = assess(
        snapshot=catalog(
            retrieved_at=(NOW - timedelta(days=6)).isoformat(), coverage_end="2026-11-01"
        )
    )
    assert result["valid_until"] == "2026-11-08T12:00:00Z"
    stale = assess(snapshot=catalog(retrieved_at=(NOW - timedelta(days=7)).isoformat()))
    assert stale["status"] == "stale_catalog"
    assert stale["products"] == []


@pytest.mark.parametrize("snapshot", [None, {}, {"retrieved_at": "invalid"}])
def test_missing_invalid_catalog_is_unavailable(snapshot):
    result = assess_software(inventory(), snapshot, evidence_collected_at=NOW, now=NOW)
    assert result["status"] == "catalog_unavailable"
    assert result["products"] == []
    assert result["valid_until"] is None


def test_future_catalog_and_invalid_assessment_time_are_rejected():
    assert (
        assess(snapshot=catalog(retrieved_at=(NOW + timedelta(seconds=1)).isoformat()))["status"]
        == "catalog_unavailable"
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        assess(now=NOW.replace(tzinfo=None))


@pytest.mark.parametrize(
    "evidence",
    [inventory(os={"family": "Linux"}), inventory(packages={"source": "rpm"}), {}],
)
def test_other_platforms_and_sources_are_not_implicitly_mapped(evidence):
    assert assess(evidence)["status"] in {"unsupported", "identity_incomplete"}


@pytest.mark.parametrize("changes", [{"name": None}, {"publisher": {}}, {"version": "1\n2"}])
def test_tampered_evidence_is_rejected_before_applicability(changes):
    with pytest.raises(ValueError, match="evidence|identity"):
        assess(inventory([package(**changes)]))


def test_bounded_product_versions_remain_explicitly_unassessed_and_result_fits_api_limit():
    evidence = inventory(
        [package(version=f"150.0.1.{number}") for number in range(MAX_PRODUCT_VERSIONS + 3)]
    )
    result = assess(evidence)
    assert result["summary"]["product_versions"] == MAX_PRODUCT_VERSIONS + 3
    assert result["products_total"] == MAX_PRODUCT_VERSIONS + 3
    assert result["products_truncated"] is True
    assert len(result["products"]) == MAX_PRODUCT_VERSIONS
    assert result["summary"]["assessed_entries"] == MAX_PRODUCT_VERSIONS
    assert result["summary"]["unassessed_entries"] == 3
    assert "limit" in result["unassessed"][0]["reason"]
    assert len(json.dumps(result).encode()) < 4 * 1024 * 1024


@pytest.mark.parametrize(
    "version,matched", [("24.09", True), ("25.00", True), ("25.01", False), ("25.10", False)]
)
def test_7zip_uses_numeric_two_part_release_with_zero_lower_sentinel(version, matched):
    row = package(
        name=f"7-Zip {version} (x64)",
        version=version,
        publisher="Igor Pavlov",
        registry_key="7-Zip",
    )
    advisory = entry(
        product_key="7zip-windows",
        source_product="7-Zip",
        affected_ranges=[{"introduced": "0", "fixed": "25.01"}],
    )
    result = assess(inventory([row]), catalog([advisory]))
    assert result["products"][0]["product_key"] == "7zip-windows"
    assert bool(result["summary"]["cve_matches"]) is matched


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "7-Zip 24.08 (x64)", "version": "24.09"},
        {"name": "7-Zip 24.09 (x64)", "version": "24.9"},
        {"name": "7-Zip 24.09 (x64)", "publisher": "Igor Pavlov repack"},
        {"name": "7-Zip ZS 24.09 (x64)"},
        {"version": "24.09.00.0"},
    ],
)
def test_7zip_identity_and_display_version_must_agree(changes):
    row = package(
        **{"name": "7-Zip 24.09 (x64)", "version": "24.09", "publisher": "Igor Pavlov", **changes}
    )
    assert assess(inventory([row]))["summary"]["assessed_entries"] == 0


def test_source_catalog_corruption_is_not_repaired_by_engine():
    snapshot = catalog()
    snapshot["entries"][0]["affected_ranges"][0]["fixed"] = "not-a-version"
    assert assess(snapshot=snapshot)["status"] == "catalog_unavailable"


def test_global_match_and_source_display_limits_preserve_real_totals():
    entries = [entry(cve=f"CVE-2026-{10000 + number}") for number in range(600)]
    result = assess(
        inventory([package(), package(version="150.0.1.3")]),
        catalog(entries),
    )
    assert result["summary"]["cve_matches"] == 1200
    assert sum(len(row["matches"]) for row in result["products"]) == 500
    assert all(row["matches_total"] == 600 for row in result["products"])
    assert any(row["matches_truncated"] for row in result["products"])
    assert result["sources_total"] > 100
    assert len(result["sources"]) == 100
    assert result["sources_truncated"] is True
    assert len(json.dumps(result, ensure_ascii=True).encode()) < 4 * 1024 * 1024


def test_unassessed_display_limit_never_reduces_unassessed_evidence_count():
    result = assess(
        inventory([package(name=f"Synthetic unsupported app {number}") for number in range(220)])
    )
    assert result["summary"]["inventory_entries"] == 220
    assert result["summary"]["unassessed_entries"] == 220
    assert result["unassessed_total"] == 220
    assert result["unassessed_truncated"] is True
    assert len(result["unassessed"]) == 200


@pytest.mark.parametrize("field", ["name", "version", "publisher", "registry_key"])
def test_control_characters_cannot_enter_saved_applicability_display(field):
    with pytest.raises(ValueError, match="evidence|identity"):
        assess(inventory([package(**{field: "synthetic\x85text"})]))
