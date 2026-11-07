"""Exact identity, numeric build ordering and explicit assessment coverage."""

import copy
import json
from datetime import UTC, datetime, timedelta

import pytest

from app.services.windows_patch_assessment import (
    ENGINE_VERSION,
    MAX_REFERENCES,
    PRODUCTS,
    assess_windows_patches,
)

NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)


def inventory(year="2022", ubr=900, *, core=False, **identity):
    build = PRODUCTS[year][0]
    return {
        "schema_version": 1,
        "os": {
            "family": "Windows",
            "name": f"Microsoft Windows Server {year} Standard",
            "version": f"10.0.{build}",
            "kernel": f"{build}.{ubr}",
            "architecture": "64-bit",
            "hostname": "SYNTHETIC-SERVER",
            "product_type": "3",
            "installation_type": "Server Core" if core else "Server",
            "edition_id": "ServerStandard",
            "native_architecture": "AMD64",
            **identity,
        },
        "packages": {"status": "complete", "source": "registry-uninstall", "items": []},
        "hotfixes": {
            "status": "complete",
            "source": "Get-HotFix",
            # An old KB row is deliberate: KB absence cannot decide patch state.
            "items": [{"id": "KB5000001", "description": "Synthetic update"}],
        },
    }


def entry(year="2022", ubr=1000, *, core=False, **changes):
    build, desktop, core_id = PRODUCTS[year]
    cve = changes.get("cve", "CVE-2026-10001")
    return {
        "product_id": core_id if core else desktop,
        "product_name": f"Windows Server {year}" + (" (Server Core installation)" if core else ""),
        "cve": cve,
        "title": "Synthetic cumulative-update reference",
        "severity": "high",
        "cvss_score": "7.5",
        "kb": "KB5001000",
        "fixed_build": f"10.0.{build}.{ubr}",
        "document_id": "2026-Nov",
        "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/" + cve,
        "subtype": "Security Update",
        **changes,
    }


def catalog(entries=None, **changes):
    documents = []
    for month, day in (("Sep", 10), ("Oct", 10), ("Nov", 2)):
        date = f"2026-{ {'Sep': 9, 'Oct': 10, 'Nov': 11}[month]:02d}-{day:02d}T00:00:00Z"
        documents.append(
            {
                "id": "2026-" + month,
                "url": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-" + month,
                "sha256": "a" * 64,
                "current_release_date": date,
                "initial_release_date": date,
            }
        )
    return {
        "schema_version": 1,
        "source": "msrc-cvrf",
        "retrieved_at": NOW.isoformat(),
        "coverage_start": "2026-09-01",
        "coverage_end": "2026-11-07",
        "documents": documents,
        "entries": [entry()] if entries is None else entries,
        **changes,
    }


def assess(evidence=None, snapshot=None, **changes):
    return assess_windows_patches(
        inventory() if evidence is None else evidence,
        catalog() if snapshot is None else snapshot,
        evidence_collected_at=changes.pop("evidence_collected_at", NOW - timedelta(hours=1)),
        now=changes.pop("now", NOW),
        **changes,
    )


@pytest.mark.parametrize("year", PRODUCTS)
@pytest.mark.parametrize("core", [False, True])
def test_supported_server_variants_use_exact_product_and_numeric_build(year, core):
    result = assess(inventory(year, core=core), catalog([entry(year, core=core)]))
    assert result["status"] == "build_gap"
    assert result["engine_version"] == ENGINE_VERSION
    assert result["product"]["id"] == PRODUCTS[year][2 if core else 1]
    assert result["product"]["installation_type"] == ("Server Core" if core else "Server")
    assert result["baseline_build"] == f"10.0.{PRODUCTS[year][0]}.1000"
    assert result["baseline_kbs"] == ["KB5001000"]
    assert result["cve_references"][0]["cvss_score"] == 7.5
    assert result["coverage"]["status"] == "evaluated"
    assert result["valid_until"] == "2026-11-14T11:00:00Z"


@pytest.mark.parametrize("ubr", [1000, 1001, 10000])
def test_equal_and_later_build_meets_only_the_checked_catalog_baseline(ubr):
    data = inventory(ubr=ubr)
    data["hotfixes"]["items"] = []
    result = assess(data)
    assert result["status"] == "meets_catalog_baseline"
    assert "not a complete vulnerability assessment" in result["reason"]
    assert result["coverage"]["component_applicability"] == "not_checked"
    assert result["coverage"]["third_party_software"] == "unavailable"
    assert result["coverage"]["hotpatch"] == "unavailable"


def test_highest_numeric_build_is_selected_and_only_its_cve_references_are_reported():
    result = assess(
        inventory(ubr=999),
        catalog(
            [
                entry(ubr=999, cve="CVE-2026-10001", kb="KB5000999"),
                entry(ubr=1000, cve="CVE-2025-10002", kb="KB5001000"),
                entry("2019", ubr=99999, cve="CVE-2026-10003"),
                entry(ubr=99999, core=True, cve="CVE-2026-10004"),
            ]
        ),
    )
    assert result["status"] == "build_gap"
    assert result["baseline_build"] == "10.0.20348.1000"
    assert [row["cve"] for row in result["cve_references"]] == ["CVE-2025-10002"]
    assert "Latest remediations can reference older CVEs" in " ".join(result["limitations"])


@pytest.mark.parametrize(
    "key", ["product_type", "installation_type", "edition_id", "native_architecture"]
)
def test_legacy_inventory_requests_new_identity_evidence_instead_of_guessing(key):
    data = inventory()
    del data["os"][key]
    result = assess(data)
    assert result["status"] == "identity_incomplete"
    assert result["baseline_build"] is None
    assert result["cve_references"] == []


@pytest.mark.parametrize(
    "identity",
    [
        {"product_type": "1"},
        {"native_architecture": "ARM64"},
        {"architecture": "32-bit"},
        {"edition_id": "ServerDatacenterAzureEdition"},
        {"edition_id": "ServerAzureCor"},
        {"edition_id": "ServerDatacenterTurbine"},
        {"edition_id": "UnknownEdition"},
        {"edition_id": "ServerStandardCore", "installation_type": "Server"},
        {"edition_id": "ServerDatacenter"},
        {"installation_type": "Client"},
        {"name": "Microsoft Windows Server 2022 Datacenter: Azure Edition"},
        {"name": "Microsoft Windows Server 2022 Standard Hotpatch"},
        {"name": "Microsoft Windows 11 Pro"},
        {"family": "Linux"},
        {"edition_id": {}},
    ],
)
def test_unsupported_or_conflicting_identity_is_not_evaluated(identity):
    result = assess(inventory(**identity))
    assert result["status"] == "unsupported"
    assert result["baseline_build"] is None


@pytest.mark.parametrize(
    "identity",
    [
        {"kernel": "20348"},
        {"kernel": "20348."},
        {"version": "unknown"},
    ],
)
def test_incomplete_build_cannot_be_assessed(identity):
    assert assess(inventory(**identity))["status"] == "identity_incomplete"


@pytest.mark.parametrize(
    "identity",
    [
        {"kernel": "17763.1000"},
        {"version": "10.0.17763"},
        {"version": "10.0.20348.999"},
    ],
)
def test_caption_version_and_build_must_agree(identity):
    assert assess(inventory(**identity))["status"] == "unsupported"


def test_domain_controller_type_and_standard_core_edition_are_supported():
    result = assess(
        inventory(core=True, product_type="2", edition_id="ServerStandardCore"),
        catalog([entry(core=True)]),
    )
    assert result["status"] == "build_gap"


@pytest.mark.parametrize(
    "collected",
    [
        None,
        "invalid",
        "2026-11-07T11:00:00",
        NOW + timedelta(seconds=1),
        NOW - timedelta(days=7),
    ],
)
def test_missing_future_naive_or_seven_day_old_evidence_cannot_claim_current_baseline(collected):
    result = assess(evidence_collected_at=collected)
    assert result["status"] == "stale_evidence"
    assert result["baseline_build"] is None


def test_catalog_freshness_and_validity_limit_are_independent_of_evidence_age():
    retrieved = NOW - timedelta(days=6)
    snapshot = catalog(retrieved_at=retrieved.isoformat(), coverage_end="2026-11-01")
    snapshot["documents"] = snapshot["documents"][:2]
    snapshot["coverage_end"] = "2026-10-31"
    snapshot["entries"] = [entry(document_id="2026-Oct")]
    assert assess(snapshot=snapshot)["valid_until"] == "2026-11-08T12:00:00Z"
    snapshot["retrieved_at"] = (NOW - timedelta(days=7)).isoformat()
    assert assess(snapshot=snapshot)["status"] == "stale_catalog"


def test_none_or_invalid_catalog_never_becomes_a_clean_result():
    result = assess_windows_patches(inventory(), None, evidence_collected_at=NOW, now=NOW)
    assert result["status"] == "catalog_unavailable" and result["valid_until"] is None
    assert assess(snapshot={})["status"] == "catalog_unavailable"
    assert assess(snapshot=catalog(retrieved_at="invalid"))["status"] == "catalog_unavailable"
    assert (
        assess(snapshot=catalog(retrieved_at=(NOW + timedelta(seconds=1)).isoformat()))["status"]
        == "catalog_unavailable"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"product_id": "11924"},
        {"fixed_build": "10.0.17763.99999"},
        {"fixed_build": ""},
        {"subtype": "Hotpatch"},
        {"source_url": "https://example.test/CVE-2026-10001"},
        {"source_url": "javascript:alert(1)"},
        {"document_id": "2026-Dec"},
        {"cvss_score": "NaN"},
    ],
)
def test_inapplicable_or_unverifiable_reference_cannot_produce_a_build_assessment(changes):
    assert assess(snapshot=catalog([entry(**changes)]))["status"] == "coverage_unavailable"


def test_missing_variant_fixed_build_and_empty_catalog_have_explicit_unavailable_coverage():
    assert assess(snapshot=catalog([]))["status"] == "coverage_unavailable"
    assert assess(snapshot=catalog([entry(core=True)]))["status"] == "coverage_unavailable"
    assert assess(snapshot=catalog([entry("2019")]))["status"] == "coverage_unavailable"


def test_missing_document_inside_window_is_rejected():
    snapshot = catalog()
    del snapshot["documents"][1]
    assert assess(snapshot=snapshot)["status"] == "coverage_unavailable"


def test_fresh_catalog_can_end_at_last_published_month_before_patch_tuesday():
    now = datetime(2026, 12, 8, 12, tzinfo=UTC)
    result = assess(
        snapshot=catalog(retrieved_at=now.isoformat(), coverage_end="2026-11-30"),
        evidence_collected_at=now,
        now=now,
    )
    assert result["status"] == "build_gap"
    assert result["coverage"]["catalog_end"] == "2026-11-30"
    assert result["valid_until"] == "2026-12-15T12:00:00Z"


def test_fresh_retrieval_of_an_ancient_window_does_not_claim_current_baseline():
    now = datetime(2026, 12, 8, 12, tzinfo=UTC)
    snapshot = catalog(retrieved_at=now.isoformat(), coverage_end="2026-10-31")
    snapshot["documents"] = snapshot["documents"][:2]
    snapshot["entries"] = [entry(document_id="2026-Oct")]
    assert (
        assess(snapshot=snapshot, evidence_collected_at=now, now=now)["status"] == "stale_catalog"
    )


def test_repeated_cve_metadata_is_combined_with_all_baseline_provenance():
    result = assess(
        snapshot=catalog(
            [
                entry(document_id="2026-Oct", cvss_score="7.0", severity="high"),
                entry(
                    document_id="2026-Nov", cvss_score="9.8", severity="critical", kb="KB5001001"
                ),
            ]
        )
    )
    assert result["cve_references_total"] == 1
    reference = result["cve_references"][0]
    assert reference["severity"] == "critical" and reference["cvss_score"] == 9.8
    assert reference["kbs"] == ["KB5001000", "KB5001001"]
    assert reference["document_ids"] == ["2026-Nov", "2026-Oct"]
    assert len(result["sources"]) == 2


def test_reference_output_is_bounded_and_truncation_is_explicit():
    snapshot = catalog(
        [entry(cve=f"CVE-2026-{10000 + index}") for index in range(MAX_REFERENCES + 5)]
    )
    result = assess(snapshot=snapshot)
    assert result["status"] == "build_gap"
    assert len(result["cve_references"]) == MAX_REFERENCES
    assert result["cve_references_total"] == MAX_REFERENCES + 5
    assert result["cve_references_truncated"] is True
    assert len(json.dumps(result)) < 1000000


def test_assessment_does_not_mutate_saved_evidence_or_catalog():
    data, snapshot = inventory(), catalog()
    before = copy.deepcopy((data, snapshot))
    assess(data, snapshot)
    assert (data, snapshot) == before


def test_naive_assessment_clock_is_rejected_instead_of_assuming_a_timezone():
    with pytest.raises(ValueError, match="timezone-aware"):
        assess(now=datetime(2026, 11, 7, 12))


def test_far_future_evidence_timestamp_fails_without_date_overflow():
    result = assess(evidence_collected_at=datetime.max.replace(tzinfo=UTC))
    assert result["status"] == "stale_evidence"
    assert result["valid_until"] is None
