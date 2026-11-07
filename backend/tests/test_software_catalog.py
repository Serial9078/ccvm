"""Synthetic source fixtures; no vendor or target network calls in unit tests."""

import copy
import json
from datetime import UTC, datetime

import pytest
import requests

from app.services import software_catalog as catalog

NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)
EDGE_CVE = "CVE-2026-100201"


def catalog_fixture():
    """One valid synthetic catalog for database/engine integration tests."""
    return {
        "schema_version": 1,
        "source": catalog.SOURCE,
        "rules_version": catalog.RULES_VERSION,
        "retrieved_at": NOW.isoformat(),
        "coverage_start": "2026-11-01",
        "coverage_end": "2026-11-07",
        "documents": [
            {"id": "msrc:2026-Nov", "url": f"{catalog.API}/cvrf/2026-Nov", "sha256": "a" * 64},
            {"id": f"cve:{EDGE_CVE}", "url": catalog.cve_url(EDGE_CVE), "sha256": "b" * 64},
            {
                "id": f"cve:{catalog.SEVEN_CVE}",
                "url": catalog.cve_url(catalog.SEVEN_CVE),
                "sha256": "c" * 64,
            },
            {"id": "source:7zip-history", "url": catalog.HISTORY_URL, "sha256": "d" * 64},
        ],
        "entries": [
            {
                "cve": EDGE_CVE,
                "product_key": "edge-windows",
                "source_product": "Microsoft Edge for Windows",
                "title": "Synthetic desktop browser advisory",
                "severity": "high",
                "affected_ranges": [{"introduced": "1.0.0.0", "fixed": "152.0.4191.52"}],
                "source_urls": [catalog.cve_url(EDGE_CVE), catalog.msrc.CVE_URL + EDGE_CVE],
                "document_ids": [f"cve:{EDGE_CVE}", "msrc:2026-Nov"],
            },
            {
                "cve": catalog.SEVEN_CVE,
                "product_key": "7zip-windows",
                "source_product": "7-Zip",
                "title": "Synthetic archive advisory",
                "severity": "unknown",
                "affected_ranges": [{"introduced": "0", "fixed": "25.01"}],
                "source_urls": [catalog.cve_url(catalog.SEVEN_CVE), catalog.HISTORY_URL],
                "document_ids": [f"cve:{catalog.SEVEN_CVE}", "source:7zip-history"],
            },
        ],
        "coverage": [
            {
                "product_key": "edge-windows",
                "discovered": 1,
                "parsed": 1,
                "unavailable_cves": [],
                "scope": catalog.PRODUCTS["edge-windows"]["scope"],
            },
            {
                "product_key": "7zip-windows",
                "discovered": 1,
                "parsed": 1,
                "unavailable_cves": [],
                "scope": catalog.PRODUCTS["7zip-windows"]["scope"],
            },
        ],
    }


def cna(cve=EDGE_CVE, *, seven=False, windows=True):
    provider = catalog.SEVEN_CNA if seven else catalog.MICROSOFT_CNA
    product = (
        "7-Zip"
        if seven
        else "Microsoft Edge for Windows" if windows else "Microsoft Edge (Chromium-based)"
    )
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": cve,
            "state": "PUBLISHED",
            "assignerOrgId": provider[0],
            "assignerShortName": provider[1],
        },
        "containers": {
            "cna": {
                "providerMetadata": {"orgId": provider[0], "shortName": provider[1]},
                "title": "Synthetic vendor advisory",
                "affected": [
                    {
                        "vendor": "7-Zip" if seven else "Microsoft",
                        "product": product,
                        "defaultStatus": "unaffected",
                        "versions": [
                            {
                                "version": "0" if seven else "1.0.0.0",
                                "lessThan": "25.01" if seven else "152.0.4191.52",
                                "status": "affected",
                                "versionType": "custom",
                            }
                        ],
                    }
                ],
            }
        },
    }


def discovery():
    return {"title": "Synthetic MSRC title", "severity": "high", "document_ids": ["msrc:2026-Nov"]}


def monthly_document(identifier):
    return {
        "DocumentTracking": {
            "Identification": {"ID": {"Value": identifier}},
            "InitialReleaseDate": identifier[:4]
            + "-"
            + str(catalog.msrc.MONTHS.index(identifier[5:]) + 1).zfill(2)
            + "-04T07:00:00",
            "CurrentReleaseDate": "2026-11-05T08:00:00",
        },
        "ProductTree": {
            "FullProductName": [
                {"ProductID": "edge", "Value": "Microsoft Edge (Chromium-based)"},
                {"ProductID": "android", "Value": "Microsoft Edge for Android"},
            ]
        },
        "Vulnerability": [
            {
                "CVE": EDGE_CVE,
                "Title": {"Value": "Microsoft Edge (Chromium-based) synthetic advisory"},
                "ProductStatuses": [{"Type": 3, "ProductID": ["edge", "android"]}],
                "Threats": [
                    {"Type": 3, "ProductID": ["edge"], "Description": {"Value": "Important"}}
                ],
            }
        ],
    }


class Response:
    def __init__(self, value, *, status=200, content_type="application/json", raw=False):
        self.status_code, self.headers = status, {"Content-Type": content_type}
        self.content = value if raw else json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def iter_content(self, size):
        for offset in range(0, len(self.content), size):
            yield self.content[offset : offset + size]


class Session:
    def __init__(self, replies):
        self.replies, self.calls, self.headers = replies, [], {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        result = self.replies[url]
        if isinstance(result, list):
            result = result.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def fixture_session(monkeypatch):
    identifiers = ["2026-Sep", "2026-Oct", "2026-Nov"]
    docs = {key: monthly_document(key) for key in identifiers}
    index = {
        "value": [
            {
                "ID": key,
                "InitialReleaseDate": doc["DocumentTracking"]["InitialReleaseDate"] + "Z",
                "CurrentReleaseDate": doc["DocumentTracking"]["CurrentReleaseDate"] + "Z",
                "CvrfUrl": f"{catalog.API}/cvrf/{key}",
            }
            for key, doc in docs.items()
        ]
    }
    session = Session(
        {
            f"{catalog.API}/updates": Response(index),
            **{f"{catalog.API}/cvrf/{key}": Response(value) for key, value in docs.items()},
            catalog.cve_url(EDGE_CVE): Response(cna()),
            catalog.cve_url(catalog.SEVEN_CVE): Response(cna(catalog.SEVEN_CVE, seven=True)),
            catalog.HISTORY_URL: Response(
                b"HISTORY of 7-Zip\n25.01          2025-08-03\n-------------------------\n"
                b"- CVE-2025-55188 : Symbolic link security.\n\n"
                b"25.00          2025-07-05\n-------------------------\n",
                content_type="text/plain",
                raw=True,
            ),
        }
    )
    monkeypatch.setattr(catalog.requests, "Session", lambda: session)
    return session


def test_build_discovers_complete_window_deduplicates_cves_and_uses_verified_sources(monkeypatch):
    session = fixture_session(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.example.test")
    updates = []
    result = catalog.build_catalog(now=NOW, progress=updates.append)
    assert result["coverage_start"] == "2026-09-01"
    assert result["coverage_end"] == "2026-11-07"
    assert len(result["entries"]) == 2
    edge = next(item for item in result["entries"] if item["product_key"] == "edge-windows")
    assert edge["source_product"] == "Microsoft Edge for Windows"
    assert edge["severity"] == "high"
    assert edge["document_ids"] == [
        f"cve:{EDGE_CVE}",
        "msrc:2026-Nov",
        "msrc:2026-Oct",
        "msrc:2026-Sep",
    ]
    assert all(item["parsed"] == 1 for item in result["coverage"])
    assert (
        session.trust_env is False
        and session.proxies == {}
        and session.verify is True
        and session.auth is None
    )
    assert all(
        kwargs == {"allow_redirects": False, "timeout": (5, 30), "stream": True}
        for _, kwargs in session.calls
    )
    assert len(session.calls) == 7
    assert len(updates) == 8


@pytest.mark.parametrize(
    "value", ["1.2beta", " 1.2", "1.2 ", "+1.2", "1..2", "1.2.3.4.5", "１.２", 1.2, True, None]
)
def test_numeric_versions_never_guess_suffixes_or_normalize_unknown_formats(value):
    with pytest.raises(catalog.CatalogError):
        catalog.numeric_version(value)


def test_numeric_version_keeps_component_count_and_parses_vendor_leading_zero():
    assert catalog.numeric_version("25.01", 2) == (25, 1)
    assert catalog.numeric_version("152.0.4191.52", 4) == (152, 0, 4191, 52)
    with pytest.raises(catalog.CatalogError):
        catalog.numeric_version("152.0.4191", 4)


def test_exact_windows_product_takes_precedence_over_generic_chromium_range():
    record = cna()
    generic = copy.deepcopy(record["containers"]["cna"]["affected"][0])
    generic["product"] = "Microsoft Edge (Chromium-based)"
    generic["versions"][0]["lessThan"] = "152.0.4191.53"
    record["containers"]["cna"]["affected"].append(generic)
    entry = catalog._parse_cna(record, EDGE_CVE, "edge-windows", discovery())
    assert entry["source_product"] == "Microsoft Edge for Windows"
    assert entry["affected_ranges"] == [{"introduced": "1.0.0.0", "fixed": "152.0.4191.52"}]


def test_explicit_desktop_generic_product_is_retained_when_no_windows_product_exists():
    entry = catalog._parse_cna(cna(windows=False), EDGE_CVE, "edge-windows", discovery())
    assert entry["source_product"] == "Microsoft Edge (Chromium-based)"


def test_upstream_chromium_and_other_component_titles_do_not_expand_edge_scope():
    document = monthly_document("2026-Nov")
    for number, title in enumerate(
        ("Chromium CVE-2026-100202: Synthetic upstream issue", "Windows Shell security issue"),
        202,
    ):
        other = copy.deepcopy(document["Vulnerability"][0])
        other["CVE"] = f"CVE-2026-100{number}"
        other["Title"]["Value"] = title
        document["Vulnerability"].append(other)
    expected = {
        "initial": catalog.msrc._timestamp(
            document["DocumentTracking"]["InitialReleaseDate"], source=True
        ),
        "current": catalog.msrc._timestamp(
            document["DocumentTracking"]["CurrentReleaseDate"], source=True
        ),
    }
    updates = []
    found = catalog._discover_edge(document, "2026-Nov", expected, progress=updates.append)
    assert set(found) == {EDGE_CVE}
    assert "excluded 2" in updates[0]


@pytest.mark.parametrize(
    "change",
    [
        "provider",
        "cve",
        "state",
        "empty_interval",
        "unaffected",
        "wildcard",
        "inclusive",
        "changes",
        "platform",
        "wrong_product",
        "conflict",
        "empty_versions",
    ],
)
def test_unsupported_or_conflicting_cna_semantics_remain_unavailable(change):
    record = cna()
    item = record["containers"]["cna"]["affected"][0]
    version = item["versions"][0]
    if change == "provider":
        record["containers"]["cna"]["providerMetadata"]["orgId"] = "untrusted"
    elif change == "cve":
        record["cveMetadata"]["cveId"] = "CVE-2026-9999"
    elif change == "state":
        record["cveMetadata"]["state"] = "REJECTED"
    elif change == "empty_interval":
        version["version"] = version["lessThan"]
    elif change == "unaffected":
        version["status"] = "unaffected"
    elif change == "wildcard":
        version["lessThan"] = "152.*"
    elif change == "inclusive":
        version["lessThanOrEqual"] = version.pop("lessThan")
    elif change == "changes":
        version["changes"] = [{"at": "2.0.0.0", "status": "unaffected"}]
    elif change == "platform":
        item["platforms"] = ["Linux"]
    elif change == "wrong_product":
        item["product"] = "Microsoft Edge for Android"
    elif change == "empty_versions":
        item["versions"] = []
    else:
        other = copy.deepcopy(item)
        other["versions"][0]["lessThan"] = "152.0.4191.99"
        record["containers"]["cna"]["affected"].append(other)
    assert catalog._parse_cna(record, EDGE_CVE, "edge-windows", discovery()) is None


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"cveMetadata": []},
        {"cveMetadata": {}, "containers": []},
        {"cveMetadata": {}, "containers": {"cna": None}},
        None,
        [],
    ],
)
def test_malformed_cna_containers_are_unavailable_without_parser_crashes(record):
    assert catalog._parse_cna(record, EDGE_CVE, "edge-windows", discovery()) is None


def test_unavailable_cna_is_visible_and_never_becomes_an_implicit_affected_range(monkeypatch):
    session = fixture_session(monkeypatch)
    record = cna()
    record["containers"]["cna"]["affected"][0]["versions"][0]["status"] = "unaffected"
    session.replies[catalog.cve_url(EDGE_CVE)] = Response(record)
    result = catalog.build_catalog(now=NOW)
    coverage = next(item for item in result["coverage"] if item["product_key"] == "edge-windows")
    assert coverage["discovered"] == 1 and coverage["parsed"] == 0
    assert coverage["unavailable_cves"] == [EDGE_CVE]
    assert [entry["product_key"] for entry in result["entries"]] == ["7zip-windows"]


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "rules",
        "hash",
        "url",
        "missing_month",
        "missing_vendor",
        "missing_cna",
        "foreign_reference",
        "duplicate",
        "range",
        "coverage_count",
        "coverage_overlap",
        "scope_cve",
        "timestamp",
        "extra",
        "bad_source_product",
    ],
)
def test_persisted_catalog_rejects_drift(change):
    data = catalog_fixture()
    if change == "source":
        data["source"] = "arbitrary"
    elif change == "rules":
        data["rules_version"] = "future"
    elif change == "hash":
        data["documents"][0]["sha256"] = "a" * 63
    elif change == "url":
        data["documents"][1]["url"] = "http://169.254.169.254/private"
    elif change == "missing_month":
        data["documents"].pop(0)
    elif change == "missing_vendor":
        data["documents"].pop(3)
    elif change == "missing_cna":
        data["entries"][0]["document_ids"].remove(f"cve:{EDGE_CVE}")
    elif change == "foreign_reference":
        data["entries"][0]["source_urls"].append("https://example.test/advisory")
    elif change == "duplicate":
        data["entries"].append(copy.deepcopy(data["entries"][0]))
    elif change == "range":
        data["entries"][0]["affected_ranges"][0]["introduced"] = "152.0.4191.52"
    elif change == "coverage_count":
        data["coverage"][0]["parsed"] = 0
    elif change == "coverage_overlap":
        data["coverage"][0]["unavailable_cves"] = [EDGE_CVE]
    elif change == "scope_cve":
        data["entries"][1]["cve"] = "CVE-2025-9999"
    elif change == "timestamp":
        data["retrieved_at"] = "2026-11-07T12:00:00"
    elif change == "bad_source_product":
        data["entries"][0]["source_product"] = []
    else:
        data["extra"] = True
    with pytest.raises(catalog.CatalogError):
        catalog.validate_catalog(data)


def test_validation_is_deterministic_and_does_not_mutate_input():
    data = catalog_fixture()
    before = copy.deepcopy(data)
    assert catalog.validate_catalog(data) == catalog.validate_catalog(copy.deepcopy(data))
    assert data == before


def test_source_failure_stops_build_and_never_returns_a_partial_new_catalog(monkeypatch):
    session = fixture_session(monkeypatch)
    monkeypatch.setattr(catalog.time, "sleep", lambda *_args: None)
    session.replies[catalog.cve_url(EDGE_CVE)] = Response({}, status=503)
    with pytest.raises(catalog.CatalogError, match="three attempts"):
        catalog.build_catalog(now=NOW)
    assert all(url != catalog.HISTORY_URL for url, _ in session.calls)


def test_missing_official_cve_record_is_unavailable_without_fabricating_a_document_hash(
    monkeypatch,
):
    session = fixture_session(monkeypatch)
    session.replies[catalog.cve_url(EDGE_CVE)] = Response({}, status=404)
    result = catalog.build_catalog(now=NOW)
    edge = next(item for item in result["coverage"] if item["product_key"] == "edge-windows")
    assert edge["discovered"] == 1 and edge["parsed"] == 0
    assert edge["unavailable_cves"] == [EDGE_CVE]
    assert f"cve:{EDGE_CVE}" not in {item["id"] for item in result["documents"]}


def test_total_import_deadline_prevents_any_further_request():
    session = Session({})
    with pytest.raises(catalog.CatalogError, match="total time limit"):
        catalog._get_source(session, f"cve:{EDGE_CVE}", deadline=0)
    assert session.calls == []


def test_history_must_associate_curated_cve_with_the_expected_fixed_release(monkeypatch):
    session = fixture_session(monkeypatch)
    session.replies[catalog.HISTORY_URL] = Response(
        b"25.01          2025-08-03\n-------------------------\n- Changes.\n"
        b"25.00          2025-07-05\n-------------------------\n- CVE-2025-55188\n",
        raw=True,
        content_type="text/plain",
    )
    with pytest.raises(catalog.CatalogError, match="vendor release evidence"):
        catalog.build_catalog(now=NOW)


def test_generated_endpoints_reject_external_redirects_and_bound_bytes():
    url = catalog.cve_url(EDGE_CVE)
    session = Session({url: Response({}, status=302)})
    with pytest.raises(catalog.CatalogError):
        catalog._get_source(session, f"cve:{EDGE_CVE}")
    assert len(session.calls) == 1
    with pytest.raises(catalog.CatalogError):
        catalog._get_source(session, "https://example.test/source")
    assert len(session.calls) == 1


def test_tls_failures_are_not_retried_and_transient_retries_are_bounded(monkeypatch):
    url = catalog.cve_url(EDGE_CVE)
    session = Session({url: requests.exceptions.SSLError("synthetic")})
    with pytest.raises(catalog.CatalogError, match="TLS"):
        catalog._get_source(session, f"cve:{EDGE_CVE}")
    assert len(session.calls) == 1
    monkeypatch.setattr(catalog.time, "sleep", lambda *_args: None)
    session = Session({url: requests.Timeout()})
    with pytest.raises(catalog.CatalogError, match="three attempts"):
        catalog._get_source(session, f"cve:{EDGE_CVE}")
    assert len(session.calls) == 3


def test_sync_does_not_touch_database_when_fetch_fails(monkeypatch):
    from app.services import software_catalog_sync as sync

    def fail(**_kwargs):
        raise catalog.CatalogError("Synthetic fetch failure")

    monkeypatch.setattr(catalog, "build_catalog", fail)
    with pytest.raises(catalog.CatalogError):
        sync.synchronize_catalog(object())


def test_sync_canonicalization_and_validation_precede_database_access():
    from app.services import software_catalog_sync as sync

    data = catalog_fixture()
    normalized = sync.validated_catalog(data)
    assert sync.catalog_digest(normalized) == sync.catalog_digest(
        sync.validated_catalog(copy.deepcopy(data))
    )
    with pytest.raises(ValueError):
        sync.canonical_bytes({"oversized": "x" * 100}, limit=10)
    data["rules_version"] = "arbitrary"
    with pytest.raises(catalog.CatalogError):
        sync.store_catalog(object(), data)
