"""Synthetic CVRF fixtures; unit tests never contact Microsoft or a target host."""

import copy
import json
from datetime import UTC, datetime

import pytest
import requests

from app.services import windows_patch_catalog as catalog

NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)
INITIAL = {"2026-Sep": "2026-09-08", "2026-Oct": "2026-10-13", "2026-Nov": "2026-11-04"}


def document(identifier, *, empty=False):
    initial = INITIAL[identifier] + "T07:00:00"
    return {
        "DocumentTracking": {
            "Identification": {"ID": {"Value": identifier}},
            "InitialReleaseDate": initial,
            "CurrentReleaseDate": "2026-11-05T08:00:00",
        },
        "ProductTree": {
            "FullProductName": [
                {"ProductID": "11923", "Value": "Windows Server 2022"},
                {"ProductID": "11924", "Value": "Windows Server 2022 (Server Core installation)"},
                {"ProductID": "999", "Value": "Unsupported synthetic application"},
            ]
        },
        "Vulnerability": (
            []
            if empty
            else [
                {
                    "CVE": "CVE-2026-100201",
                    "Title": {"Value": "Synthetic OS security reference"},
                    "ProductStatuses": [{"Type": 3, "ProductID": ["11923", "11924"]}],
                    "Remediations": [
                        {
                            "Type": 2,
                            "ProductID": ["11923", "11924"],
                            "SubType": "Security Update",
                            "Description": {"Value": "5010000"},
                            "FixedBuild": "10.0.20348.5761",
                            "URL": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5010000",
                        }
                    ],
                    "Threats": [
                        {
                            "Type": 3,
                            "ProductID": ["11923", "11924"],
                            "Description": {"Value": "Important"},
                        }
                    ],
                    "CVSSScoreSets": [{"BaseScore": 7.5, "ProductID": ["11923", "11924"]}],
                }
            ]
        ),
    }


def index(identifiers=("2026-Nov", "2026-Sep", "2026-Oct")):
    return {
        "value": [
            {
                "ID": identifier,
                "InitialReleaseDate": INITIAL[identifier] + "T07:00:00Z",
                "CurrentReleaseDate": "2026-11-05T08:00:00Z",
                "CvrfUrl": f"{catalog.API}/cvrf/{identifier}",
            }
            for identifier in identifiers
        ]
    }


class Response:
    def __init__(self, data, *, status=200, content_type="application/json", raw=False):
        self.status_code = status
        self.headers = {"Content-Type": content_type}
        self.content = data if raw else json.dumps(data).encode()
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def iter_content(self, size):
        for offset in range(0, len(self.content), size):
            yield self.content[offset : offset + size]


class Session:
    def __init__(self, replies):
        self.replies, self.calls, self.headers = replies, [], {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        result = self.replies[url]
        if isinstance(result, list):
            result = result.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def fixture_session(monkeypatch, *, documents=None, update_index=None):
    docs = documents or {
        identifier: document(identifier, empty=identifier == "2026-Nov") for identifier in INITIAL
    }
    session = Session(
        {
            f"{catalog.API}/updates": Response(update_index or index()),
            **{f"{catalog.API}/cvrf/{key}": Response(value) for key, value in docs.items()},
        }
    )
    monkeypatch.setattr(catalog.requests, "Session", lambda: session)
    return session


def normalized(monkeypatch):
    fixture_session(monkeypatch)
    return catalog.fetch_catalog(now=NOW)


def test_fetch_uses_all_published_months_in_order_and_preserves_empty_early_current_feed(
    monkeypatch,
):
    session = fixture_session(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.example.test:8080")
    monkeypatch.setenv("NETRC", "/untrusted/netrc")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/untrusted/ca.pem")
    updates = []
    result = catalog.fetch_catalog(now=NOW, progress=updates.append)
    assert [doc["id"] for doc in result["documents"]] == ["2026-Sep", "2026-Oct", "2026-Nov"]
    assert result["coverage_start"] == "2026-09-01" and result["coverage_end"] == "2026-11-07"
    assert len(result["entries"]) == 4
    assert {entry["document_id"] for entry in result["entries"]} == {"2026-Sep", "2026-Oct"}
    assert result["entries"][0]["severity"] == "high"
    assert result["entries"][0]["cvss_score"] == "7.5"
    assert result["entries"][0]["kb"] == "KB5010000"
    assert result["entries"][0]["source_url"] == catalog.CVE_URL + "CVE-2026-100201"
    assert session.trust_env is False and session.proxies == {} and session.verify is True
    assert session.auth is None and session.headers["Accept"] == "application/json"
    assert [url for url, _ in session.calls] == [
        f"{catalog.API}/updates",
        *(f"{catalog.API}/cvrf/{key}" for key in ("2026-Sep", "2026-Oct", "2026-Nov")),
    ]
    assert all(
        kwargs == {"allow_redirects": False, "timeout": (5, 30), "stream": True}
        for _, kwargs in session.calls
    )
    assert len(updates) == 3


def test_pre_patch_tuesday_missing_current_month_bounds_coverage_at_last_published_month(
    monkeypatch,
):
    fixture_session(monkeypatch)
    result = catalog.fetch_catalog(now=datetime(2026, 12, 1, tzinfo=UTC))
    assert result["coverage_start"] == "2026-10-01"
    assert result["coverage_end"] == "2026-11-30"
    assert [item["id"] for item in result["documents"]] == ["2026-Oct", "2026-Nov"]


@pytest.mark.parametrize("value", [0, 13, True, "3", None])
def test_invalid_month_windows_are_rejected_before_network(monkeypatch, value):
    monkeypatch.setattr(catalog.requests, "Session", lambda: pytest.fail("Session created"))
    with pytest.raises(catalog.CatalogError, match="one to twelve"):
        catalog.fetch_catalog(months=value, now=NOW)


@pytest.mark.parametrize("change", ["gap", "duplicate", "external_url", "unknown_identity"])
def test_index_is_validated_before_following_any_document_url(monkeypatch, change):
    data = index()
    if change == "gap":
        data["value"].pop(1)
    elif change == "duplicate":
        data["value"].append(copy.deepcopy(data["value"][0]))
    elif change == "external_url":
        data["value"][0]["CvrfUrl"] = "http://169.254.169.254/private"
    else:
        data["value"][0]["ID"] = "2026-Nov-extra"
    session = fixture_session(monkeypatch, update_index=data)
    with pytest.raises(catalog.CatalogError):
        catalog.fetch_catalog(now=NOW)
    assert len(session.calls) == 1


def test_hotpatch_non_os_and_unaffected_rows_are_counted_without_becoming_baselines(monkeypatch):
    docs = {key: document(key, empty=True) for key in INITIAL}
    doc = document("2026-Oct")
    original = doc["Vulnerability"][0]["Remediations"][0]
    doc["Vulnerability"][0]["Remediations"] = [
        original,
        {**original, "SubType": "AzureHotpatch", "FixedBuild": "10.0.20348.9999"},
        {**original, "FixedBuild": "4.8.9999"},
        {**original, "FixedBuild": None},
        {**original, "ProductID": ["999"]},
    ]
    not_affected = copy.deepcopy(doc["Vulnerability"][0])
    not_affected["ProductStatuses"][0]["Type"] = 4
    doc["Vulnerability"].append(not_affected)
    docs["2026-Oct"] = doc
    fixture_session(monkeypatch, documents=docs)
    result = catalog.fetch_catalog(now=NOW)
    assert len(result["entries"]) == 2
    assert result["statistics"]["excluded_nonstandard_update"] == 2
    assert result["statistics"]["excluded_non_os_build"] == 2
    assert result["statistics"]["excluded_missing_fixed_build"] == 2
    assert result["statistics"]["excluded_not_affected"] == 8
    assert result["statistics"]["excluded_unsupported_product"] == 2


@pytest.mark.parametrize("change", ["id", "product", "cve", "kb", "revision", "score"])
def test_supported_os_identity_or_release_corruption_rejects_the_entire_import(monkeypatch, change):
    docs = {key: document(key, empty=True) for key in INITIAL}
    doc = document("2026-Oct")
    if change == "id":
        doc["DocumentTracking"]["Identification"]["ID"]["Value"] = "2026-Nov"
    elif change == "product":
        doc["ProductTree"]["FullProductName"][0]["ProductID"] = "999"
    elif change == "cve":
        doc["Vulnerability"][0]["CVE"] = "ADV-unsupported"
    elif change == "kb":
        doc["Vulnerability"][0]["Remediations"][0]["Description"]["Value"] = "not-a-KB"
    elif change == "score":
        doc["Vulnerability"][0]["CVSSScoreSets"][0]["BaseScore"] = float("nan")
    else:
        doc["DocumentTracking"]["CurrentReleaseDate"] = "2026-11-04T08:00:00"
    docs["2026-Oct"] = doc
    fixture_session(monkeypatch, documents=docs)
    with pytest.raises(catalog.CatalogError):
        catalog.fetch_catalog(now=NOW)


@pytest.mark.parametrize(
    "change",
    [
        "hash",
        "url",
        "missing_month",
        "wrong_build",
        "foreign_product",
        "duplicate",
        "timestamp",
        "extra",
        "stats",
        "source_url",
    ],
)
def test_persisted_catalog_validation_rejects_drift(monkeypatch, change):
    data = normalized(monkeypatch)
    if change == "hash":
        data["documents"][0]["sha256"] = "a" * 63
    elif change == "url":
        data["documents"][0]["url"] = "https://api.msrc.microsoft.com.evil.test/cvrf/2026-Sep"
    elif change == "missing_month":
        data["documents"].pop()
    elif change == "wrong_build":
        data["entries"][0]["fixed_build"] = "10.0.26100.9999"
    elif change == "foreign_product":
        data["entries"][0]["product_name"] = "Windows Server 2025"
    elif change == "duplicate":
        data["entries"].append(copy.deepcopy(data["entries"][0]))
    elif change == "timestamp":
        data["retrieved_at"] = "2026-11-07T12:00:00"
    elif change == "extra":
        data["arbitrary_source_url"] = "http://localhost/private"
    elif change == "source_url":
        data["entries"][0]["source_url"] = "https://example.test/CVE-2026-100201"
    else:
        data["statistics"]["entries"] += 1
    with pytest.raises(catalog.CatalogError):
        catalog.validate_catalog(data)


@pytest.mark.parametrize(
    "reply",
    [
        Response({}, status=302),
        Response({}, status=401),
        Response({}, content_type="application/xml"),
        Response(b"{unfinished", raw=True),
        Response([], content_type="application/json"),
    ],
)
def test_http_failure_redirect_and_invalid_content_fail_without_followup_or_retry(reply):
    session = Session({f"{catalog.API}/updates": reply})
    with pytest.raises(catalog.CatalogError):
        catalog._get_json(session, f"{catalog.API}/updates", catalog.MAX_INDEX)
    assert len(session.calls) == 1


def test_request_retries_are_bounded_and_tls_failure_does_not_retry(monkeypatch):
    monkeypatch.setattr(catalog.time, "sleep", lambda *_args: None)
    url = f"{catalog.API}/updates"
    session = Session(
        {url: [requests.Timeout(), Response({}, status=503), Response({"value": []})]}
    )
    assert catalog._get_json(session, url, catalog.MAX_INDEX)[0] == {"value": []}
    assert len(session.calls) == 3
    session = Session({url: requests.ConnectionError()})
    with pytest.raises(catalog.CatalogError, match="three attempts"):
        catalog._get_json(session, url, catalog.MAX_INDEX)
    assert len(session.calls) == 3
    session = Session({url: requests.exceptions.SSLError("untrusted")})
    with pytest.raises(catalog.CatalogError, match="TLS verification"):
        catalog._get_json(session, url, catalog.MAX_INDEX)
    assert len(session.calls) == 1


def test_byte_limit_applies_to_streamed_body_and_endpoint_cannot_be_substituted():
    url = f"{catalog.API}/updates"
    session = Session({url: Response({"large": "x" * 100})})
    with pytest.raises(catalog.CatalogError, match="size limit"):
        catalog._get_json(session, url, 20)
    with pytest.raises(catalog.CatalogError, match="endpoint"):
        catalog._get_json(session, "http://169.254.169.254/private", catalog.MAX_INDEX)
    assert len(session.calls) == 1


def test_validation_is_deterministic_and_never_rewrites_its_input(monkeypatch):
    data = normalized(monkeypatch)
    before = copy.deepcopy(data)
    assert catalog.validate_catalog(data) == catalog.validate_catalog(copy.deepcopy(data))
    assert data == before
    assert data["statistics"]["entries"] == len(data["entries"])
