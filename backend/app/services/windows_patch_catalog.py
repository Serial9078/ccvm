"""Bounded Microsoft CVRF imports for standard Windows Server OS baselines.

This is a catalog of published cumulative-update build references. It is not an
applicability engine, a software-name matcher or a proof of CVE exploitability.
"""

import calendar
import hashlib
import json
import math
import re
import time
from datetime import UTC, date, datetime, timedelta

import requests

API = "https://api.msrc.microsoft.com/cvrf/v3.0"
CVE_URL = "https://msrc.microsoft.com/update-guide/vulnerability/"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
MAX_DOCUMENT = 64 * 1024 * 1024
MAX_INDEX = 2 * 1024 * 1024
MAX_ENTRIES = 100000
MAX_VULNERABILITIES = 20000
PRODUCTS = {
    "Windows Server 2016": ("10816", 14393),
    "Windows Server 2016 (Server Core installation)": ("10855", 14393),
    "Windows Server 2019": ("11571", 17763),
    "Windows Server 2019 (Server Core installation)": ("11572", 17763),
    "Windows Server 2022": ("11923", 20348),
    "Windows Server 2022 (Server Core installation)": ("11924", 20348),
    "Windows Server 2025": ("12436", 26100),
    "Windows Server 2025 (Server Core installation)": ("12437", 26100),
}
SEVERITIES = {"Critical": "critical", "Important": "high", "Moderate": "medium", "Low": "low"}


class CatalogError(ValueError):
    pass


def _text(value, maximum=512):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise CatalogError("Invalid Microsoft catalog text field")
    return value


def _timestamp(value, *, source=False):
    try:
        result = datetime.fromisoformat(_text(value, 50).replace("Z", "+00:00"))
    except ValueError:
        raise CatalogError("Invalid Microsoft catalog timestamp") from None
    if result.tzinfo is None:
        if not source:
            raise CatalogError("Catalog timestamps must include their timezone")
        # CVRF JSON uses UTC values without a suffix; its update index uses Z.
        result = result.replace(tzinfo=UTC)
    return result.astimezone(UTC)


def _day(value):
    try:
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise ValueError
        return date.fromisoformat(value)
    except ValueError:
        raise CatalogError("Invalid Microsoft catalog coverage date") from None


def _document_month(identifier):
    match = re.fullmatch(r"(\d{4})-([A-Z][a-z]{2})", _text(identifier, 8))
    if not match or match[2] not in MONTHS:
        raise CatalogError("Invalid Microsoft CVRF document identity")
    try:
        return date(int(match[1]), MONTHS.index(match[2]) + 1, 1)
    except ValueError:
        raise CatalogError("Invalid Microsoft CVRF document identity") from None


def _month_ids(start, end):
    result = []
    index = start.year * 12 + start.month - 1
    last = end.year * 12 + end.month - 1
    while index <= last:
        year, month = divmod(index, 12)
        result.append(f"{year:04d}-{MONTHS[month]}")
        index += 1
    return result


def _array(value, maximum, label):
    if not isinstance(value, list) or len(value) > maximum:
        raise CatalogError(f"Invalid or oversized Microsoft {label}")
    return value


def _ids(value):
    result = _array(value, 10000, "product identifier list")
    if any(
        not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", item)
        for item in result
    ):
        raise CatalogError("Invalid Microsoft product identifier")
    return result


def _value(container, field):
    value = container.get(field)
    if not isinstance(value, dict):
        raise CatalogError("Invalid Microsoft CVRF field")
    return value.get("Value")


def _build(value, product_name):
    match = re.fullmatch(r"10\.0\.(\d{1,6})\.(\d{1,9})", _text(value, 40))
    if not match or int(match[1]) != PRODUCTS[product_name][1]:
        raise CatalogError("Fixed build does not match the supported OS product")
    return f"10.0.{int(match[1])}.{int(match[2])}"


def _score(value):
    if isinstance(value, bool):
        raise CatalogError("Invalid Microsoft CVSS score")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise CatalogError("Invalid Microsoft CVSS score") from None
    if not math.isfinite(number) or not 0 <= number <= 10:
        raise CatalogError("Invalid Microsoft CVSS score")
    return str(number)


def validate_catalog(data):
    """Validate imported or persisted evidence without network access or mutation."""
    if (
        not isinstance(data, dict)
        or type(data.get("schema_version")) is not int
        or data["schema_version"] != 1
    ):
        raise CatalogError("Unsupported Windows patch catalog format")
    required = {
        "schema_version",
        "source",
        "retrieved_at",
        "coverage_start",
        "coverage_end",
        "documents",
        "entries",
    }
    if (
        set(data) - required - {"statistics"}
        or required - set(data)
        or data["source"] != "msrc-cvrf"
    ):
        raise CatalogError("Invalid Windows patch catalog metadata")
    retrieved = _timestamp(data["retrieved_at"])
    start, end = _day(data["coverage_start"]), _day(data["coverage_end"])
    if start.day != 1 or end < start or end > retrieved.date():
        raise CatalogError("Invalid Windows patch catalog coverage window")
    identifiers = _month_ids(start, end)
    if len(identifiers) > 12:
        raise CatalogError("Catalog coverage exceeds twelve months")
    documents = []
    seen = set()
    for item in _array(data["documents"], 12, "document list"):
        if not isinstance(item, dict) or set(item) != {
            "id",
            "url",
            "sha256",
            "current_release_date",
            "initial_release_date",
        }:
            raise CatalogError("Invalid Windows patch source document")
        identifier = item["id"]
        _document_month(identifier)
        if identifier in seen or identifier not in identifiers:
            raise CatalogError("Duplicate or out-of-window CVRF document")
        if item["url"] != f"{API}/cvrf/{identifier}" or not re.fullmatch(
            r"[0-9a-f]{64}", _text(item["sha256"], 64)
        ):
            raise CatalogError("Invalid Microsoft source URL or digest")
        initial = _timestamp(item["initial_release_date"])
        current = _timestamp(item["current_release_date"])
        if (
            not start <= initial.date() <= end
            or current < initial
            or current > retrieved + timedelta(minutes=5)
        ):
            raise CatalogError("Invalid Microsoft source release dates")
        documents.append(
            {
                **item,
                "initial_release_date": initial.isoformat(),
                "current_release_date": current.isoformat(),
            }
        )
        seen.add(identifier)
    if seen != set(identifiers):
        raise CatalogError("Catalog is missing a document inside its stated coverage")
    entries = []
    identities = set()
    for item in _array(data["entries"], MAX_ENTRIES, "entry list"):
        fields = {
            "product_id",
            "product_name",
            "cve",
            "title",
            "severity",
            "kb",
            "fixed_build",
            "document_id",
            "source_url",
            "subtype",
        }
        if not isinstance(item, dict) or fields - set(item) or set(item) - fields - {"cvss_score"}:
            raise CatalogError("Invalid Windows baseline entry")
        name = item["product_name"]
        if (
            not isinstance(name, str)
            or name not in PRODUCTS
            or item["product_id"] != PRODUCTS[name][0]
        ):
            raise CatalogError("Unsupported or mismatched Windows product identity")
        if (
            not re.fullmatch(r"CVE-\d{4}-\d{4,19}", _text(item["cve"], 40))
            or not re.fullmatch(r"KB\d{4,10}", _text(item["kb"], 12))
            or not isinstance(item["document_id"], str)
            or item["document_id"] not in seen
            or item["source_url"] != CVE_URL + item["cve"]
            or item["subtype"] != "Security Update"
            or not isinstance(item["severity"], str)
            or item["severity"] not in {*SEVERITIES.values(), "unknown"}
        ):
            raise CatalogError("Invalid Windows baseline reference")
        entry = {
            **item,
            "title": _text(item["title"]),
            "fixed_build": _build(item["fixed_build"], name),
        }
        if "cvss_score" in entry:
            entry["cvss_score"] = _score(entry["cvss_score"])
        identity = tuple(
            entry[k] for k in ("document_id", "product_id", "cve", "kb", "fixed_build")
        )
        if identity in identities:
            raise CatalogError("Duplicate Windows baseline reference")
        identities.add(identity)
        entries.append(entry)
    result = {
        "schema_version": 1,
        "source": "msrc-cvrf",
        "retrieved_at": retrieved.isoformat(),
        "coverage_start": start.isoformat(),
        "coverage_end": end.isoformat(),
        "documents": sorted(documents, key=lambda item: _document_month(item["id"])),
        "entries": sorted(
            entries,
            key=lambda item: (
                item["product_id"],
                item["cve"],
                item["fixed_build"],
                item["kb"],
                item["document_id"],
            ),
        ),
    }
    if "statistics" in data:
        stats = data["statistics"]
        if (
            not isinstance(stats, dict)
            or len(stats) > 32
            or any(
                not isinstance(key, str)
                or not re.fullmatch(r"[a-z_]{1,50}", key)
                or type(value) is not int
                or not 0 <= value <= 10000000
                for key, value in stats.items()
            )
            or stats.get("entries", len(entries)) != len(entries)
        ):
            raise CatalogError("Invalid Microsoft catalog import statistics")
        result["statistics"] = dict(sorted(stats.items()))
    return result


def _get_json(session, url, maximum):
    """Only callers construct these fixed Microsoft URLs; never follow redirects."""
    if url != f"{API}/updates":
        prefix = f"{API}/cvrf/"
        if not url.startswith(prefix):
            raise CatalogError("Unsupported Microsoft catalog endpoint")
        _document_month(url[len(prefix) :])
    for attempt in range(3):
        try:
            started = time.monotonic()
            with session.get(url, allow_redirects=False, timeout=(5, 30), stream=True) as response:
                if response.status_code in {429, 500, 502, 503, 504}:
                    raise requests.ConnectionError("Microsoft catalog temporarily unavailable")
                if response.status_code != 200:
                    raise CatalogError("Microsoft catalog request did not return HTTP 200")
                if (
                    response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                    != "application/json"
                ):
                    raise CatalogError("Microsoft catalog response was not JSON")
                content = bytearray()
                for part in response.iter_content(65536):
                    if time.monotonic() - started > 120:
                        raise CatalogError("Microsoft catalog response exceeded its time limit")
                    content.extend(part)
                    if len(content) > maximum:
                        raise CatalogError("Microsoft catalog response exceeded its size limit")
                try:
                    document = json.loads(content)
                except (ValueError, UnicodeError, RecursionError):
                    raise CatalogError("Microsoft catalog response contains invalid JSON") from None
                if not isinstance(document, dict):
                    raise CatalogError("Microsoft catalog response has invalid structure")
                return document, hashlib.sha256(content).hexdigest()
        except requests.exceptions.SSLError:
            raise CatalogError("Microsoft catalog TLS verification failed") from None
        except (requests.Timeout, requests.ConnectionError):
            if attempt == 2:
                raise CatalogError(
                    "Microsoft catalog request failed after three attempts"
                ) from None
            time.sleep(0.25 * (attempt + 1))
        except requests.RequestException:
            raise CatalogError("Microsoft catalog response could not be read safely") from None
    raise CatalogError("Microsoft catalog request failed")


def _parse_document(document, identifier, expected, digest, statistics):
    tracking = document.get("DocumentTracking")
    if not isinstance(tracking, dict) or not isinstance(tracking.get("Identification"), dict):
        raise CatalogError("Missing Microsoft document identity")
    if _value(tracking["Identification"], "ID") != identifier:
        raise CatalogError("Microsoft document identity changed")
    initial = _timestamp(tracking.get("InitialReleaseDate"), source=True)
    current = _timestamp(tracking.get("CurrentReleaseDate"), source=True)
    if initial != expected["initial"] or current < expected["current"]:
        raise CatalogError("Microsoft document release metadata regressed or changed")
    tree = document.get("ProductTree")
    if not isinstance(tree, dict):
        raise CatalogError("Missing Microsoft product tree")
    products, all_products = {}, {}
    for item in _array(tree.get("FullProductName"), 10000, "product tree"):
        if not isinstance(item, dict):
            raise CatalogError("Invalid Microsoft product identity")
        name, product_id = item.get("Value"), item.get("ProductID")
        _text(name, 1024)
        _ids([product_id])
        if product_id in all_products:
            raise CatalogError("Duplicate Microsoft product identity")
        all_products[product_id] = name
        if name in PRODUCTS:
            if product_id != PRODUCTS[name][0] or product_id in products:
                raise CatalogError("Supported Microsoft product identity changed or duplicated")
            products[product_id] = name
    entries = {}
    for vulnerability in _array(
        document.get("Vulnerability"), MAX_VULNERABILITIES, "vulnerability list"
    ):
        statistics["vulnerabilities_seen"] += 1
        if not isinstance(vulnerability, dict):
            raise CatalogError("Invalid Microsoft vulnerability record")
        affected = set()
        for status in _array(vulnerability.get("ProductStatuses", []), 100, "product statuses"):
            if not isinstance(status, dict):
                raise CatalogError("Invalid Microsoft product status")
            if status.get("Type") == 3:
                affected.update(_ids(status.get("ProductID")))
        for remediation in _array(vulnerability.get("Remediations", []), 10000, "remediation list"):
            if not isinstance(remediation, dict):
                raise CatalogError("Invalid Microsoft remediation")
            if remediation.get("Type") != 2:
                continue
            product_ids = set(_ids(remediation.get("ProductID", [])))
            supported = product_ids & products.keys()
            statistics["excluded_unsupported_product"] += len(product_ids - products.keys())
            for product_id in sorted(supported):
                if product_id not in affected:
                    statistics["excluded_not_affected"] += 1
                    continue
                if remediation.get("SubType") != "Security Update":
                    statistics["excluded_nonstandard_update"] += 1
                    continue
                name = products[product_id]
                if not remediation.get("FixedBuild"):
                    statistics["excluded_missing_fixed_build"] += 1
                    continue
                try:
                    fixed = _build(remediation.get("FixedBuild"), name)
                except CatalogError:
                    statistics["excluded_non_os_build"] += 1
                    continue
                cve = _text(vulnerability.get("CVE"), 40)
                if not re.fullmatch(r"CVE-\d{4}-\d{4,19}", cve):
                    raise CatalogError("Invalid CVE identity in a supported OS remediation")
                kb = _text(_value(remediation, "Description"), 12)
                if not re.fullmatch(r"(?:KB)?\d{4,10}", kb):
                    raise CatalogError("Invalid KB identity in a supported OS remediation")
                severity = "unknown"
                for threat in _array(vulnerability.get("Threats", []), 10000, "threat list"):
                    if not isinstance(threat, dict):
                        raise CatalogError("Invalid Microsoft threat metadata")
                    if threat.get("Type") == 3 and product_id in _ids(threat.get("ProductID", [])):
                        severity = SEVERITIES.get(
                            _text(_value(threat, "Description"), 100), "unknown"
                        )
                scores = []
                for score in _array(vulnerability.get("CVSSScoreSets", []), 10000, "CVSS list"):
                    if not isinstance(score, dict):
                        raise CatalogError("Invalid Microsoft CVSS metadata")
                    if product_id in _ids(score.get("ProductID", [])):
                        scores.append(float(_score(score.get("BaseScore"))))
                entry = {
                    "product_id": product_id,
                    "product_name": name,
                    "cve": cve,
                    "title": _text(_value(vulnerability, "Title")),
                    "severity": severity,
                    "kb": kb if kb.startswith("KB") else "KB" + kb,
                    "fixed_build": fixed,
                    "document_id": identifier,
                    "source_url": CVE_URL + cve,
                    "subtype": "Security Update",
                }
                if scores:
                    entry["cvss_score"] = str(max(scores))
                key = (product_id, cve, entry["kb"], fixed)
                if key in entries and entries[key] != entry:
                    raise CatalogError("Conflicting Microsoft OS baseline references")
                entries[key] = entry
    metadata = {
        "id": identifier,
        "url": f"{API}/cvrf/{identifier}",
        "sha256": digest,
        "initial_release_date": initial.isoformat(),
        "current_release_date": current.isoformat(),
    }
    return metadata, list(entries.values())


def fetch_catalog(*, months=3, now=None, progress=None):
    """Fetch all published monthly documents in a bounded calendar window.

    The result is returned only after every selected document validates. Callers
    can therefore retain the preceding catalog unchanged on any import failure.
    """
    if type(months) is not int or not 1 <= months <= 12:
        raise CatalogError("Select one to twelve catalog months")
    now = now or datetime.now(UTC)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise CatalogError("Catalog import time must include its timezone")
    now = now.astimezone(UTC)
    index = now.year * 12 + now.month - months
    year, month = divmod(index, 12)
    start = date(year, month + 1, 1)
    statistics = dict.fromkeys(
        (
            "vulnerabilities_seen",
            "excluded_not_affected",
            "excluded_nonstandard_update",
            "excluded_non_os_build",
            "excluded_missing_fixed_build",
            "excluded_unsupported_product",
        ),
        0,
    )
    with requests.Session() as session:
        session.trust_env = False
        session.proxies = {}
        session.verify = True
        session.auth = None
        session.headers.update({"Accept": "application/json"})
        index_data, _ = _get_json(session, f"{API}/updates", MAX_INDEX)
        selected = {}
        seen = set()
        for item in _array(index_data.get("value"), 1000, "update index"):
            if not isinstance(item, dict):
                raise CatalogError("Invalid Microsoft update index record")
            identifier = item.get("ID")
            document_month = _document_month(identifier)
            if identifier in seen:
                raise CatalogError("Duplicate Microsoft update index identity")
            seen.add(identifier)
            # The index includes unrelated historical Mariner documents whose
            # revision timestamp can be the 1601 sentinel. Their metadata is
            # outside this catalog's evidence window and is never fetched.
            if not start <= document_month <= now.date():
                continue
            initial = _timestamp(item.get("InitialReleaseDate"), source=True)
            current = _timestamp(item.get("CurrentReleaseDate"), source=True)
            if current < initial or initial.date() < start:
                raise CatalogError("Invalid Microsoft update index dates")
            if initial.date() <= now.date():
                if item.get("CvrfUrl") != f"{API}/cvrf/{identifier}":
                    raise CatalogError("Microsoft update index contains a different source URL")
                selected[identifier] = {"initial": initial, "current": current}
        if not selected:
            raise CatalogError("No Microsoft documents cover the selected calendar window")
        last = max(_document_month(identifier) for identifier in selected)
        end = min(
            now.date(), date(last.year, last.month, calendar.monthrange(last.year, last.month)[1])
        )
        if set(selected) != set(_month_ids(start, end)):
            raise CatalogError("Microsoft update index has a gap in the selected calendar window")
        documents, entries = [], []
        for number, identifier in enumerate(sorted(selected, key=_document_month), 1):
            if progress:
                progress(f"Fetching Microsoft CVRF {identifier} ({number}/{len(selected)})")
            raw, digest = _get_json(session, f"{API}/cvrf/{identifier}", MAX_DOCUMENT)
            metadata, references = _parse_document(
                raw, identifier, selected[identifier], digest, statistics
            )
            # A monthly document can exceed 30 MiB. Release its full JSON tree
            # before fetching the next one; retain only bounded OS references.
            del raw
            documents.append(metadata)
            entries.extend(references)
            if len(entries) > MAX_ENTRIES:
                raise CatalogError("Microsoft OS baseline catalog has too many entries")
    statistics["entries"] = len(entries)
    return validate_catalog(
        {
            "schema_version": 1,
            "source": "msrc-cvrf",
            "retrieved_at": now.isoformat(),
            "coverage_start": start.isoformat(),
            "coverage_end": end.isoformat(),
            "documents": documents,
            "entries": entries,
            "statistics": statistics,
        }
    )
