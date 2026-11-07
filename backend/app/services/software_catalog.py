"""Bounded, explicit vendor version ranges for two Windows registry products.

Edge CVEs are discovered from the complete selected MSRC monthly window. The
7-Zip scope is deliberately one reviewed advisory, not its entire CVE history.
Unsupported CNA representations remain unavailable; no ranges are inferred from
titles, release dates, prose, CPE guesses or a vendor's latest release number.
"""

import calendar
import hashlib
import json
import re
import time
from datetime import UTC, date, datetime, timedelta

import requests

from app.services import windows_patch_catalog as msrc

CatalogError = msrc.CatalogError


class SourceRecordMissing(CatalogError):
    """The official fixed CVE URL definitively returned HTTP 404."""


API = msrc.API
CVE_ROOT = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
HISTORY_URL = "https://www.7-zip.org/history.txt"
RULES_VERSION = "windows-registry-v1"
SOURCE = "vendor-software-ranges"
SEVEN_CVE = "CVE-2025-55188"
MICROSOFT_CNA = ("f38d906d-7342-40ea-92c1-6c4a2c6478c8", "microsoft")
SEVEN_CNA = ("8254265b-2729-46b6-b9e3-3dfca2d5bfca", "mitre")
EDGE_NAMES = {"Microsoft Edge (Chromium-based)", "Microsoft Edge for Windows"}
EDGE_TITLE_PREFIXES = ("Microsoft Edge (Chromium-based) ", "Microsoft Edge for Windows ")
PRODUCTS = {
    "edge-windows": {
        "components": 4,
        "source_products": EDGE_NAMES,
        "scope": (
            "Edge-specific Microsoft-titled advisories with Microsoft CNA numeric ranges, "
            "discovered in the stated MSRC monthly window; upstream Chromium and "
            "other-component CVEs are excluded. Windows-specific product takes precedence "
            "over the generic Chromium desktop product."
        ),
    },
    "7zip-windows": {
        "components": 2,
        "source_products": {"7-Zip"},
        "scope": (
            "Curated advisory CVE-2025-55188 only; other 7-Zip advisories are not assessed. "
            "Windows exploitation requires extraction with symbolic-link creation privileges; "
            "those conditions are not verified by the version comparison."
        ),
    },
}
MAX_CVES = 1000
MAX_CNA_BYTES = 2 * 1024 * 1024
MAX_HISTORY_BYTES = 1024 * 1024
MAX_ENTRIES = MAX_CVES + 1
MAX_IMPORT_SECONDS = 20 * 60


def _text(value, maximum=1000):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(c) < 32 for c in value)
    ):
        raise CatalogError("Invalid software catalog text")
    return value


def numeric_version(value, components=None):
    """Parse digits and dots only, preserving vendor-specific component counts."""
    if components is not None and (type(components) is not int or not 1 <= components <= 4):
        raise CatalogError("Invalid software version component count")
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{1,9}(?:\.\d{1,9}){0,3}", value, flags=re.ASCII
    ):
        raise CatalogError("Unsupported software version format")
    result = tuple(int(part) for part in value.split("."))
    if components is not None and len(result) != components:
        raise CatalogError("Software version component count does not match its product")
    return result


def _cve(value):
    if not isinstance(value, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,9}", value, flags=re.ASCII):
        raise CatalogError("Invalid software CVE identity")
    return value


def cve_url(cve):
    year, number = _cve(cve).split("-")[1:]
    return f"{CVE_ROOT}/{year}/{number[:-3]}xxx/{cve}.json"


def _array(value, maximum, label):
    if not isinstance(value, list) or len(value) > maximum:
        raise CatalogError(f"Invalid or oversized software {label}")
    return value


def _range(item, product):
    if not isinstance(item, dict) or set(item) != {"introduced", "fixed"}:
        raise CatalogError("Invalid software affected range")
    count = PRODUCTS[product]["components"]
    fixed = numeric_version(item["fixed"], count)
    introduced = numeric_version(item["introduced"])
    if len(introduced) != count and item["introduced"] != "0":
        raise CatalogError("Unsupported affected-range lower bound")
    introduced += (0,) * (count - len(introduced))
    if introduced >= fixed:
        raise CatalogError("Software affected range must be nonempty")
    return dict(item)


def _range_keys(item, product):
    count = PRODUCTS[product]["components"]
    lo = numeric_version(item["introduced"])
    return lo + (0,) * (count - len(lo)), numeric_version(item["fixed"], count)


def _ranges(items, product):
    result = [_range(item, product) for item in _array(items, 32, "affected ranges")]
    if not result:
        raise CatalogError("Software advisory has no explicit affected range")
    result.sort(key=lambda item: _range_keys(item, product))
    for previous, following in zip(result, result[1:], strict=False):
        if _range_keys(following, product)[0] < _range_keys(previous, product)[1]:
            raise CatalogError("Overlapping or conflicting software affected ranges")
    return result


def _document_url(identifier):
    if identifier == "source:7zip-history":
        return HISTORY_URL
    if identifier == "msrc:updates":
        return f"{API}/updates"
    if identifier.startswith("msrc:"):
        msrc._document_month(identifier[5:])
        return f"{API}/cvrf/{identifier[5:]}"
    if identifier.startswith("cve:"):
        return cve_url(identifier[4:])
    raise CatalogError("Unsupported software source document")


def validate_catalog(data):
    """Validate normalized imported/persisted evidence without IO or mutation."""
    fields = {
        "schema_version",
        "source",
        "rules_version",
        "retrieved_at",
        "coverage_start",
        "coverage_end",
        "documents",
        "entries",
        "coverage",
    }
    if (
        not isinstance(data, dict)
        or set(data) != fields
        or type(data.get("schema_version")) is not int
        or data["schema_version"] != 1
        or data["source"] != SOURCE
        or data["rules_version"] != RULES_VERSION
    ):
        raise CatalogError("Unsupported software catalog format or matching rules")
    retrieved = msrc._timestamp(data["retrieved_at"])
    start, end = msrc._day(data["coverage_start"]), msrc._day(data["coverage_end"])
    if start.day != 1 or end < start or end > retrieved.date():
        raise CatalogError("Invalid software discovery coverage window")
    months = msrc._month_ids(start, end)
    if len(months) > 12:
        raise CatalogError("Software discovery coverage exceeds twelve months")
    documents, known = [], {}
    for item in _array(data["documents"], MAX_CVES + 20, "source documents"):
        if not isinstance(item, dict) or set(item) != {"id", "url", "sha256"}:
            raise CatalogError("Invalid software source document")
        identifier = _text(item["id"], 64)
        if (
            identifier in known
            or item["url"] != _document_url(identifier)
            or not isinstance(item["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
        ):
            raise CatalogError("Invalid or duplicate software document identity, URL or digest")
        if (
            identifier.startswith("msrc:")
            and identifier != "msrc:updates"
            and identifier[5:] not in months
        ):
            raise CatalogError("Out-of-window software discovery document")
        known[identifier] = item
        documents.append(dict(item))
    required_documents = {"source:7zip-history", *(f"msrc:{month}" for month in months)}
    if not required_documents <= known.keys():
        raise CatalogError("Software catalog is missing a stated discovery document")
    entries, identities = [], set()
    for item in _array(data["entries"], MAX_ENTRIES, "advisory entries"):
        expected = {
            "cve",
            "product_key",
            "source_product",
            "title",
            "severity",
            "affected_ranges",
            "source_urls",
            "document_ids",
        }
        if not isinstance(item, dict) or set(item) != expected:
            raise CatalogError("Invalid software advisory entry")
        product, cve = item["product_key"], _cve(item["cve"])
        if (
            not isinstance(product, str)
            or product not in PRODUCTS
            or not isinstance(item["source_product"], str)
            or item["source_product"] not in PRODUCTS[product]["source_products"]
            or not isinstance(item["severity"], str)
            or item["severity"] not in {"critical", "high", "medium", "low", "unknown"}
        ):
            raise CatalogError("Unsupported software advisory product or severity")
        if (product, cve) in identities or (product == "7zip-windows" and cve != SEVEN_CVE):
            raise CatalogError("Duplicate or outside-scope software advisory")
        ranges = _ranges(item["affected_ranges"], product)
        if product == "7zip-windows" and ranges != [{"introduced": "0", "fixed": "25.01"}]:
            raise CatalogError("Curated 7-Zip advisory range changed")
        docids = _array(item["document_ids"], 14, "advisory document references")
        if (
            any(not isinstance(doc, str) or doc not in known for doc in docids)
            or len(set(docids)) != len(docids)
            or f"cve:{cve}" not in docids
        ):
            raise CatalogError("Software advisory is missing its CNA evidence")
        if product == "edge-windows" and not any(
            doc.startswith("msrc:") and doc != "msrc:updates" for doc in docids
        ):
            raise CatalogError("Edge advisory has no monthly discovery evidence")
        if product == "7zip-windows" and "source:7zip-history" not in docids:
            raise CatalogError("7-Zip advisory has no vendor release evidence")
        urls = _array(item["source_urls"], 16, "advisory URLs")
        allowed = {_document_url(doc) for doc in docids} | {msrc.CVE_URL + cve}
        if (
            not urls
            or any(not isinstance(url, str) or url not in allowed for url in urls)
            or len(set(urls)) != len(urls)
            or cve_url(cve) not in urls
        ):
            raise CatalogError("Invalid software advisory source URL")
        identities.add((product, cve))
        entries.append(
            {
                **item,
                "title": _text(item["title"]),
                "affected_ranges": ranges,
                "document_ids": sorted(docids),
                "source_urls": sorted(urls),
            }
        )
    coverage, products_seen = [], set()
    for item in _array(data["coverage"], len(PRODUCTS), "product coverage"):
        if not isinstance(item, dict) or set(item) != {
            "product_key",
            "discovered",
            "parsed",
            "unavailable_cves",
            "scope",
        }:
            raise CatalogError("Invalid software coverage summary")
        product = item["product_key"]
        if not isinstance(product, str) or product not in PRODUCTS or product in products_seen:
            raise CatalogError("Duplicate or unsupported software coverage product")
        unavailable = _array(item["unavailable_cves"], MAX_CVES, "unavailable CVEs")
        if (
            any(_cve(cve) != cve for cve in unavailable)
            or len(set(unavailable)) != len(unavailable)
            or any((product, cve) in identities for cve in unavailable)
        ):
            raise CatalogError("Invalid unavailable software advisory identities")
        parsed = sum(entry["product_key"] == product for entry in entries)
        if (
            type(item["parsed"]) is not int
            or type(item["discovered"]) is not int
            or item["parsed"] != parsed
            or item["discovered"] != parsed + len(unavailable)
        ):
            raise CatalogError("Software coverage counts do not match the evidence")
        if product == "7zip-windows" and (
            item["discovered"] != 1
            or ({cve for key, cve in identities if key == product} | set(unavailable))
            != {SEVEN_CVE}
        ):
            raise CatalogError("Curated 7-Zip coverage changed")
        products_seen.add(product)
        coverage.append(
            {**item, "scope": _text(item["scope"]), "unavailable_cves": sorted(unavailable)}
        )
    if products_seen != set(PRODUCTS):
        raise CatalogError("Software catalog must state coverage for each supported product")
    return {
        "schema_version": 1,
        "source": SOURCE,
        "rules_version": RULES_VERSION,
        "retrieved_at": retrieved.isoformat(),
        "coverage_start": start.isoformat(),
        "coverage_end": end.isoformat(),
        "documents": sorted(documents, key=lambda x: x["id"]),
        "entries": sorted(entries, key=lambda x: (x["product_key"], x["cve"])),
        "coverage": sorted(coverage, key=lambda x: x["product_key"]),
    }


def _check_deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise CatalogError("Software catalog import exceeded its total time limit")


def _get_source(session, identifier, *, deadline=None):
    """Read only generated official HTTPS endpoints, bounded and without redirects."""
    url = _document_url(identifier)
    maximum = (
        MAX_HISTORY_BYTES
        if identifier == "source:7zip-history"
        else (
            msrc.MAX_INDEX
            if identifier == "msrc:updates"
            else msrc.MAX_DOCUMENT if identifier.startswith("msrc:") else MAX_CNA_BYTES
        )
    )
    for attempt in range(3):
        try:
            _check_deadline(deadline)
            started = time.monotonic()
            remaining = deadline - started if deadline is not None else 120
            timeout = (min(5, max(0.1, remaining)), min(30, max(0.1, remaining)))
            with session.get(url, allow_redirects=False, timeout=timeout, stream=True) as response:
                if response.status_code in {429, 500, 502, 503, 504}:
                    raise requests.ConnectionError("Software source temporarily unavailable")
                if response.status_code == 404 and identifier.startswith("cve:"):
                    raise SourceRecordMissing("Official CVE source record is unavailable")
                if response.status_code != 200:
                    raise CatalogError("Software source did not return HTTP 200")
                mime = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                if mime not in {"text/plain", "application/json", "application/octet-stream"}:
                    raise CatalogError("Unsupported software source content type")
                if identifier.startswith("msrc:") and mime != "application/json":
                    raise CatalogError("Microsoft software discovery response was not JSON")
                content = bytearray()
                for part in response.iter_content(65536):
                    _check_deadline(deadline)
                    content.extend(part)
                    if len(content) > maximum or time.monotonic() - started > 60:
                        raise CatalogError("Software source exceeded its byte or time limit")
                digest = hashlib.sha256(content).hexdigest()
                try:
                    value = content.decode("utf-8")
                    if identifier.startswith(("cve:", "msrc:")):
                        value = json.loads(value)
                        if not isinstance(value, dict):
                            raise ValueError
                except (ValueError, UnicodeError, RecursionError):
                    raise CatalogError("Invalid software source encoding or JSON") from None
                return value, {"id": identifier, "url": url, "sha256": digest}
        except requests.exceptions.SSLError:
            raise CatalogError("Software source TLS verification failed") from None
        except (requests.Timeout, requests.ConnectionError):
            if attempt == 2:
                raise CatalogError("Software source failed after three attempts") from None
            time.sleep(0.25 * (attempt + 1))
        except requests.RequestException:
            raise CatalogError("Software source could not be read safely") from None
    raise CatalogError("Software source request failed")


def _selected_months(index_data, months, now):
    offset = now.year * 12 + now.month - months
    year, month = divmod(offset, 12)
    start, selected, seen = date(year, month + 1, 1), {}, set()
    for item in _array(index_data.get("value"), 1000, "MSRC update index"):
        if not isinstance(item, dict):
            raise CatalogError("Invalid software MSRC discovery index")
        identifier = item.get("ID")
        month_date = msrc._index_month(identifier)
        if identifier in seen:
            raise CatalogError("Duplicate software discovery document")
        seen.add(identifier)
        if not start <= month_date <= now.date():
            continue
        msrc._document_month(identifier)
        initial = msrc._timestamp(item.get("InitialReleaseDate"), source=True)
        current = msrc._timestamp(item.get("CurrentReleaseDate"), source=True)
        if current < initial or initial.date() < start or current > now + timedelta(minutes=5):
            raise CatalogError("Invalid software discovery release metadata")
        if initial.date() <= now.date():
            if item.get("CvrfUrl") != f"{API}/cvrf/{identifier}":
                raise CatalogError("Software discovery source URL changed")
            selected[identifier] = {"initial": initial, "current": current}
    if not selected:
        raise CatalogError("No MSRC software discovery documents cover the selected window")
    last = max(msrc._document_month(identifier) for identifier in selected)
    end = min(
        now.date(), date(last.year, last.month, calendar.monthrange(last.year, last.month)[1])
    )
    if set(selected) != set(msrc._month_ids(start, end)):
        raise CatalogError("Software discovery index has a monthly coverage gap")
    return start, end, selected


def _discover_edge(document, identifier, expected, progress=None):
    tracking = document.get("DocumentTracking", {})
    if (
        not isinstance(tracking, dict)
        or msrc._value(tracking.get("Identification", {}), "ID") != identifier
    ):
        raise CatalogError("Software discovery document identity changed")
    initial = msrc._timestamp(tracking.get("InitialReleaseDate"), source=True)
    current = msrc._timestamp(tracking.get("CurrentReleaseDate"), source=True)
    if initial != expected["initial"] or current < expected["current"]:
        raise CatalogError("Software discovery document revision regressed")
    tree = document.get("ProductTree", {})
    if not isinstance(tree, dict):
        raise CatalogError("Invalid software discovery product tree")
    products, seen = set(), set()
    for item in _array(tree.get("FullProductName"), 10000, "MSRC products"):
        if not isinstance(item, dict):
            raise CatalogError("Invalid software discovery product")
        product_id, name = item.get("ProductID"), item.get("Value")
        msrc._ids([product_id])
        _text(name, 1024)
        if product_id in seen:
            raise CatalogError("Duplicate software discovery product identifier")
        seen.add(product_id)
        if name in EDGE_NAMES:
            products.add(product_id)
    found, excluded = {}, 0
    for item in _array(
        document.get("Vulnerability"), msrc.MAX_VULNERABILITIES, "MSRC vulnerabilities"
    ):
        if not isinstance(item, dict):
            raise CatalogError("Invalid software discovery vulnerability")
        affected = set()
        for status in _array(item.get("ProductStatuses", []), 100, "MSRC product statuses"):
            if not isinstance(status, dict):
                raise CatalogError("Invalid software discovery product status")
            if status.get("Type") == 3:
                affected.update(msrc._ids(status.get("ProductID")))
        if not products & affected:
            continue
        title = _text(msrc._value(item, "Title"))
        # MSRC also publishes hundreds of upstream Chromium issues against Edge.
        # Their Chrome CNA ranges cannot establish an Edge fixed build. Keep the
        # catalog's explicitly stated first scope to vendor-titled Edge issues;
        # exact Microsoft CNA identity and product ranges are still required.
        if not title.startswith(EDGE_TITLE_PREFIXES):
            excluded += 1
            continue
        cve = _cve(item.get("CVE"))
        severity = "unknown"
        for threat in _array(item.get("Threats", []), 10000, "MSRC threat metadata"):
            if not isinstance(threat, dict):
                raise CatalogError("Invalid software discovery threat metadata")
            if threat.get("Type") == 3 and products & set(msrc._ids(threat.get("ProductID", []))):
                value = msrc._value(threat, "Description")
                proposed = msrc.SEVERITIES.get(value, "unknown")
                rank = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                if rank[proposed] > rank[severity]:
                    severity = proposed
        found[cve] = {
            "title": title,
            "severity": severity,
            "document_ids": [f"msrc:{identifier}"],
        }
    if progress:
        progress(
            f"MSRC {identifier}: selected {len(found)} Edge-specific advisories; "
            f"excluded {excluded} upstream or other-component references outside this scope"
        )
    return found


def _parse_cna(record, cve, product, discovery):
    """Reject unsupported semantics; never repair vendor data into guessed ranges."""
    try:
        metadata, cna = record["cveMetadata"], record["containers"]["cna"]
        expected = MICROSOFT_CNA if product == "edge-windows" else SEVEN_CNA
        if (
            metadata["cveId"] != cve
            or metadata["state"] != "PUBLISHED"
            or (metadata["assignerOrgId"], metadata["assignerShortName"]) != expected
            or (cna["providerMetadata"]["orgId"], cna["providerMetadata"]["shortName"]) != expected
        ):
            raise CatalogError("CNA identity changed")
        selected = []
        preferred = "Microsoft Edge for Windows" if product == "edge-windows" else "7-Zip"
        affected = _array(cna.get("affected"), 100, "CNA affected products")
        for item in affected:
            if not isinstance(item, dict):
                raise CatalogError("Invalid CNA affected product")
            if item.get("product") == preferred:
                selected.append(item)
        if not selected and product == "edge-windows":
            selected = [
                item
                for item in affected
                if item.get("product") == "Microsoft Edge (Chromium-based)"
            ]
        if not selected:
            raise CatalogError("CNA has no supported exact product")
        candidates = []
        for item in selected:
            if (
                item.get("vendor") != ("Microsoft" if product == "edge-windows" else "7-Zip")
                or set(item) - {"vendor", "product", "versions", "defaultStatus", "cpes"}
                or item.get("defaultStatus", "unknown") not in {"unknown", "unaffected"}
            ):
                raise CatalogError("Unsupported CNA product applicability")
            ranges = []
            for version in _array(item.get("versions"), 32, "CNA versions"):
                if (
                    not isinstance(version, dict)
                    or set(version) != {"version", "lessThan", "versionType", "status"}
                    or version["status"] != "affected"
                    or version["versionType"] != "custom"
                ):
                    raise CatalogError("CNA has no explicit supported numeric affected interval")
                ranges.append({"introduced": version["version"], "fixed": version["lessThan"]})
            candidates.append((item["product"], _ranges(ranges, product)))
        if any(candidate != candidates[0] for candidate in candidates[1:]):
            raise CatalogError("Conflicting exact-product CNA ranges")
        source_product, ranges = candidates[0]
        if product == "7zip-windows" and ranges != [{"introduced": "0", "fixed": "25.01"}]:
            raise CatalogError("Curated 7-Zip CNA range changed")
        return {
            "cve": cve,
            "product_key": product,
            "source_product": source_product,
            "title": _text(cna.get("title") or discovery["title"]),
            "severity": discovery["severity"],
            "affected_ranges": ranges,
            "source_urls": sorted(
                {
                    cve_url(cve),
                    *([msrc.CVE_URL + cve] if product == "edge-windows" else [HISTORY_URL]),
                }
            ),
            "document_ids": sorted({f"cve:{cve}", *discovery["document_ids"]}),
        }
    except (KeyError, TypeError, AttributeError, IndexError, CatalogError):
        return None


def build_catalog(*, months=3, now=None, progress=None):
    """Return one complete bounded snapshot; network failures never persist it."""
    if type(months) is not int or not 1 <= months <= 12:
        raise CatalogError("Select one to twelve software catalog months")
    now = now or datetime.now(UTC)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise CatalogError("Software catalog time must include its timezone")
    now = now.astimezone(UTC)
    deadline = time.monotonic() + MAX_IMPORT_SECONDS
    documents, discovery, entries, unavailable = [], {}, [], []
    with requests.Session() as session:
        session.trust_env, session.proxies, session.verify, session.auth = False, {}, True, None
        session.headers.update({"Accept": "application/json"})
        index_data, metadata = _get_source(session, "msrc:updates", deadline=deadline)
        documents.append(metadata)
        start, end, selected = _selected_months(index_data, months, now)
        for identifier in sorted(selected, key=msrc._document_month):
            if progress:
                progress(f"Discovering Edge advisories in Microsoft CVRF {identifier}")
            raw, metadata = _get_source(session, f"msrc:{identifier}", deadline=deadline)
            found = _discover_edge(raw, identifier, selected[identifier], progress=progress)
            documents.append(metadata)
            del raw
            for cve, item in found.items():
                if cve in discovery:
                    item["document_ids"] = sorted(
                        set(item["document_ids"] + discovery[cve]["document_ids"])
                    )
                discovery[cve] = item
            if len(discovery) > MAX_CVES:
                raise CatalogError("Software discovery exceeds its CVE limit")
        for number, (cve, item) in enumerate(sorted(discovery.items()), 1):
            if progress and (number == 1 or number % 25 == 0):
                progress(f"Validating Edge CNA ranges ({number}/{len(discovery)})")
            try:
                raw, metadata = _get_source(session, f"cve:{cve}", deadline=deadline)
            except SourceRecordMissing:
                unavailable.append(cve)
                continue
            documents.append(metadata)
            entry = _parse_cna(raw, cve, "edge-windows", item)
            if entry:
                entries.append(entry)
            else:
                unavailable.append(cve)
        if progress:
            progress("Validating the curated 7-Zip advisory against vendor release history")
        history, metadata = _get_source(session, "source:7zip-history", deadline=deadline)
        documents.append(metadata)
        section = re.search(
            r"(?ms)^25\.01[ \t]+\d{4}-\d{2}-\d{2}\r?\n-+\r?\n(.*?)(?=^\d+\.\d+[ \t]+\d{4}-|\Z)",
            history,
        )
        if not section or SEVEN_CVE not in section[1]:
            raise CatalogError("The curated 7-Zip vendor release evidence changed")
        try:
            raw, metadata = _get_source(session, f"cve:{SEVEN_CVE}", deadline=deadline)
        except SourceRecordMissing:
            seven = None
        else:
            documents.append(metadata)
            seven = _parse_cna(
                raw,
                SEVEN_CVE,
                "7zip-windows",
                {
                    "title": "7-Zip symbolic link extraction vulnerability",
                    "severity": "unknown",
                    "document_ids": ["source:7zip-history"],
                },
            )
        if seven:
            entries.append(seven)
    coverage = [
        {
            "product_key": "edge-windows",
            "discovered": len(discovery),
            "parsed": len(discovery) - len(unavailable),
            "unavailable_cves": unavailable,
            "scope": PRODUCTS["edge-windows"]["scope"],
        },
        {
            "product_key": "7zip-windows",
            "discovered": 1,
            "parsed": int(seven is not None),
            "unavailable_cves": [] if seven else [SEVEN_CVE],
            "scope": PRODUCTS["7zip-windows"]["scope"],
        },
    ]
    return validate_catalog(
        {
            "schema_version": 1,
            "source": SOURCE,
            "rules_version": RULES_VERSION,
            "retrieved_at": now.isoformat(),
            "coverage_start": start.isoformat(),
            "coverage_end": end.isoformat(),
            "documents": documents,
            "entries": entries,
            "coverage": coverage,
        }
    )
