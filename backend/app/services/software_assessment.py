"""Deterministic, operator-only software version applicability from saved evidence.

Registry metadata is evidence of a reported installation, not proof that a CVE
is exploitable. Only explicitly mapped Windows products and vendor-published
numeric ranges are evaluated. This module performs no I/O or authentication.
"""

import copy
import json
import re
from collections import Counter
from datetime import UTC, datetime, timedelta

from app.services.software_catalog import numeric_version, validate_catalog

ENGINE_VERSION = "windows-registry-ranges-v1"
MAX_AGE = timedelta(days=7)
MAX_PACKAGE_ROWS = 10000
MAX_PRODUCT_VERSIONS = 200
MAX_UNASSESSED_ROWS = 200
MAX_DISPLAY_MATCHES = 500
MAX_DISPLAY_BYTES = 2 * 1024 * 1024
MAX_DISPLAY_SOURCES = 100
PRODUCT_NAMES = {"edge-windows": "Microsoft Edge", "7zip-windows": "7-Zip"}
LIMITATIONS = [
    "These are reported installed-version matches against the catalog's explicit affected ranges; "
    "exploitability and the presence or use of a vulnerable feature were not verified.",
    "Registry uninstall entries are not a complete software inventory. Portable programs and "
    "per-user installations are not collected.",
    "Only the named product mappings and the displayed catalog scopes are checked. "
    "A version outside these ranges is not a claim that the program or host is secure.",
    "Program architecture is not inferred from the registry view. Product authenticity, "
    "vendor backports and release-channel policies are not independently verified.",
]


def _timestamp(value):
    try:
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            return None
        return value.astimezone(UTC)
    except (ValueError, TypeError, OverflowError):
        return None


def _iso(value):
    return value.isoformat().replace("+00:00", "Z") if value else None


def _text(value):
    return (
        isinstance(value, str)
        and len(value) <= 500
        and not any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
    )


def _identity(row):
    """Match allowlisted uninstall identities, without fuzzy product inference."""
    name, publisher = row.get("name"), row.get("publisher")
    if not _text(publisher) or not publisher.strip():
        return None, "Publisher identity is missing. Collect a new inventory.", None
    if (
        not _text(row.get("registry_key"))
        or not row["registry_key"].strip()
        or row.get("registry_view") not in {"native", "wow6432"}
        or row.get("install_scope") != "machine"
    ):
        return (
            None,
            "Machine uninstall-entry identity is incomplete. Collect a new inventory.",
            None,
        )
    name_key = name.casefold()
    publisher_key = publisher.casefold()
    if name_key == "microsoft edge" and publisher_key == "microsoft corporation":
        return "edge-windows", None, None
    match = re.fullmatch(
        r"7-zip(?: (?P<version>\d{1,3}\.\d{2}))?(?: \((?:x64|x86|arm64)(?: edition)?\))?",
        name_key,
    )
    if match and publisher_key == "igor pavlov":
        return "7zip-windows", None, match.group("version")
    return None, "No exact supported product and publisher mapping is available.", None


def _version(value, product_key):
    if product_key == "edge-windows":
        return numeric_version(value, components=4)
    # Official 7-Zip releases use a two-digit minor field, rather than a
    # decimal fraction. Unusual MSI/repackaged version formats stay unknown.
    if not isinstance(value, str) or not re.fullmatch(r"\d{1,3}\.\d{2}", value):
        raise ValueError("Unsupported 7-Zip release format")
    return numeric_version(value, components=2)


def _range_match(installed, affected):
    lower = numeric_version(affected["introduced"])
    upper = numeric_version(affected["fixed"], components=len(installed))
    if len(lower) > len(installed):
        raise ValueError("Incompatible affected-version range")
    lower += (0,) * (len(installed) - len(lower))
    return lower <= installed < upper


def assess_software(inventory, catalog, *, evidence_collected_at, now):
    """Evaluate a bounded immutable inventory against one validated snapshot."""
    now = _timestamp(now)
    if now is None:
        raise ValueError("Assessment time must be timezone-aware")
    collected = _timestamp(evidence_collected_at)
    result = {
        "schema_version": 1,
        "engine_version": ENGINE_VERSION,
        "status": "identity_incomplete",
        "reason": "",
        "evaluated_at": _iso(now),
        "valid_until": _iso(collected + MAX_AGE) if collected and collected <= now else None,
        "evidence_collected_at": _iso(collected),
        "catalog_retrieved_at": None,
        "summary": {
            "inventory_entries": 0,
            "identified_entries": 0,
            "assessed_entries": 0,
            "unassessed_entries": 0,
            "product_versions": 0,
            "matched_product_versions": 0,
            "cve_matches": 0,
        },
        "coverage": {
            "scope": "windows_machine_registry_vendor_ranges",
            "status": "unavailable",
            "package_status": None,
            "catalog_start": None,
            "catalog_end": None,
            "vendor_catalog": [],
            "exploitability": "not_verified",
            "per_user": "not_collected",
        },
        "products": [],
        "unassessed": [],
        "products_total": 0,
        "products_truncated": False,
        "unassessed_total": 0,
        "unassessed_truncated": False,
        "limitations": list(LIMITATIONS),
        "sources": [],
        "sources_total": 0,
        "sources_truncated": False,
    }

    def finish(status, reason):
        result.update(status=status, reason=reason)
        return result

    if (
        not isinstance(inventory, dict)
        or type(inventory.get("schema_version")) is not int
        or inventory["schema_version"] != 1
        or not isinstance(inventory.get("os"), dict)
    ):
        return finish("identity_incomplete", "A saved host inventory is required.")
    if inventory["os"].get("family") != "Windows":
        return finish("unsupported", "Only Windows machine uninstall entries are supported.")
    packages = inventory.get("packages")
    if not isinstance(packages, dict) or packages.get("source") != "registry-uninstall":
        return finish("unsupported", "Windows registry uninstall evidence is required.")
    if packages.get("status") not in {"complete", "truncated", "unavailable"}:
        return finish("identity_incomplete", "The package collection coverage is invalid.")
    items = packages.get("items")
    if not isinstance(items, list) or len(items) > MAX_PACKAGE_ROWS:
        raise ValueError("Invalid inventory package count")
    if packages["status"] == "unavailable" and items:
        raise ValueError("Package rows contradict unavailable coverage")
    for row in items:
        if not isinstance(row, dict) or any(not _text(row.get(key)) for key in ("name", "version")):
            raise ValueError("Invalid inventory package evidence")
        for key in ("publisher", "registry_key", "registry_view", "install_scope"):
            if key in row and not _text(row[key]):
                raise ValueError("Invalid optional package identity")
    summary = result["summary"]
    summary.update(inventory_entries=len(items), unassessed_entries=len(items))
    result["coverage"]["package_status"] = packages["status"]
    if collected is None or collected > now or now >= collected + MAX_AGE:
        result["valid_until"] = None
        return finish(
            "stale_evidence", "Collect a new inventory; its timestamp is outside seven days."
        )
    if not isinstance(catalog, dict):
        result["valid_until"] = None
        return finish("catalog_unavailable", "A validated software advisory catalog is required.")
    retrieved = _timestamp(catalog.get("retrieved_at"))
    result["catalog_retrieved_at"] = _iso(retrieved)
    if retrieved is None or retrieved > now:
        result["valid_until"] = None
        return finish("catalog_unavailable", "The software catalog retrieval timestamp is invalid.")
    result["valid_until"] = _iso(min(collected + MAX_AGE, retrieved + MAX_AGE))
    if now >= retrieved + MAX_AGE:
        return finish(
            "stale_catalog", "Refresh the software catalog; it is at least seven days old."
        )
    try:
        snapshot = validate_catalog(catalog)
    except (ValueError, TypeError, KeyError):
        result["valid_until"] = None
        return finish("catalog_unavailable", "The software catalog failed validation.")
    result["coverage"].update(
        status="limited",
        catalog_start=snapshot["coverage_start"],
        catalog_end=snapshot["coverage_end"],
        vendor_catalog=copy.deepcopy(snapshot["coverage"]),
    )
    result["sources"] = copy.deepcopy(snapshot["documents"][:MAX_DISPLAY_SOURCES])
    result["sources_total"] = len(snapshot["documents"])
    result["sources_truncated"] = len(snapshot["documents"]) > MAX_DISPLAY_SOURCES
    by_product = {key: [] for key in PRODUCT_NAMES}
    coverage = {row["product_key"]: row for row in snapshot["coverage"]}
    for entry in snapshot["entries"]:
        by_product[entry["product_key"]].append(entry)
    unknown = Counter()
    groups = {}

    def unassessed(row, reason, count=1):
        unknown[(row["name"], row["version"], row.get("publisher", ""), reason)] += count

    for row in items:
        product_key, reason, named_version = _identity(row)
        if product_key is None:
            unassessed(row, reason)
            continue
        summary["identified_entries"] += 1
        try:
            installed = _version(row["version"], product_key)
            if named_version is not None and _version(named_version, product_key) != installed:
                raise ValueError("Display name and version disagree")
        except ValueError:
            unassessed(
                row,
                "The supported product's numeric version evidence is incomplete or conflicting.",
            )
            continue
        key = (product_key, installed)
        if key not in groups:
            groups[key] = {"evidence": row, "count": 0}
        groups[key]["count"] += 1
    summary["product_versions"] = len(groups)
    result["products_total"] = len(groups)
    display_matches = 0
    display_bytes = 0
    for index, ((product_key, installed), group) in enumerate(sorted(groups.items())):
        row, count = group["evidence"], group["count"]
        if index >= MAX_PRODUCT_VERSIONS:
            unassessed(row, "The bounded assessment product-version limit was reached.", count)
            result["products_truncated"] = True
            continue
        entries = by_product[product_key]
        scope = coverage[product_key]
        product = {
            "product_key": product_key,
            "name": PRODUCT_NAMES[product_key],
            "version": row["version"],
            "publisher": row["publisher"],
            "evidence_basis": "registry-uninstall",
            "evidence_count": count,
            "status": "no_match_in_catalog",
            "reason": "The recorded version does not match the checked affected ranges.",
            "checked_cves": len(entries),
            "matches": [],
            "matches_total": 0,
            "matches_truncated": False,
            "catalog_scope": scope["scope"],
        }
        if entries:
            summary["assessed_entries"] += count
            summary["unassessed_entries"] -= count
        for entry in entries:
            if not any(_range_match(installed, affected) for affected in entry["affected_ranges"]):
                continue
            product["matches_total"] += 1
            match = {
                key: copy.deepcopy(entry[key])
                for key in (
                    "cve",
                    "title",
                    "severity",
                    "source_product",
                    "affected_ranges",
                    "source_urls",
                    "document_ids",
                )
            }
            size = len(json.dumps(match, ensure_ascii=True, allow_nan=False).encode())
            if display_matches < MAX_DISPLAY_MATCHES and display_bytes + size <= MAX_DISPLAY_BYTES:
                product["matches"].append(match)
                display_matches += 1
                display_bytes += size
            else:
                product["matches_truncated"] = True
        if product["matches_total"]:
            product["status"] = "version_matches_affected_range"
            product["reason"] = (
                "The reported installed version matches a published affected range; "
                "exploitability was not verified."
            )
            summary["matched_product_versions"] += 1
            summary["cve_matches"] += product["matches_total"]
        elif not entries or scope["unavailable_cves"]:
            product["status"] = "catalog_incomplete"
            product["reason"] = (
                "No match in the checked ranges; some or all discovered advisories "
                "could not be evaluated."
            )
        result["products"].append(product)
    result["unassessed_total"] = len(unknown)
    result["unassessed_truncated"] = len(unknown) > MAX_UNASSESSED_ROWS
    for (name, version, publisher, reason), count in sorted(unknown.items())[:MAX_UNASSESSED_ROWS]:
        result["unassessed"].append(
            {
                "name": name,
                "version": version,
                "publisher": publisher,
                "reason": reason,
                "evidence_count": count,
            }
        )
    if summary["cve_matches"]:
        return finish(
            "version_matches_found",
            "Installed-version matches were found within the displayed, limited advisory scopes.",
        )
    if not summary["assessed_entries"]:
        return finish(
            "coverage_unavailable",
            "No installed product version could be evaluated against a validated affected range.",
        )
    return finish(
        "no_matches_in_checked_ranges",
        "No installed-version matches were found in the checked ranges. Unassessed software "
        "and advisories remain outside this result.",
    )
