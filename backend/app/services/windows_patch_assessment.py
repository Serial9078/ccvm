"""Conservative OS-build comparisons against an immutable MSRC catalog.

This is a standard Windows Server cumulative-update baseline assessment. It
does not prove that an individual CVE's optional component is installed or
vulnerable. No credentials, target connection, network I/O or Finding writes
belong in this module.
"""

import re
from datetime import UTC, date, datetime, timedelta

from app.services.windows_patch_catalog import validate_catalog

ENGINE_VERSION = "windows-server-build-v1"
MAX_AGE = timedelta(days=7)
MAX_REFERENCES = 1000
MAX_BASELINE_KBS = 32
PRODUCTS = {
    "2016": (14393, "10816", "10855"),
    "2019": (17763, "11571", "11572"),
    "2022": (20348, "11923", "11924"),
    "2025": (26100, "12436", "12437"),
}
EDITIONS = {
    "ServerStandard": "Standard",
    "ServerDatacenter": "Datacenter",
    "ServerStandardEval": "Standard",
    "ServerDatacenterEval": "Datacenter",
    "ServerStandardCore": "Standard",
    "ServerDatacenterCore": "Datacenter",
    "ServerStandardEvalCore": "Standard",
    "ServerDatacenterEvalCore": "Datacenter",
}
SEVERITIES = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LIMITATIONS = [
    "This compares the recorded OS build with a standard cumulative security-update baseline.",
    "CVE references describe the selected Microsoft update; component applicability and "
    "exploitability were not checked. Latest remediations can reference older CVEs.",
    "Get-HotFix is not a complete update inventory. "
    "Missing KB rows are not used as patch evidence.",
    "Hotpatch, third-party software CVEs, Linux and other Windows components are not assessed.",
]


def timestamp(value):
    try:
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            return None
        return value.astimezone(UTC)
    except (ValueError, TypeError, OverflowError):
        return None


def iso(value):
    return value.isoformat().replace("+00:00", "Z") if value else None


def identify(inventory):
    if (
        not isinstance(inventory, dict)
        or inventory.get("schema_version") != 1
        or not isinstance(inventory.get("os"), dict)
    ):
        return (
            None,
            None,
            "identity_incomplete",
            "OS identity evidence is missing. Collect a new inventory.",
        )
    os_data = inventory["os"]
    if os_data.get("family") != "Windows":
        return (
            None,
            None,
            "unsupported",
            "Only Windows Server standard cumulative builds are supported.",
        )
    caption = os_data.get("name")
    match = re.fullmatch(
        r"(?:Microsoft\s+)?Windows\s+Server\s+(2016|2019|2022|2025)\b.*",
        caption if isinstance(caption, str) and len(caption) <= 500 else "",
        flags=re.IGNORECASE,
    )
    if not match:
        return None, None, "unsupported", "The Windows Server product could not be mapped exactly."
    year = match.group(1)
    expected_build, desktop_id, core_id = PRODUCTS[year]
    metadata = ("product_type", "installation_type", "edition_id", "native_architecture")
    if any(os_data.get(key) is None or os_data.get(key) == "" for key in metadata):
        return (
            None,
            None,
            "identity_incomplete",
            ("Required Windows product identity is missing. Collect a new inventory."),
        )
    edition = os_data["edition_id"]
    installation = os_data["installation_type"]
    if (
        any(not isinstance(os_data[key], str) or len(os_data[key]) > 100 for key in metadata[1:])
        or not isinstance(os_data["product_type"], (str, int))
        or edition not in EDITIONS
        or installation not in {"Server", "Server Core"}
        or str(os_data["product_type"]) not in {"2", "3"}
        or os_data["native_architecture"] != "AMD64"
        or any(word in caption.casefold() for word in ("azure", "hotpatch"))
        or (edition.endswith("Core") and installation != "Server Core")
    ):
        return (
            None,
            None,
            "unsupported",
            (
                "This edition, installation or architecture is outside "
                "the standard Windows Server scope."
            ),
        )
    architecture = os_data.get("architecture", "")
    if not isinstance(architecture, str) or architecture.casefold() not in {
        "64-bit",
        "64 bit",
        "x64",
        "amd64",
        "x86_64",
    }:
        return (
            None,
            None,
            "unsupported",
            "OS architecture evidence does not agree with AMD64 identity.",
        )
    caption_edition = re.search(r"\b(Standard|Datacenter)\b", caption, flags=re.IGNORECASE)
    if caption_edition and caption_edition.group(1).casefold() != EDITIONS[edition].casefold():
        return None, None, "unsupported", "OS caption and registry edition do not agree."
    kernel = os_data.get("kernel", "")
    version = os_data.get("version", "")
    kernel_match = re.fullmatch(r"(\d{4,5})\.(\d{1,7})", kernel if isinstance(kernel, str) else "")
    version_match = re.fullmatch(
        r"10\.0\.(\d{4,5})(?:\.(\d{1,7}))?", version if isinstance(version, str) else ""
    )
    if not kernel_match or not version_match:
        return (
            None,
            None,
            "identity_incomplete",
            "The complete OS build and update revision are required.",
        )
    build, ubr = map(int, kernel_match.groups())
    if (
        build != expected_build
        or int(version_match.group(1)) != expected_build
        or (version_match.group(2) is not None and int(version_match.group(2)) != ubr)
    ):
        return (
            None,
            None,
            "unsupported",
            "The OS caption, version and servicing build do not agree.",
        )
    core = installation == "Server Core"
    product = {
        "id": core_id if core else desktop_id,
        "name": f"Windows Server {year}" + (" (Server Core installation)" if core else ""),
        "year": year,
        "installation_type": installation,
        "edition_id": edition,
    }
    return product, (10, 0, build, ubr), None, None


def assess_windows_patches(inventory, catalog, *, evidence_collected_at, now):
    now = timestamp(now)
    if now is None:
        raise ValueError("Assessment time must be timezone-aware")
    evidence = timestamp(evidence_collected_at)
    result = {
        "schema_version": 1,
        "engine_version": ENGINE_VERSION,
        "status": "identity_incomplete",
        "reason": "",
        "evaluated_at": iso(now),
        "valid_until": iso(evidence + MAX_AGE) if evidence and evidence <= now else None,
        "evidence_collected_at": iso(evidence),
        "catalog_retrieved_at": None,
        "installed_build": None,
        "product": None,
        "baseline_build": None,
        "baseline_kbs": [],
        "cve_references": [],
        "cve_references_total": 0,
        "cve_references_truncated": False,
        "coverage": {
            "scope": "windows_server_standard_cumulative_os_build",
            "status": "unavailable",
            "catalog_start": None,
            "catalog_end": None,
            "component_applicability": "not_checked",
            "third_party_software": "unavailable",
            "linux": "unavailable",
            "hotpatch": "unavailable",
        },
        "limitations": list(LIMITATIONS),
        "sources": [],
    }

    def finish(status, reason):
        result.update(status=status, reason=reason)
        return result

    product, installed, status, reason = identify(inventory)
    if status:
        return finish(status, reason)
    result.update(product=product, installed_build=".".join(map(str, installed)))
    if evidence is None or evidence > now or now >= evidence + MAX_AGE:
        return finish(
            "stale_evidence",
            "Collect a new inventory; its timestamp is missing or outside seven days.",
        )
    if (
        not isinstance(catalog, dict)
        or catalog.get("schema_version") != 1
        or catalog.get("source") != "msrc-cvrf"
    ):
        result["valid_until"] = None
        return finish("catalog_unavailable", "A validated Microsoft CVRF catalog is required.")
    retrieved = timestamp(catalog.get("retrieved_at"))
    result["catalog_retrieved_at"] = iso(retrieved)
    if retrieved is None or retrieved > now:
        result["valid_until"] = None
        return finish(
            "catalog_unavailable", "The catalog retrieval timestamp is missing or invalid."
        )
    result["valid_until"] = iso(min(evidence + MAX_AGE, retrieved + MAX_AGE))
    if now >= retrieved + MAX_AGE:
        return finish(
            "stale_catalog", "Refresh the Microsoft catalog; it is at least seven days old."
        )
    try:
        catalog = validate_catalog(catalog)
    except (ValueError, TypeError, KeyError):
        return finish(
            "coverage_unavailable",
            "The catalog document coverage or source metadata is incomplete.",
        )
    documents = {
        document["id"]: {
            "document_id": document["id"],
            **{
                key: document[key]
                for key in ("url", "sha256", "initial_release_date", "current_release_date")
            },
        }
        for document in catalog["documents"]
    }
    result["coverage"].update(
        catalog_start=catalog["coverage_start"], catalog_end=catalog["coverage_end"]
    )
    previous_month_end = now.date().replace(day=1) - timedelta(days=1)
    if date.fromisoformat(catalog["coverage_end"]) < previous_month_end:
        return finish(
            "stale_catalog", "The catalog coverage does not reach the preceding calendar month."
        )
    candidates = []
    for entry in catalog["entries"]:
        if entry["product_id"] == product["id"] and entry["product_name"] == product["name"]:
            build = tuple(map(int, entry["fixed_build"].split(".")))
            # validate_catalog() requires the exact supported product/branch
            # and standard Security Update subtype, including official provenance.
            candidates.append(
                (
                    build,
                    {
                        **entry,
                        "cvss_score": (
                            float(entry["cvss_score"]) if "cvss_score" in entry else None
                        ),
                    },
                )
            )
    if not candidates:
        return finish(
            "coverage_unavailable",
            "No standard security-update FixedBuild is available for this exact product.",
        )
    baseline = max(build for build, _ in candidates)
    selected = [entry for build, entry in candidates if build == baseline]
    baseline_kbs = sorted({entry["kb"] for entry in selected})
    if len(baseline_kbs) > MAX_BASELINE_KBS:
        return finish(
            "coverage_unavailable",
            "The selected baseline has an ambiguous number of update packages.",
        )
    result["baseline_build"] = ".".join(map(str, baseline))
    result["baseline_kbs"] = baseline_kbs
    references = {}
    for entry in selected:
        reference = references.setdefault(
            entry["cve"],
            {
                "cve": entry["cve"],
                "title": entry["title"],
                "severity": entry["severity"],
                "cvss_score": entry["cvss_score"],
                "kbs": set(),
                "source_urls": set(),
                "document_ids": set(),
            },
        )
        if SEVERITIES[entry["severity"]] > SEVERITIES[reference["severity"]]:
            reference["severity"] = entry["severity"]
        if entry["cvss_score"] is not None:
            reference["cvss_score"] = max(reference["cvss_score"] or 0, entry["cvss_score"])
        for field, value in (
            ("kbs", entry["kb"]),
            ("source_urls", entry["source_url"]),
            ("document_ids", entry["document_id"]),
        ):
            reference[field].add(value)
    result["cve_references_total"] = len(references)
    result["cve_references_truncated"] = len(references) > MAX_REFERENCES
    for cve in sorted(references)[:MAX_REFERENCES]:
        reference = references[cve]
        result["cve_references"].append(
            {
                **reference,
                **{key: sorted(reference[key]) for key in ("kbs", "source_urls", "document_ids")},
            }
        )
    result["sources"] = [
        documents[key] for key in sorted({entry["document_id"] for entry in selected})
    ]
    result["coverage"]["status"] = "evaluated"
    if installed < baseline:
        return finish(
            "build_gap",
            "The recorded OS build is below the catalog's standard "
            "cumulative security-update baseline.",
        )
    return finish(
        "meets_catalog_baseline",
        "The recorded OS build meets or exceeds this catalog baseline; "
        "this is not a complete vulnerability assessment.",
    )
