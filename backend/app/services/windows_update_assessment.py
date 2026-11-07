"""Local interpretation of a retained Windows Update Agent offer query.

This module never connects to a host, refreshes a catalog, downloads an update or
changes update policy. Offers describe the device's configured update source;
their absence cannot establish complete patch or vulnerability coverage.
"""

import re
from datetime import UTC, datetime, timedelta
from uuid import UUID

ENGINE_VERSION = "windows-client-wua-v1"
PROVIDER = "windows-update-agent"
SOURCE = "configured_windows_update_service"
MAX_AGE = timedelta(hours=24)
MAX_ITEMS = 200
# Stable Microsoft update-classification category IDs, not localized names.
# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ff357803(v=vs.85)
# https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update
CATEGORIES = {
    "0fa1201d-4330-4fa8-8ae9-b877473b6441": "security",
    "e6cf1350-c01b-414d-a61f-263d14d133b4": "quality",
    "28bc880e-0592-4cbf-8f95-c79b17911d5f": "quality",
    "cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83": "quality",
    "3689bdc8-b205-4af4-8d4a-a63924c5e9d5": "feature",
    "b54e7d24-7add-428f-8b75-90a396fa584f": "feature",
    "e0789628-ce08-4437-be74-2495b842f43b": "definition",
}
LIMITATIONS = [
    "This is the last collected online Windows Update Agent offer query against the "
    "device's configured Windows Update or WSUS source; update policy was not changed.",
    "No offers does not mean fully patched. Source approvals, deferrals, safeguards, "
    "licensing and scan coverage can limit the updates offered.",
    "Hidden updates, drivers, superseded updates, CVE applicability and software "
    "outside the configured update source are not assessed.",
    "Feature and definition offers are separate from security and quality offers. "
    "Optional offers are not treated as required patches.",
    "This report does not establish Windows lifecycle support or ESU entitlement.",
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


def is_windows_client(inventory):
    os_data = inventory.get("os") if isinstance(inventory, dict) else None
    return bool(
        isinstance(os_data, dict)
        and os_data.get("family") == "Windows"
        and type(os_data.get("product_type")) in {int, str}
        and str(os_data["product_type"]) == "1"
    )


def _uuid(value):
    if not isinstance(value, str) or len(value) != 36 or str(UUID(value)) != value:
        raise ValueError("Invalid update identity")
    return value


def _text(value, maximum):
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
    ):
        raise ValueError("Invalid update metadata")
    return value


def _item(value):
    if not isinstance(value, dict):
        raise ValueError("Invalid update offer")
    identity = _uuid(value.get("update_id"))
    revision = value.get("revision")
    if type(revision) is not int or not 0 <= revision <= 2147483647:
        raise ValueError("Invalid update revision")
    if value.get("is_hidden") is not False or value.get("is_installed") is not False:
        raise ValueError("Update offer visibility or installation state changed")
    optional, mandatory = value.get("is_optional"), value.get("is_mandatory")
    if any(flag is not None and type(flag) is not bool for flag in (optional, mandatory)):
        raise ValueError("Invalid update recommendation")
    kbs = value.get("kbs")
    categories = value.get("categories")
    if not isinstance(kbs, list) or len(kbs) > 64:
        raise ValueError("Invalid KB references")
    if any(not isinstance(kb, str) or re.fullmatch(r"KB[0-9]{1,12}", kb) is None for kb in kbs):
        raise ValueError("Invalid KB reference")
    if not isinstance(categories, list) or len(categories) > 100:
        raise ValueError("Invalid classification evidence")
    normalized, classification_ids = [], set()
    for category in categories:
        if not isinstance(category, dict):
            raise ValueError("Invalid classification evidence")
        identifier = _uuid(category.get("id"))
        kind = _text(category.get("type"), 100)
        normalized.append(
            {
                "id": identifier,
                "name": _text(category.get("name"), 500),
                "type": kind,
            }
        )
        if kind == "UpdateClassification":
            classification_ids.add(identifier)
    # Ambiguous or unknown categories remain unclassified. A title, product
    # category or MsrcSeverity alone cannot establish a security classification.
    classification = (
        CATEGORIES.get(next(iter(classification_ids)), "other")
        if len(classification_ids) == 1
        else "other"
    )
    severity = value.get("msrc_severity")
    if severity is not None:
        severity = _text(severity, 100)
    return {
        "update_id": identity,
        "revision": revision,
        "title": _text(value.get("title"), 1000),
        "kbs": sorted(set(kbs)),
        "categories": normalized,
        "msrc_severity": severity,
        "is_hidden": False,
        "is_installed": False,
        "is_optional": optional,
        "is_mandatory": mandatory,
        "classification": classification,
        "actionable": classification in {"security", "quality"} and optional is False,
    }


def assess_windows_updates(inventory, *, evidence_collected_at, now, evidence_mode="inventory"):
    now = timestamp(now)
    if now is None:
        raise ValueError("Assessment time must be timezone-aware")
    collected = timestamp(evidence_collected_at)
    result = {
        "schema_version": 1,
        "engine_version": ENGINE_VERSION,
        "provider": PROVIDER,
        "source": SOURCE,
        "catalog_applicable": False,
        "status": "update_query_required",
        "reason": "Collect a new online Windows update query for this Windows client.",
        "evaluated_at": iso(now),
        "valid_until": None,
        "evidence_collected_at": iso(collected),
        "windows_updates": None,
        "limitations": list(LIMITATIONS),
    }

    def finish(status, reason):
        result.update(status=status, reason=reason)
        return result

    if (
        not is_windows_client(inventory)
        or type(inventory.get("schema_version")) is not int
        or inventory.get("schema_version") != 1
    ):
        return finish("update_query_required", "Windows client identity is not established.")
    section = inventory.get("windows_updates")
    if evidence_mode != "windows_updates" or section is None:
        return result
    if not isinstance(section, dict):
        return finish("update_query_incomplete", "The retained update query is malformed.")

    queried = timestamp(section.get("queried_at"))
    raw_items = section.get("items")
    items, seen, malformed = [], set(), False
    if isinstance(raw_items, list):
        for item in raw_items[:MAX_ITEMS]:
            try:
                normalized = _item(item)
                identity = (normalized["update_id"], normalized["revision"])
                if identity in seen:
                    raise ValueError("Duplicate update offer")
                seen.add(identity)
                items.append(normalized)
            except (ValueError, TypeError, AttributeError):
                malformed = True
        malformed = malformed or len(raw_items) > MAX_ITEMS
    else:
        malformed = True
    total = section.get("total")
    total_valid = type(total) is int and 0 <= total <= 1000000
    result_code = section.get("result_code")
    reboot = section.get("reboot_required")
    valid_reboot = reboot is None or type(reboot) is bool
    summary = {
        key: 0
        for key in (
            "offers",
            "security",
            "quality",
            "feature",
            "definition",
            "other",
            "optional",
            "optional_unknown",
            "actionable",
        )
    }
    for item in items:
        summary["offers"] += 1
        summary[item["classification"]] += 1
        summary["optional"] += item["is_optional"] is True
        summary["optional_unknown"] += item["is_optional"] is None
        summary["actionable"] += item["actionable"]
    report = {
        "source": PROVIDER,
        "mode": "online",
        "server_selection": "default",
        "queried_at": iso(queried),
        "status": (
            section.get("status")
            if section.get("status") in {"complete", "partial", "unavailable", "timeout"}
            else "unavailable"
        ),
        "result_code": result_code if type(result_code) is int and result_code in {2, 3} else None,
        "total": total if total_valid else len(items),
        "items": items,
        "items_truncated": bool(section.get("truncated") is not False or malformed),
        "summary": summary,
        "reboot_required": reboot if valid_reboot else None,
        "hidden_updates": "not_assessed",
        "drivers": "not_assessed",
        "superseded": "excluded",
    }
    result["windows_updates"] = report
    trusted_contract = (
        type(section.get("schema_version")) is int
        and section.get("schema_version") == 1
        and section.get("source") == PROVIDER
        and section.get("mode") == "online"
        and section.get("server_selection") == "default"
        and section.get("hidden_updates") == "not_assessed"
        and section.get("drivers") == "not_assessed"
        and section.get("superseded") == "excluded"
    )
    if not trusted_contract:
        return finish(
            "update_query_incomplete",
            "The retained query source or visibility scope is incomplete.",
        )
    if (
        collected is None
        or queried is None
        or queried > collected
        or collected > now
        or queried > now
        or now >= queried + MAX_AGE
        or now >= collected + MAX_AGE
    ):
        return finish(
            "stale_evidence",
            "Collect a new online update query; valid evidence is required within 24 hours.",
        )
    result["valid_until"] = iso(min(queried, collected) + MAX_AGE)
    complete = (
        section.get("status") == "complete"
        and type(result_code) is int
        and result_code == 2
        and section.get("truncated") is False
        and total_valid
        and total == len(items)
        and not malformed
        and valid_reboot
    )
    if not complete:
        return finish(
            "update_query_incomplete",
            "The online query was incomplete; retained offers are partial and absence is not "
            "evidence of patch coverage.",
        )
    if items:
        return finish(
            "updates_offered",
            "The configured Windows Update or WSUS source offered updates. Review security, "
            "quality, optional and feature offers separately.",
        )
    return finish(
        "no_update_offers",
        "The configured update source offered no visible software updates in this query. "
        "This does not establish that the device is fully patched.",
    )
