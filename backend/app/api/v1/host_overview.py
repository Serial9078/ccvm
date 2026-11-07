"""Private read-only overview of saved host evidence and patch applicability.

The newest retained inventory is authoritative for assessment selection. A failed
new attempt stays visible separately; it never substitutes missing evidence or
causes an older assessment to bless a newer inventory.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session, joinedload

from app.api.v1 import host_assessments, software_assessments
from app.database.deps import get_db
from app.models.asset import Asset
from app.models.customer import Customer
from app.models.host_assessment import HostAssessment
from app.models.host_audit import HostAudit
from app.models.software_assessment import SoftwareAssessment
from app.schemas.host_overview import HostOverviewOut
from app.services.audit_vault import require_operator
from app.services.software_assessment import ENGINE_VERSION as SOFTWARE_ENGINE
from app.services.software_catalog import numeric_version
from app.services.windows_patch_assessment import ENGINE_VERSION as WINDOWS_ENGINE
from app.services.windows_patch_sync import canonical_bytes
from app.services.windows_update_assessment import (
    ENGINE_VERSION as CLIENT_ENGINE,
)
from app.services.windows_update_assessment import (
    MAX_AGE as CLIENT_MAX_AGE,
)
from app.services.windows_update_assessment import (
    PROVIDER as CLIENT_PROVIDER,
)
from app.services.windows_update_assessment import (
    SOURCE as CLIENT_SOURCE,
)

router = APIRouter(
    prefix="/host-audits",
    tags=["Host patch overview"],
    dependencies=[Depends(require_operator)],
)
MAX_AGE = timedelta(days=7)
MAX_PRODUCTS = 50
MAX_MATCHES = 20
MAX_RESPONSE = 8 * 1024 * 1024
OS_FIELDS = (
    "family",
    "name",
    "hostname",
    "version",
    "kernel",
    "architecture",
    "product_type",
    "sku",
    "installation_type",
    "edition_id",
    "native_architecture",
)


def _utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _text(value, maximum=500):
    return value[:maximum] if isinstance(value, str) else ""


def _timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else None
    except (ValueError, TypeError, AttributeError):
        return None


def _catalog(db, checker, now):
    try:
        row, _payload = checker(db)
    except HTTPException as error:
        if error.status_code != 503:
            raise
        return None, True
    if row is None:
        return None, False
    retrieved = _utc(row.retrieved_at)
    return {
        "id": row.id,
        "retrieved_at": row.retrieved_at,
        "expired": retrieved > now or retrieved + MAX_AGE <= now,
    }, False


def _latest_runs(db, customer_id, limit):
    ranked = (
        db.query(
            HostAudit.id.label("audit_id"),
            func.row_number()
            .over(
                partition_by=HostAudit.asset_id,
                order_by=(HostAudit.created_at.desc(), HostAudit.id.desc()),
            )
            .label("position"),
        )
        .filter(HostAudit.customer_id == customer_id)
        .subquery()
    )
    return (
        db.query(HostAudit)
        .join(ranked, HostAudit.id == ranked.c.audit_id)
        .filter(ranked.c.position == 1)
        .options(joinedload(HostAudit.job))
        .order_by(HostAudit.created_at.desc(), HostAudit.id.desc())
        .limit(limit)
        .all()
    )


def _inventories(db, customer_id, asset_ids):
    if not asset_ids:
        return {}
    ranked = (
        db.query(
            HostAudit.id.label("audit_id"),
            func.row_number()
            .over(
                partition_by=HostAudit.asset_id,
                order_by=(HostAudit.created_at.desc(), HostAudit.id.desc()),
            )
            .label("position"),
        )
        .join(HostAudit.job)
        .filter(
            HostAudit.customer_id == customer_id,
            HostAudit.asset_id.in_(asset_ids),
            HostAudit.mode.in_(("inventory", "windows_updates")),
            HostAudit.completed_at.is_not(None),
            HostAudit.inventory.is_not(None),
            HostAudit.job.has(status="finished") | HostAudit.job.has(status="failed"),
        )
        .subquery()
    )
    rows = (
        db.query(HostAudit)
        .join(ranked, HostAudit.id == ranked.c.audit_id)
        .filter(ranked.c.position == 1)
        .options(joinedload(HostAudit.job))
        .all()
    )
    return {row.asset_id: row for row in rows}


def _latest_assessments(db, model, audit_ids):
    if not audit_ids:
        return {}
    ids = (
        db.query(func.max(model.id).label("assessment_id"))
        .filter(model.host_audit_id.in_(audit_ids))
        .group_by(model.host_audit_id)
        .subquery()
    )
    return {
        row.host_audit_id: row
        for row in db.query(model).join(ids, model.id == ids.c.assessment_id).all()
    }


def _binding(audit, asset, customer_id):
    if (
        asset is None
        or asset.customer_id != customer_id
        or asset.type != "ip"
        or audit.customer_id != customer_id
        or audit.asset_id != asset.id
        or audit.target != asset.target
        or audit.job is None
        or audit.job.asset_id != asset.id
        or audit.job.plugin != "hostinventory"
    ):
        raise HTTPException(status_code=409, detail="Host overview customer/asset identity changed")


def _platform(os_data):
    if os_data.get("family") == "Windows":
        product_type = str(os_data.get("product_type", ""))
        return {"1": "windows_client", "2": "windows_server", "3": "windows_server"}.get(
            product_type, "unclassified"
        )
    if os_data.get("family") == "Linux":
        return "linux"
    if os_data.get("family") in {"VMware", "ESXi"}:
        return "vmware"
    return "unclassified"


def _inventory(audit):
    data = audit.inventory
    if not isinstance(data, dict) or not isinstance(data.get("os"), dict):
        return None
    os_data = {
        key: _text(str(data["os"][key]) if type(data["os"].get(key)) is int else data["os"][key])
        for key in OS_FIELDS
        if key in data["os"]
    }
    if not os_data.get("family"):
        return None
    result = {
        "id": audit.id,
        "mode": audit.mode,
        "completed_at": audit.completed_at,
        "os": os_data,
    }
    for label, prefix in (("packages", "package"), ("hotfixes", "hotfix")):
        section = data.get(label, {})
        items = section.get("items") if isinstance(section, dict) else None
        result[prefix + "_count"] = len(items) if isinstance(items, list) else 0
        result[prefix + "_status"] = (
            _text(section.get("status"), 40) if isinstance(section, dict) else "unavailable"
        ) or "unavailable"
    updates = data.get("windows_updates")
    result["windows_updates"] = (
        {
            "has_evidence": True,
            "queried_at": _text(updates.get("queried_at"), 60) or None,
            "status": _text(updates.get("status"), 40),
            "result_code": (
                updates.get("result_code") if type(updates.get("result_code")) is int else None
            ),
            "total": _number(updates.get("total")),
            "reboot_required": (
                updates.get("reboot_required")
                if type(updates.get("reboot_required")) is bool
                else None
            ),
            "truncated": updates.get("truncated") is not False,
        }
        if isinstance(updates, dict)
        else None
    )
    return result


def _number(value):
    return value if type(value) is int and 0 <= value <= 100000000 else 0


def _reference_fix(item):
    """Derive the highest applicable published fixed bound from the full result.

    This is only a reference within the checked advisory scope. Truncated,
    missing or malformed retained matches cannot establish that reference.
    The overview's smaller display cap does not change the retained proof.
    """
    components = {"edge-windows": 4, "7zip-windows": 2}.get(item.get("product_key"))
    matches = item.get("matches")
    if (
        components is None
        or item.get("matches_truncated") is not False
        or not isinstance(matches, list)
        or not matches
        or type(item.get("matches_total")) is not int
        or len(matches) != item["matches_total"]
    ):
        return None, False
    try:
        installed = numeric_version(item.get("version"), components=components)
        bounds = []
        for match in matches:
            if not isinstance(match, dict):
                return None, False
            ranges = match.get("affected_ranges")
            if not isinstance(ranges, list) or not 1 <= len(ranges) <= 32:
                return None, False
            matched = False
            for affected in ranges:
                if not isinstance(affected, dict):
                    return None, False
                lower = numeric_version(affected.get("introduced"))
                if len(lower) != components and affected.get("introduced") != "0":
                    return None, False
                lower += (0,) * (components - len(lower))
                upper = numeric_version(affected.get("fixed"), components=components)
                if lower >= upper:
                    return None, False
                if lower <= installed < upper:
                    matched = True
                    bounds.append((upper, affected["fixed"]))
            if not matched:
                return None, False
        return max(bounds)[1], True
    except (ValueError, TypeError, KeyError):
        return None, False


def _software_result(result):
    summary = result.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    coverage = result.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    output = {
        "reason": _text(result.get("reason"), 1000),
        "valid_until": _text(result.get("valid_until"), 60) or None,
        "summary": {
            key: _number(summary.get(key))
            for key in (
                "inventory_entries",
                "identified_entries",
                "assessed_entries",
                "unassessed_entries",
                "product_versions",
                "matched_product_versions",
                "cve_matches",
            )
        },
        "coverage": {
            key: _text(coverage.get(key), 500)
            for key in (
                "scope",
                "status",
                "package_status",
                "catalog_start",
                "catalog_end",
            )
        },
        "products_total": _number(result.get("products_total")),
        "products_truncated": bool(result.get("products_truncated")),
    }
    vendor = coverage.get("vendor_catalog")
    output["coverage"]["vendor_catalog"] = (
        [
            {
                "product_key": _text(row.get("product_key"), 40),
                "scope": _text(row.get("scope"), 1000),
                "discovered": _number(row.get("discovered")),
                "parsed": _number(row.get("parsed")),
                "unavailable_count": (
                    len(row.get("unavailable_cves", []))
                    if isinstance(row.get("unavailable_cves"), list)
                    else 0
                ),
            }
            for row in vendor[:2]
            if isinstance(row, dict)
        ]
        if isinstance(vendor, list)
        else []
    )
    products = result.get("products")
    products = products if isinstance(products, list) else []
    products = sorted(
        (item for item in products if isinstance(item, dict)),
        key=lambda item: not bool(_number(item.get("matches_total"))),
    )
    output["products_total"] = max(len(products), output["products_total"])
    output["products_truncated"] = bool(
        output["products_truncated"] or len(products) > MAX_PRODUCTS
    )
    output["products"] = []
    remaining = MAX_MATCHES
    for item in products[:MAX_PRODUCTS]:
        if not isinstance(item, dict):
            continue
        product = {
            key: _text(item.get(key), 1000)
            for key in (
                "product_key",
                "name",
                "version",
                "publisher",
                "status",
                "reason",
                "catalog_scope",
                "evidence_basis",
            )
        }
        product["reference_fix"], product["reference_fix_complete"] = _reference_fix(item)
        product["checked_cves"] = _number(item.get("checked_cves"))
        product["matches_total"] = _number(item.get("matches_total"))
        matches = item.get("matches")
        matches = matches if isinstance(matches, list) else []
        product["matches"] = []
        for match in matches[:remaining]:
            if not isinstance(match, dict):
                continue
            projected = {
                key: _text(match.get(key), 1000)
                for key in (
                    "cve",
                    "title",
                    "severity",
                    "source_product",
                )
            }
            ranges = match.get("affected_ranges")
            projected["affected_ranges"] = (
                [
                    {
                        "introduced": _text(row.get("introduced"), 40),
                        "fixed": _text(row.get("fixed"), 40),
                    }
                    for row in ranges[:32]
                    if isinstance(row, dict)
                ]
                if isinstance(ranges, list)
                else []
            )
            urls = match.get("source_urls")
            projected["source_urls"] = (
                [_text(url, 512) for url in urls[:16] if isinstance(url, str)]
                if isinstance(urls, list)
                else []
            )
            product["matches"].append(projected)
        product["matches_truncated"] = bool(
            item.get("matches_truncated") or len(matches) > remaining
        )
        remaining = max(0, remaining - len(product["matches"]))
        output["products"].append(product)
    return output


def _windows_update_result(result):
    report = result.get("windows_updates")
    output = {
        "provider": CLIENT_PROVIDER,
        "source": CLIENT_SOURCE,
        "reason": _text(result.get("reason"), 1000),
        "valid_until": _text(result.get("valid_until"), 60) or None,
        "limitations": (
            [
                _text(value, 1000)
                for value in result.get("limitations", [])[:10]
                if isinstance(value, str)
            ]
            if isinstance(result.get("limitations"), list)
            else []
        ),
        "windows_updates": None,
    }
    if not isinstance(report, dict):
        return output
    summary = report.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    items = report.get("items")
    items = items if isinstance(items, list) else []
    projected = {
        "source": CLIENT_PROVIDER,
        "mode": _text(report.get("mode"), 30),
        "server_selection": _text(report.get("server_selection"), 30),
        "queried_at": _text(report.get("queried_at"), 60) or None,
        "status": _text(report.get("status"), 40),
        "result_code": (
            report.get("result_code") if type(report.get("result_code")) is int else None
        ),
        "total": _number(report.get("total")),
        "reboot_required": (
            report.get("reboot_required") if type(report.get("reboot_required")) is bool else None
        ),
        "hidden_updates": "not_assessed",
        "drivers": "not_assessed",
        "superseded": "excluded",
        "items_truncated": bool(report.get("items_truncated") or len(items) > 20),
        "summary": {
            key: _number(summary.get(key))
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
        },
        "items": [],
    }
    for item in items[:20]:
        if not isinstance(item, dict):
            continue
        projected["items"].append(
            {
                "update_id": _text(item.get("update_id"), 40),
                "revision": _number(item.get("revision")),
                "title": _text(item.get("title"), 1000),
                "kbs": (
                    [_text(kb, 40) for kb in item.get("kbs", [])[:32]]
                    if isinstance(item.get("kbs"), list)
                    else []
                ),
                "classification": _text(item.get("classification"), 40),
                "is_optional": (
                    item.get("is_optional") if type(item.get("is_optional")) is bool else None
                ),
                "is_mandatory": (
                    item.get("is_mandatory") if type(item.get("is_mandatory")) is bool else None
                ),
                "actionable": item.get("actionable") is True,
                "categories": (
                    [
                        {key: _text(category.get(key), 500) for key in ("id", "name", "type")}
                        for category in item.get("categories", [])[:8]
                        if isinstance(category, dict)
                    ]
                    if isinstance(item.get("categories"), list)
                    else []
                ),
            }
        )
    output["windows_updates"] = projected
    return output


def _assessment(row, audit, catalog, engine, now, *, software=False):
    if row is None:
        return None
    if row.customer_id != audit.customer_id or row.asset_id != audit.asset_id:
        return None
    result = row.result
    if not isinstance(result, dict) or result.get("status") != row.status:
        return None
    try:
        canonical_bytes(result, limit=4 * 1024 * 1024)
        digest = hashlib.sha256(canonical_bytes(audit.inventory, limit=8 * 1024 * 1024)).hexdigest()
    except (ValueError, TypeError):
        digest = None
    valid_until = _timestamp(result.get("valid_until"))
    evaluated = _utc(row.evaluated_at)
    collected = _utc(audit.completed_at)
    wua = not software and row.engine_version == CLIENT_ENGINE
    maximum_age = CLIENT_MAX_AGE if wua else MAX_AGE
    projection = (
        _software_result(result)
        if software
        else (
            _windows_update_result(result)
            if wua
            else {
                key: _text(result.get(key), 1000) or None
                for key in ("reason", "valid_until", "installed_build", "baseline_build")
            }
        )
    )
    if not software and not wua:
        kbs = result.get("baseline_kbs")
        projection["baseline_kbs"] = (
            [_text(kb, 40) for kb in kbs[:32]] if isinstance(kbs, list) else []
        )
        product = result.get("product")
        projection["product"] = (
            {
                key: _text(product.get(key), 100)
                for key in ("id", "name", "installation_type", "edition_id")
            }
            if isinstance(product, dict)
            else None
        )
    return {
        "id": row.id,
        "status": row.status,
        "evaluated_at": row.evaluated_at,
        "expired": (
            valid_until is None
            or valid_until <= now
            or evaluated > now
            or evaluated + maximum_age <= now
            or collected > now
            or collected + maximum_age <= now
        ),
        "provider": (
            CLIENT_PROVIDER if wua else ("vendor-software-catalog" if software else "msrc-cvrf")
        ),
        "source": (
            CLIENT_SOURCE if wua else ("vendor-software-catalog" if software else "msrc-cvrf")
        ),
        "catalog_applicable": not wua,
        "current_catalog": bool(
            not wua and catalog and not catalog["expired"] and row.catalog_id == catalog["id"]
        ),
        "evidence_matches": digest is not None and row.evidence_sha256 == digest,
        "engine_current": (
            row.engine_version == engine
            and result.get("engine_version") == engine
            and (
                not wua
                or (
                    result.get("provider") == CLIENT_PROVIDER
                    and result.get("source") == CLIENT_SOURCE
                    and result.get("catalog_applicable") is False
                    and row.catalog_id is None
                )
            )
        ),
        "result": projection,
    }


@router.get("/overview", response_model=HostOverviewOut)
def overview(
    customer_id: int = Query(..., ge=1),
    limit: int = Query(200, ge=1, le=500),
    db: Session = Depends(get_db),
):
    if db.get(Customer, customer_id) is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    now = datetime.now(UTC)
    windows, windows_invalid = _catalog(db, host_assessments.checked_catalog, now)
    software, software_invalid = _catalog(db, software_assessments.checked_catalog, now)
    issues = []
    if windows_invalid:
        issues.append("windows_catalog_invalid")
    if software_invalid:
        issues.append("software_catalog_invalid")
    total = (
        db.query(func.count(distinct(HostAudit.asset_id)))
        .filter(HostAudit.customer_id == customer_id)
        .scalar()
    )
    latest = _latest_runs(db, customer_id, limit)
    asset_ids = [row.asset_id for row in latest]
    assets = {row.id: row for row in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()}
    inventories = _inventories(db, customer_id, asset_ids)
    audit_ids = [row.id for row in inventories.values()]
    windows_rows = _latest_assessments(db, HostAssessment, audit_ids)
    software_rows = _latest_assessments(db, SoftwareAssessment, audit_ids)
    hosts, size = [], 0
    for latest_run in latest:
        asset = assets.get(latest_run.asset_id)
        _binding(latest_run, asset, customer_id)
        retained = inventories.get(asset.id)
        inventory = None
        host_issues = []
        if retained:
            _binding(retained, asset, customer_id)
            inventory = _inventory(retained)
        if latest_run.job.status in {"queued", "running"}:
            host_issues.append("collection_pending")
        elif latest_run.job.status == "failed":
            host_issues.append(
                "latest_collection_failed"
                if latest_run.mode in {"inventory", "windows_updates"}
                else "latest_connection_failed"
            )
        platform = _platform(inventory["os"]) if inventory else "unclassified"
        if inventory is None:
            host_issues.append("inventory_missing")
        else:
            collected = _utc(inventory["completed_at"])
            if collected > now or collected + MAX_AGE <= now:
                host_issues.append("inventory_stale")
            if any(inventory[name] != "complete" for name in ("package_status", "hotfix_status")):
                host_issues.append("inventory_partial")
        patch = (
            _assessment(
                windows_rows.get(retained.id),
                retained,
                windows,
                CLIENT_ENGINE if platform == "windows_client" else WINDOWS_ENGINE,
                now,
            )
            if inventory
            else None
        )
        apps = (
            _assessment(
                software_rows.get(retained.id),
                retained,
                software,
                SOFTWARE_ENGINE,
                now,
                software=True,
            )
            if inventory
            else None
        )
        if platform in {"windows_server", "windows_client"}:
            if patch is None:
                host_issues.append("windows_assessment_missing")
            if apps is None:
                host_issues.append("software_assessment_missing")
            if platform == "windows_client":
                if patch is None or patch.get("provider") != CLIENT_PROVIDER:
                    host_issues.append("windows_client_update_query_required")
                elif patch["status"] in {
                    "update_query_required",
                    "update_query_incomplete",
                    "stale_evidence",
                }:
                    host_issues.append(patch["status"])
        elif platform in {"linux", "vmware"}:
            host_issues.append("patch_assessment_unsupported")
        elif inventory:
            host_issues.append("inventory_identity_incomplete")
        host = {
            "asset_id": asset.id,
            "target": asset.target,
            "platform": platform,
            "latest_run": {
                "id": latest_run.id,
                "credential_id": latest_run.credential_id,
                "port": latest_run.port,
                "winrm_transport": latest_run.winrm_transport,
                "ssh_fingerprint": latest_run.ssh_fingerprint,
                "mode": latest_run.mode,
                "status": latest_run.job.status,
                "message": _text(latest_run.job.message, 1000),
                "created_at": latest_run.created_at,
                "completed_at": latest_run.completed_at,
            },
            "inventory": inventory,
            "windows_assessment": patch,
            "software_assessment": apps,
            "issues": host_issues,
        }
        measured = len(json.dumps(host, default=str, ensure_ascii=True).encode())
        if apps and size + measured > MAX_RESPONSE - 4 * 1024 * 1024:
            apps["result"]["products"] = []
            apps["result"]["products_truncated"] = True
            host_issues.append("software_details_truncated")
            measured = len(json.dumps(host, default=str, ensure_ascii=True).encode())
        if size + measured > MAX_RESPONSE - 16384:
            issues.append("overview_size_limit")
            break
        size += measured
        hosts.append(host)
    return {
        "customer_id": customer_id,
        "generated_at": now,
        "hosts": hosts,
        "catalogs": {"windows": windows, "software": software},
        "issues": issues,
        "limit": limit,
        "hosts_total": total,
        "hosts_truncated": total > len(hosts),
    }
