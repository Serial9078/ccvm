"""Private capability metadata and positively observed devices, without probing.

The discovery queue contains historical positive TCP observations, not every
address that a scan attempted. Service banners are reported evidence only and
never determine an operating system or prove patch status.
"""

import ipaddress
from datetime import UTC

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session, aliased, defer, joinedload

from app.database.deps import get_db
from app.models.asset import Asset
from app.models.customer import Customer
from app.models.host import Host
from app.models.host_audit import HostAudit
from app.models.job import Job
from app.models.network_scan import NetworkObservation, NetworkScan
from app.schemas.scanner_capabilities import DiscoveredDevicesOut, ScannerCapabilitiesOut
from app.services.audit_vault import require_operator
from app.services.network_rules import coverage_for
from app.services.network_scope import build_scope, scope_hash
from app.services.scanner_capabilities import capabilities

router = APIRouter(
    prefix="/host-audits",
    tags=["Scanner coverage and discovered devices"],
    dependencies=[Depends(require_operator)],
)
MAX_SERVICES = 64


def _invalid():
    raise HTTPException(status_code=409, detail="Stored discovery/customer identity changed")


def _address(value):
    try:
        address = ipaddress.ip_address(value)
        if str(address) != value or address.is_multicast or address.is_unspecified or "%" in value:
            _invalid()
        return value
    except (ValueError, TypeError):
        _invalid()


def _utc(value):
    if value is None:
        _invalid()
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _text(value, maximum=256):
    if not isinstance(value, str):
        return None
    value = "".join(char for char in value if ord(char) >= 32 and not 127 <= ord(char) <= 159)
    return value[:maximum] or None


def _candidates(db, customer_id):
    # The importer stores an array consisting only of open TCP services.
    # Requiring its first positive item excludes silent target attempts and
    # closed-only/missing observations before ranking or counting addresses.
    ranked = (
        db.query(
            NetworkObservation.id.label("observation_id"),
            func.row_number()
            .over(
                partition_by=NetworkObservation.ip_address,
                order_by=(
                    NetworkScan.created_at.desc(),
                    NetworkScan.id.desc(),
                    NetworkObservation.id.desc(),
                ),
            )
            .label("position"),
        )
        .join(NetworkScan, NetworkScan.id == NetworkObservation.scan_id)
        .filter(
            NetworkScan.customer_id == customer_id,
            NetworkObservation.services[0]["state"].as_string() == "open",
            NetworkObservation.services[0]["protocol"].as_string() == "tcp",
        )
        .subquery()
    )
    root, asset = aliased(Asset), aliased(Asset)
    discovery, audit = aliased(Job), aliased(Job)
    return (
        db.query(NetworkObservation, NetworkScan, root, asset, Host, discovery, audit)
        .join(ranked, NetworkObservation.id == ranked.c.observation_id)
        .join(NetworkScan, NetworkScan.id == NetworkObservation.scan_id)
        .outerjoin(root, root.id == NetworkScan.asset_id)
        .outerjoin(asset, asset.id == NetworkObservation.asset_id)
        .outerjoin(Host, Host.id == NetworkObservation.host_id)
        .outerjoin(discovery, discovery.id == NetworkScan.discovery_job_id)
        .outerjoin(audit, audit.id == NetworkScan.audit_job_id)
        .filter(ranked.c.position == 1)
        .options(defer(NetworkObservation.services, raiseload=True))
        .order_by(
            NetworkScan.created_at.desc(), NetworkScan.id.desc(), NetworkObservation.id.desc()
        )
        .yield_per(200)
    )


def _binding(row, customer_id, scopes):
    observation, scan, root, asset, host, discovery, audit = row
    address = _address(observation.ip_address)
    if (
        root is None
        or asset is None
        or host is None
        or discovery is None
        or audit is None
        or scan.customer_id != customer_id
        or root.customer_id != customer_id
        or root.type != "network"
        or root.target != scan.target
        or asset.customer_id != customer_id
        or asset.type != "ip"
        or asset.target != address
        or (asset.ip_address is not None and _address(asset.ip_address) != address)
        or host.customer_id != customer_id
        or host.domain_id is not None
        or host.source != "nmap-network"
        or host.ip_address != address
        or discovery.asset_id != root.id
        or discovery.plugin != "networkdiscovery"
        or discovery.pipeline_id != scan.pipeline_id
        or discovery.domain_id is not None
        or discovery.parent_job_id is not None
        or audit.asset_id != root.id
        or audit.plugin != "networkaudit"
        or audit.pipeline_id != scan.pipeline_id
        or audit.domain_id is not None
        or audit.parent_job_id != discovery.id
    ):
        _invalid()
    if scan.id not in scopes:
        try:
            scope = build_scope(
                scan.target,
                scan.exclusions,
                scan.profile,
                scan.ports,
                scan.rate,
                scan.timeout_seconds,
            )
            if scan.targets != scope.targets or scan.scope_sha256 != scope_hash(
                scope, scan.profile, scan.rate, scan.timeout_seconds, customer_id
            ):
                _invalid()
        except (ValueError, TypeError):
            _invalid()
        scopes[scan.id] = set(scope.targets)
    if address not in scopes[scan.id]:
        _invalid()
    return address


def _services(observation, audit_status):
    if not isinstance(observation.services, list):
        _invalid()
    services = []
    for item in observation.services:
        if (
            not isinstance(item, dict)
            or item.get("state") != "open"
            or item.get("protocol") != "tcp"
        ):
            continue
        port = item.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            _invalid()
        checks = item.get("checks", [])
        if not isinstance(checks, list) or any(not isinstance(check, dict) for check in checks):
            _invalid()
        coverage = coverage_for(
            {
                "method": item.get("method"),
                "service": item.get("service"),
                "tunnel": item.get("tunnel"),
                "checks": checks,
            },
            audit_status,
        )
        services.append(
            {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": _text(item.get("service")),
                "product": _text(item.get("product")),
                "version": _text(item.get("version"), 128),
                "audit_coverage": coverage,
            }
        )
    return services


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
        .filter(
            HostAudit.customer_id == customer_id,
            HostAudit.asset_id.in_(asset_ids),
            HostAudit.mode.in_(["inventory", "windows_updates", "cim_inventory"]),
        )
        .subquery()
    )
    rows = (
        db.query(
            HostAudit,
            HostAudit.inventory["os"]["family"].as_string(),
            HostAudit.inventory["packages"]["status"].as_string(),
            HostAudit.inventory["hotfixes"]["status"].as_string(),
        )
        .join(ranked, HostAudit.id == ranked.c.audit_id)
        .filter(ranked.c.position == 1)
        .options(joinedload(HostAudit.job), defer(HostAudit.inventory, raiseload=True))
        .all()
    )
    return {row[0].asset_id: row for row in rows}


def _inventory_status(row, asset, customer_id):
    if row is None:
        return {
            "inventory_status": "not_inventoried",
            "host_audit_id": None,
            "inventory_collected_at": None,
        }
    audit, family, package_status, hotfix_status = row
    if (
        audit.customer_id != customer_id
        or audit.asset_id != asset.id
        or audit.target != asset.target
        or audit.job is None
        or audit.job.asset_id != asset.id
        or audit.job.plugin != "hostinventory"
    ):
        _invalid()
    status = audit.job.status
    has_evidence = (
        family in {"Windows", "Linux", "VMware", "ESXi"} and audit.completed_at is not None
    )
    if status in {"queued", "running"}:
        state = "pending"
    elif not has_evidence:
        state = "failed"
    elif (
        status == "finished"
        and package_status == "complete"
        and hotfix_status in {"complete", "not_applicable"}
    ):
        state = "inventoried"
    else:
        state = "partial"
    return {
        "inventory_status": state,
        "host_audit_id": audit.id,
        "inventory_collected_at": _utc(audit.completed_at) if has_evidence else None,
    }


@router.get("/capabilities", response_model=ScannerCapabilitiesOut)
def implementation_capabilities():
    return capabilities()


@router.get("/discovered", response_model=DiscoveredDevicesOut)
def discovered(
    customer_id: int = Query(..., ge=1),
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    if db.get(Customer, customer_id) is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    selected, scopes, total = [], {}, 0
    # Stream bounded metadata while validating/counting all distinct positive
    # addresses. Full service arrays are fetched only for the requested page.
    for row in _candidates(db, customer_id):
        _binding(row, customer_id, scopes)
        if offset <= total < offset + limit:
            selected.append(row)
        total += 1
    full = (
        {
            row.id: row
            for row in db.query(NetworkObservation)
            .filter(NetworkObservation.id.in_([row[0].id for row in selected]))
            .all()
        }
        if selected
        else {}
    )
    inventories = _inventories(db, customer_id, [row[3].id for row in selected])
    items = []
    for row in selected:
        observation, scan, _root, asset, _host, discovery, audit = row
        services = _services(full[observation.id], audit.status)
        if not services:
            _invalid()
        items.append(
            {
                "asset_id": asset.id,
                "ip_address": observation.ip_address,
                "last_seen": _utc(scan.created_at),
                "scan_id": scan.id,
                "discovery_status": discovery.status,
                "services": services[:MAX_SERVICES],
                "services_total": len(services),
                "services_truncated": len(services) > MAX_SERVICES,
                **_inventory_status(inventories.get(asset.id), asset, customer_id),
            }
        )
    return {
        "customer_id": customer_id,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(items) < total,
        "items": items,
        "limitations": [
            (
                "Nur gespeicherte positive TCP-Beobachtungen; schweigende oder nur versuchte "
                "Adressen sind keine erkannten Geräte."
            ),
            (
                "Produkt und Version stammen aus der Diensterkennung und bestätigen kein "
                "Betriebssystem oder einen Patchstand."
            ),
            (
                "Der Beobachtungszeitpunkt ist das Erstellungsdatum des zugehörigen Scans, "
                "kein erneuter Erreichbarkeitstest."
            ),
            (
                "Die Inventurkennzeichnung ist kein Sicherheits- oder Patchurteil. "
                "Es wird keine Anmeldung oder Inventur automatisch gestartet."
            ),
        ],
    }
