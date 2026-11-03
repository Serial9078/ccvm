import ipaddress
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.asset import Asset
from app.models.customer import Customer
from app.models.job import Job
from app.models.network_scan import NetworkScan
from app.schemas.network_scan import (
    NetworkScanCreate,
    NetworkScanDetail,
    NetworkScanOut,
    ScopePreview,
)
from app.services.network_scope import (
    MAX_TARGETS,
    allowed_networks,
    build_scope,
    scope_hash,
    verify_scanner_scope,
)

router = APIRouter(prefix="/network-scans", tags=["Network scans"])


def scope_for(payload):
    try:
        scope = build_scope(
            payload.target,
            payload.exclusions,
            payload.profile,
            payload.ports,
            payload.rate,
            payload.timeout_seconds,
        )
        verify_scanner_scope(scope.targets)
        return scope
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


def serialize(scan, *, detail=False):
    jobs = [scan.discovery_job, scan.audit_job]
    states = {job.status for job in jobs}
    status = next(
        (
            value
            for value in ("running", "failed", "queued", "cancelled", "skipped")
            if value in states
        ),
        "finished",
    )
    if scan.cancel_requested and "running" in states:
        status = "cancelling"
    result = {
        name: getattr(scan, name)
        for name in NetworkScanOut.model_fields
        if name not in {"address_count", "status", "jobs"}
    }
    result.update(address_count=len(scan.targets), status=status, jobs=jobs)
    if detail:
        result["observations"] = scan.observations
    return result


@router.get("/capabilities")
def capabilities():
    try:
        allowed = allowed_networks()
    except ValueError as error:
        raise HTTPException(
            status_code=503, detail="Scanner CIDR configuration is invalid"
        ) from error
    return {
        "enabled": bool(allowed),
        "allowed_cidrs": [str(net) for net in allowed],
        "max_addresses": MAX_TARGETS,
        "tcp": True,
        "udp": False,
        "credentialed": False,
    }


@router.post("/preview", response_model=ScopePreview)
def preview(payload: NetworkScanCreate, db: Session = Depends(get_db)):
    if not db.get(Customer, payload.customer_id):
        raise HTTPException(status_code=404, detail="Customer not found")
    scope = scope_for(payload)
    return {
        "target": scope.target,
        "address_count": len(scope.targets),
        "sample": scope.targets[:8],
        "exclusions": scope.exclusions,
        "ports_per_host": scope.port_count,
        "minimum_portscan_seconds": scope.minimum_seconds,
        "ip_version": scope.version,
    }


@router.post("", response_model=NetworkScanOut, status_code=201)
def start_scan(payload: NetworkScanCreate, db: Session = Depends(get_db)):
    scope = scope_for(payload)
    # Serialize scope creation per customer, including the empty-asset case.
    customer = (
        db.query(Customer).filter(Customer.id == payload.customer_id).with_for_update().first()
    )
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    active = (
        db.query(NetworkScan.id)
        .filter(
            NetworkScan.customer_id == customer.id,
            NetworkScan.target == scope.target,
            or_(
                NetworkScan.discovery_job.has(Job.status.in_(["queued", "running"])),
                NetworkScan.audit_job.has(Job.status.in_(["queued", "running"])),
            ),
        )
        .first()
    )
    if active:
        raise HTTPException(
            status_code=409, detail="A scan of this customer/network is already active"
        )
    asset = (
        db.query(Asset)
        .filter(
            Asset.customer_id == customer.id, Asset.type == "network", Asset.target == scope.target
        )
        .order_by(Asset.id)
        .first()
    )
    if not asset:
        asset = Asset(
            customer_id=customer.id,
            type="network",
            target=scope.target,
            name=payload.name or scope.target,
            exposure=("internal" if ipaddress.ip_network(scope.target).is_private else "external"),
        )
        db.add(asset)
        db.flush()
    pipeline = str(uuid.uuid4())
    discovery = Job(
        asset_id=asset.id,
        pipeline_id=pipeline,
        plugin="networkdiscovery",
        status="queued",
        progress=0,
        message="Network discovery queued",
    )
    db.add(discovery)
    db.flush()
    audit = Job(
        asset_id=asset.id,
        pipeline_id=pipeline,
        parent_job_id=discovery.id,
        plugin="networkaudit",
        status="queued",
        progress=0,
        message="Waiting for networkdiscovery",
    )
    db.add(audit)
    db.flush()
    scan = NetworkScan(
        customer_id=customer.id,
        asset_id=asset.id,
        pipeline_id=pipeline,
        discovery_job_id=discovery.id,
        audit_job_id=audit.id,
        target=scope.target,
        targets=scope.targets,
        exclusions=scope.exclusions,
        profile=payload.profile,
        ports=scope.ports,
        rate=payload.rate,
        timeout_seconds=payload.timeout_seconds,
        scope_sha256=scope_hash(
            scope, payload.profile, payload.rate, payload.timeout_seconds, customer.id
        ),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return serialize(scan)


@router.get("", response_model=list[NetworkScanOut])
def list_scans(customer_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(NetworkScan)
    if customer_id is not None:
        query = query.filter(NetworkScan.customer_id == customer_id)
    return [serialize(scan) for scan in query.order_by(NetworkScan.id.desc()).limit(50).all()]


@router.get("/{scan_id}", response_model=NetworkScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(NetworkScan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Network scan not found")
    return serialize(scan, detail=True)


@router.post("/{scan_id}/cancel", response_model=NetworkScanOut)
def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(NetworkScan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Network scan not found")
    jobs = [scan.discovery_job, scan.audit_job]
    if not any(job.status in {"queued", "running"} for job in jobs) and not scan.cancel_requested:
        raise HTTPException(status_code=409, detail="Network scan is already complete")
    scan.cancel_requested = True
    for job in jobs:
        if job.status == "queued":
            job.status, job.progress, job.message = "cancelled", 100, "Network scan cancelled"
    db.commit()
    return serialize(scan)
