import ipaddress
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.asset import Asset
from app.models.customer import Customer
from app.models.host_audit import AuditCredential, HostAudit
from app.models.job import Job
from app.schemas.host_audit import (
    CredentialCreate,
    CredentialOut,
    HostAuditCreate,
    HostAuditDetail,
    HostAuditOut,
)
from app.services.audit_vault import (
    audit_hash,
    credential_scope,
    decrypt,
    encrypt,
    require_operator,
    verify_credential_target,
)

router = APIRouter(
    prefix="/host-audits",
    tags=["Authenticated inventory"],
    dependencies=[Depends(require_operator)],
)


@router.post("/credentials", response_model=CredentialOut, status_code=201)
def create_credential(payload: CredentialCreate, db: Session = Depends(get_db)):
    if not db.get(Customer, payload.customer_id):
        raise HTTPException(status_code=404, detail="Customer not found")
    try:
        cidrs = credential_scope(payload.allowed_cidrs)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    credential = AuditCredential(
        uuid=str(uuid.uuid4()),
        customer_id=payload.customer_id,
        name=payload.name.strip(),
        kind=payload.kind,
        username=payload.username,
        allowed_cidrs=cidrs,
        enabled=True,
    )
    credential.ciphertext = encrypt(
        credential,
        {
            name: value.get_secret_value()
            for name in ("password", "private_key", "passphrase")
            if (value := getattr(payload, name)) is not None
        },
    )
    db.add(credential)
    db.commit()
    db.refresh(credential)
    return credential


@router.get("/credentials", response_model=list[CredentialOut])
def list_credentials(customer_id: int, db: Session = Depends(get_db)):
    return (
        db.query(AuditCredential)
        .filter(AuditCredential.customer_id == customer_id)
        .order_by(AuditCredential.id.desc())
        .all()
    )


@router.post("/credentials/{credential_id}/revoke", response_model=CredentialOut)
def revoke_credential(credential_id: int, db: Session = Depends(get_db)):
    credential = (
        db.query(AuditCredential)
        .filter(AuditCredential.id == credential_id)
        .with_for_update()
        .first()
    )
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")
    credential.enabled = False
    credential.ciphertext = None
    db.commit()
    db.refresh(credential)
    return credential


@router.post("", response_model=HostAuditOut, status_code=201)
def start_audit(payload: HostAuditCreate, db: Session = Depends(get_db)):
    customer = (
        db.query(Customer).filter(Customer.id == payload.customer_id).with_for_update().first()
    )
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    credential = (
        db.query(AuditCredential)
        .filter(AuditCredential.id == payload.credential_id)
        .with_for_update()
        .first()
    )
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")
    try:
        target = verify_credential_target(credential, payload.target, customer.id)
        # Catch a wrong vault key before creating a job that cannot run.
        decrypt(credential)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if credential.kind.startswith("ssh_") and not payload.ssh_fingerprint:
        raise HTTPException(
            status_code=422,
            detail="An independently approved SSH SHA256 fingerprint is required",
        )
    if credential.kind == "winrm" and payload.ssh_fingerprint:
        raise HTTPException(
            status_code=422,
            detail="WinRM uses TLS certificate validation, not SSH fingerprints",
        )
    active = (
        db.query(HostAudit.id)
        .filter(
            HostAudit.customer_id == customer.id,
            HostAudit.target == target,
            HostAudit.job.has(Job.status.in_(["queued", "running"])),
        )
        .first()
    )
    if active:
        raise HTTPException(
            status_code=409,
            detail="A host audit of this customer/address is already active",
        )
    asset = (
        db.query(Asset)
        .filter(Asset.customer_id == customer.id, Asset.type == "ip", Asset.target == target)
        .order_by(Asset.id)
        .first()
    )
    if not asset:
        asset = Asset(
            customer_id=customer.id,
            type="ip",
            target=target,
            ip_address=target,
            name=target,
            exposure=("internal" if ipaddress.ip_address(target).is_private else "external"),
        )
        db.add(asset)
        db.flush()
    job = Job(
        asset_id=asset.id,
        plugin="hostinventory",
        status="queued",
        progress=0,
        message=(
            "Authenticated host inventory queued"
            if payload.mode == "inventory"
            else "Authenticated connection test queued"
        ),
    )
    db.add(job)
    db.flush()
    audit = HostAudit(
        customer_id=customer.id,
        credential_id=credential.id,
        asset_id=asset.id,
        job_id=job.id,
        target=target,
        port=payload.port or (5986 if credential.kind == "winrm" else 22),
        ssh_fingerprint=payload.ssh_fingerprint,
        mode=payload.mode,
        cancel_requested=False,
    )
    audit.scope_sha256 = audit_hash(audit, credential)
    db.add(audit)
    db.commit()
    db.refresh(audit)
    return audit


@router.get("", response_model=list[HostAuditOut])
def list_audits(customer_id: int, db: Session = Depends(get_db)):
    return (
        db.query(HostAudit)
        .filter(HostAudit.customer_id == customer_id)
        .order_by(HostAudit.id.desc())
        .limit(100)
        .all()
    )


@router.get("/{audit_id}", response_model=HostAuditDetail)
def audit_detail(audit_id: int, db: Session = Depends(get_db)):
    audit = db.get(HostAudit, audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Host audit not found")
    return audit


@router.post("/{audit_id}/cancel", response_model=HostAuditOut)
def cancel_audit(audit_id: int, db: Session = Depends(get_db)):
    audit = db.query(HostAudit).filter(HostAudit.id == audit_id).with_for_update().first()
    if not audit:
        raise HTTPException(status_code=404, detail="Host audit not found")
    if audit.job.status in {"queued", "running"}:
        audit.cancel_requested = True
        if audit.job.status == "queued":
            audit.job.status = "cancelled"
            audit.job.progress = 100
            audit.job.message = "Host audit cancelled before authentication"
            audit.completed_at = datetime.now(UTC)
        db.commit()
        db.refresh(audit)
    return audit
