"""Local evaluation of retained evidence; no host login or network operations."""

import copy
import hashlib
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.asset import Asset
from app.models.host_assessment import HostAssessment, WindowsPatchCatalog
from app.models.host_audit import HostAudit
from app.schemas.host_assessment import AssessmentCreate, HostAssessmentOut, PatchCatalogOut
from app.services.audit_vault import require_operator
from app.services.windows_patch_sync import canonical_bytes, catalog_digest, validated_catalog

router = APIRouter(
    prefix="/host-audits",
    tags=["Windows patch assessments"],
    dependencies=[Depends(require_operator)],
)


def utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def expired(value, now):
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return date.tzinfo is None or date <= now
    except (ValueError, TypeError, AttributeError):
        return True


def assessment_output(row, now=None):
    now = now or datetime.now(UTC)
    return {
        key: getattr(row, key)
        for key in (
            "id",
            "customer_id",
            "asset_id",
            "host_audit_id",
            "catalog_id",
            "engine_version",
            "evidence_sha256",
            "status",
            "result",
            "evaluated_at",
        )
    } | {"expired": expired(row.result.get("valid_until"), now)}


def checked_catalog(db):
    row = (
        db.query(WindowsPatchCatalog)
        .order_by(WindowsPatchCatalog.retrieved_at.desc(), WindowsPatchCatalog.id.desc())
        .first()
    )
    if row is None:
        return None, None
    try:
        normalized = validated_catalog(row.payload)
        if (
            catalog_digest(normalized) != row.sha256
            or normalized["source"] != row.source
            or datetime.fromisoformat(normalized["retrieved_at"].replace("Z", "+00:00"))
            != utc(row.retrieved_at)
        ):
            raise ValueError("Catalog metadata mismatch")
    except (ValueError, TypeError, KeyError):
        raise HTTPException(
            status_code=503, detail="Stored patch catalog failed validation"
        ) from None
    return row, normalized


@router.get("/patch-catalog", response_model=PatchCatalogOut | None)
def latest_catalog(db: Session = Depends(get_db)):
    row, payload = checked_catalog(db)
    if row is None:
        return None
    return {
        "id": row.id,
        "source": row.source,
        "sha256": row.sha256,
        "retrieved_at": row.retrieved_at,
        "created_at": row.created_at,
        "coverage_start": payload["coverage_start"],
        "coverage_end": payload["coverage_end"],
        "document_ids": [document["id"] for document in payload["documents"]],
        "entry_count": len(payload["entries"]),
        "expired": utc(row.retrieved_at) + timedelta(days=7) <= datetime.now(UTC),
    }


def checked_audit(db, audit_id, *, lock=False):
    query = db.query(HostAudit).filter(HostAudit.id == audit_id)
    if lock:
        query = query.with_for_update()
    audit = query.first()
    if audit is None:
        raise HTTPException(status_code=404, detail="Host audit not found")
    asset = db.get(Asset, audit.asset_id)
    if (
        asset is None
        or asset.customer_id != audit.customer_id
        or asset.type != "ip"
        or asset.target != audit.target
        or audit.job.asset_id != asset.id
    ):
        raise HTTPException(status_code=409, detail="Host audit customer/asset identity changed")
    return audit


@router.post("/{audit_id}/assess", response_model=HostAssessmentOut)
def create_assessment(
    audit_id: int, payload: AssessmentCreate | None = None, db: Session = Depends(get_db)
):
    from app.services.windows_patch_assessment import ENGINE_VERSION, assess_windows_patches

    audit = checked_audit(db, audit_id, lock=True)
    if (
        audit.mode != "inventory"
        or not isinstance(audit.inventory, dict)
        or audit.completed_at is None
        or audit.job.status not in {"finished", "failed"}
    ):
        raise HTTPException(status_code=422, detail="A completed host inventory is required")
    now = datetime.now(UTC)
    try:
        evidence_hash = hashlib.sha256(
            canonical_bytes(audit.inventory, limit=8 * 1024 * 1024)
        ).hexdigest()
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=422, detail="Stored inventory failed assessment validation"
        ) from None
    catalog, data = checked_catalog(db)
    prior = (
        db.query(HostAssessment)
        .filter_by(
            host_audit_id=audit.id,
            catalog_id=catalog.id if catalog else None,
            engine_version=ENGINE_VERSION,
            evidence_sha256=evidence_hash,
        )
        .first()
    )
    if prior:
        if prior.customer_id != audit.customer_id or prior.asset_id != audit.asset_id:
            raise HTTPException(status_code=409, detail="Stored assessment identity changed")
        return assessment_output(prior, now)
    try:
        result = assess_windows_patches(
            copy.deepcopy(audit.inventory),
            data,
            evidence_collected_at=utc(audit.completed_at),
            now=now,
        )
        canonical_bytes(result, limit=4 * 1024 * 1024)
        if not isinstance(result, dict) or not isinstance(result.get("status"), str):
            raise ValueError("Invalid assessment result")
    except (ValueError, TypeError, KeyError):
        raise HTTPException(
            status_code=422, detail="Stored inventory could not be assessed"
        ) from None
    row = HostAssessment(
        customer_id=audit.customer_id,
        asset_id=audit.asset_id,
        host_audit_id=audit.id,
        catalog_id=catalog.id if catalog else None,
        engine_version=ENGINE_VERSION,
        evidence_sha256=evidence_hash,
        status=result["status"],
        result=result,
        evaluated_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return assessment_output(row, now)


@router.get("/{audit_id}/assessments", response_model=list[HostAssessmentOut])
def list_assessments(audit_id: int, db: Session = Depends(get_db)):
    audit = checked_audit(db, audit_id)
    rows = (
        db.query(HostAssessment)
        .filter_by(
            host_audit_id=audit.id,
            customer_id=audit.customer_id,
            asset_id=audit.asset_id,
        )
        .order_by(HostAssessment.id.desc())
        .limit(20)
        .all()
    )
    return [assessment_output(row) for row in rows]
