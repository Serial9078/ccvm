"""Private software version assessments from saved evidence, without host access."""

import copy
import hashlib
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.host_assessments import assessment_output, checked_audit, utc
from app.database.deps import get_db
from app.models.software_assessment import SoftwareAdvisoryCatalog, SoftwareAssessment
from app.schemas.software_assessment import (
    SoftwareAssessmentCreate,
    SoftwareAssessmentOut,
    SoftwareCatalogOut,
)
from app.services.audit_vault import require_operator

router = APIRouter(
    prefix="/host-audits",
    tags=["Software version assessments"],
    dependencies=[Depends(require_operator)],
)


def checked_catalog(db):
    from app.services.software_catalog_sync import catalog_digest, validated_catalog

    row = (
        db.query(SoftwareAdvisoryCatalog)
        .order_by(SoftwareAdvisoryCatalog.retrieved_at.desc(), SoftwareAdvisoryCatalog.id.desc())
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
            status_code=503, detail="Stored software catalog failed validation"
        ) from None
    return row, normalized


@router.get("/software-catalog", response_model=SoftwareCatalogOut | None)
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
        "coverage": payload["coverage"],
        "expired": utc(row.retrieved_at) + timedelta(days=7) <= datetime.now(UTC),
    }


@router.post("/{audit_id}/assess-software", response_model=SoftwareAssessmentOut)
def create_assessment(
    audit_id: int, payload: SoftwareAssessmentCreate | None = None, db: Session = Depends(get_db)
):
    from app.services.software_assessment import ENGINE_VERSION, assess_software
    from app.services.software_catalog_sync import canonical_bytes

    audit = checked_audit(db, audit_id, lock=True)
    if audit.mode == "cim_inventory":
        raise HTTPException(
            status_code=422,
            detail="CIM base inventory does not collect installed software for assessment",
        )
    if (
        audit.mode not in {"inventory", "windows_updates"}
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
        db.query(SoftwareAssessment)
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
        result = assess_software(
            copy.deepcopy(audit.inventory),
            data,
            evidence_collected_at=utc(audit.completed_at),
            now=now,
        )
        canonical_bytes(result, limit=8 * 1024 * 1024)
        if not isinstance(result, dict) or not isinstance(result.get("status"), str):
            raise ValueError("Invalid assessment result")
    except (ValueError, TypeError, KeyError):
        raise HTTPException(
            status_code=422, detail="Stored inventory could not be assessed"
        ) from None
    row = SoftwareAssessment(
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


@router.get("/{audit_id}/software-assessments", response_model=list[SoftwareAssessmentOut])
def list_assessments(audit_id: int, db: Session = Depends(get_db)):
    audit = checked_audit(db, audit_id)
    rows = (
        db.query(SoftwareAssessment)
        .filter_by(
            host_audit_id=audit.id,
            customer_id=audit.customer_id,
            asset_id=audit.asset_id,
        )
        .order_by(SoftwareAssessment.id.desc())
        .limit(20)
        .all()
    )
    return [assessment_output(row) for row in rows]
