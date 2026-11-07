"""Import explicit software version evidence; never use target credentials."""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.software_assessment import SoftwareAdvisoryCatalog

MAX_CATALOG_BYTES = 16 * 1024 * 1024


def canonical_bytes(value, *, limit=MAX_CATALOG_BYTES):
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    if len(data) > limit:
        raise ValueError("Software assessment data exceeds its size limit")
    return data


def catalog_digest(payload):
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def validated_catalog(payload):
    from app.services.software_catalog import validate_catalog

    canonical_bytes(payload)
    return validate_catalog(payload)


def store_catalog(db: Session, payload):
    payload = validated_catalog(payload)
    digest = catalog_digest(payload)
    existing = db.query(SoftwareAdvisoryCatalog).filter_by(sha256=digest).first()
    if existing:
        return existing
    retrieved = datetime.fromisoformat(payload["retrieved_at"].replace("Z", "+00:00"))
    row = SoftwareAdvisoryCatalog(
        sha256=digest,
        source=payload["source"],
        payload=payload,
        retrieved_at=retrieved.astimezone(UTC),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def synchronize_catalog(db: Session, *, months=3, now=None, progress=None):
    from app.services.software_catalog import build_catalog

    # Complete network and validation work before making any database change.
    return store_catalog(db, build_catalog(months=months, now=now, progress=progress))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--months", type=int, default=3, choices=range(1, 13))
    args = parser.parse_args(argv)
    from app.database.session import SessionLocal

    try:
        with SessionLocal() as db:
            row = synchronize_catalog(
                db, months=args.months, progress=lambda message: print(message, flush=True)
            )
            print(
                f"VERIFIED: Software catalog {row.id}; "
                f"documents={len(row.payload['documents'])}; "
                f"entries={len(row.payload['entries'])}; sha256={row.sha256}"
            )
        return 0
    except Exception:
        print(
            "STOPPED: Software catalog synchronization failed; previous snapshots retained.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
