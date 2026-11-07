"""Import one complete official catalog snapshot; never use target credentials."""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.host_assessment import WindowsPatchCatalog

MAX_CATALOG_BYTES = 16 * 1024 * 1024


def canonical_bytes(value, *, limit=MAX_CATALOG_BYTES):
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    if len(data) > limit:
        raise ValueError("Patch assessment data exceeds its size limit")
    return data


def catalog_digest(payload):
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def validated_catalog(payload):
    from app.services.windows_patch_catalog import validate_catalog

    canonical_bytes(payload)
    return validate_catalog(payload)


def store_catalog(db: Session, payload):
    """Validate the entire snapshot before its first database write."""
    payload = validated_catalog(payload)
    digest = catalog_digest(payload)
    existing = db.query(WindowsPatchCatalog).filter_by(sha256=digest).first()
    if existing:
        return existing
    retrieved = datetime.fromisoformat(payload["retrieved_at"].replace("Z", "+00:00"))
    if retrieved.tzinfo is None:
        raise ValueError("Catalog retrieval time must include its timezone")
    row = WindowsPatchCatalog(
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
    from app.services.windows_patch_catalog import fetch_catalog

    # All network/parse work precedes persistence. A failed or incomplete fetch
    # retains the last validated snapshot and does not create a partial record.
    snapshot = fetch_catalog(months=months, now=now, progress=progress)
    return store_catalog(db, snapshot)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--months", type=int, default=3, choices=range(1, 13))
    args = parser.parse_args(argv)
    from app.database.session import SessionLocal

    try:
        with SessionLocal() as db:
            catalog = synchronize_catalog(
                db, months=args.months, progress=lambda message: print(message, flush=True)
            )
            print(
                f"VERIFIED: MSRC catalog {catalog.id}; "
                f"documents={len(catalog.payload['documents'])}; "
                f"entries={len(catalog.payload['entries'])}; sha256={catalog.sha256}"
            )
        return 0
    except Exception:
        # Source payloads, database URLs and upstream errors are not CLI output.
        print(
            "STOPPED: Catalog synchronization failed; previous snapshots retained.", file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
