"""Check public software source contracts without a DB or customer evidence."""

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.software_catalog import (  # noqa: E402
    CatalogError,
    build_catalog,
    validate_catalog,
)


def main():
    if (
        sys.argv[1:]
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or not re.fullmatch(r"[1-9][0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
    ):
        raise RuntimeError("The live software source check requires isolated CI")
    snapshot = build_catalog(months=3, progress=lambda value: print(value, flush=True))
    assert validate_catalog(json.loads(json.dumps(snapshot))) == snapshot
    coverage = {row["product_key"]: row for row in snapshot["coverage"]}
    if not coverage["edge-windows"]["parsed"] or coverage["7zip-windows"]["parsed"] != 1:
        raise CatalogError("Current public sources have no usable supported ranges")
    print(
        json.dumps(
            {
                "source": snapshot["source"],
                "retrieved_at": snapshot["retrieved_at"],
                "coverage_start": snapshot["coverage_start"],
                "coverage_end": snapshot["coverage_end"],
                "documents": len(snapshot["documents"]),
                "entries": len(snapshot["entries"]),
                "coverage": snapshot["coverage"],
            },
            indent=2,
        ),
        flush=True,
    )
    print("VERIFIED: live monthly Edge discovery, explicit CNA ranges and curated 7-Zip source")


if __name__ == "__main__":
    try:
        main()
    except CatalogError as error:
        raise SystemExit(f"Software source contract failed: {error}") from None
