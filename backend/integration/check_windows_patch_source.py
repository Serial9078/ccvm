"""Read the real public Microsoft source in an isolated CI source-contract check.

No database, stored credential, customer identity or target host is accepted.
The downloaded vendor documents are not retained as repository artifacts.
"""

import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.services.windows_patch_catalog import (  # noqa: E402
    CatalogError,
    fetch_catalog,
    validate_catalog,
)


def main():
    if (
        sys.argv[1:]
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or not re.fullmatch(r"[1-9][0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
    ):
        raise RuntimeError("The live Microsoft source contract requires an isolated CI run")
    result = fetch_catalog(months=3, progress=lambda message: print(message, flush=True))
    assert validate_catalog(json.loads(json.dumps(result))) == result
    if not result["entries"]:
        raise CatalogError("The published window contained no supported Server OS build references")
    print(
        json.dumps(
            {
                "source": result["source"],
                "retrieved_at": result["retrieved_at"],
                "coverage_start": result["coverage_start"],
                "coverage_end": result["coverage_end"],
                "documents": result["documents"],
                "entries": len(result["entries"]),
                "product_entries": dict(
                    sorted(Counter(entry["product_name"] for entry in result["entries"]).items())
                ),
                "statistics": result.get("statistics", {}),
            },
            indent=2,
        ),
        flush=True,
    )
    print(
        "VERIFIED: live Microsoft CVRF JSON, complete published window "
        "and bounded Server OS references"
    )


if __name__ == "__main__":
    try:
        main()
    except CatalogError as error:
        raise SystemExit(f"Microsoft source contract failed: {error}") from None
