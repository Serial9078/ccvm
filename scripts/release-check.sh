#!/usr/bin/env bash
set -euo pipefail

echo "CCVM release check"
echo "- backend files: $(find backend/app -type f | wc -l)"
echo "- frontend files: $(find frontend/src -type f | wc -l)"
echo "- docs files: $(find docs -type f | wc -l)"
