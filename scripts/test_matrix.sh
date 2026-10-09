#!/usr/bin/env bash
# Run the test suite on every supported Python version (requires uv).
# Usage: scripts/test_matrix.sh [3.9 3.12 ...]
set -euo pipefail
cd "$(dirname "$0")/.."

versions=("$@")
[ ${#versions[@]} -eq 0 ] && versions=(3.9 3.10 3.11 3.12 3.13 3.14)

failed=()
for v in "${versions[@]}"; do
  printf '%-6s ' "$v"
  if out=$(uv run --quiet --isolated --no-project --python "$v" \
        --with 'reportlab>=4.0' --with 'pytest>=7.0' \
        python -m pytest -q -p no:cacheprovider 2>&1); then
    echo "$out" | tail -1
  else
    echo "FAILED"; echo "$out" | tail -20; failed+=("$v")
  fi
done

if [ ${#failed[@]} -gt 0 ]; then
  echo "Failed on: ${failed[*]}"; exit 1
fi
