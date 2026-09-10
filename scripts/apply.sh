#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for file in sql/*.sql; do
  echo ">> $file"
  psql -v ON_ERROR_STOP=1 -q -f "$file"
done

if [[ "${1:-}" == "--test" ]]; then
  echo ">> tests/90_assertions.sql"
  psql -v ON_ERROR_STOP=1 -f tests/90_assertions.sql
fi
