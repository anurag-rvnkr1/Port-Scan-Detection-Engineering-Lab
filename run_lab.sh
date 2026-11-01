#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$PROJECT_ROOT/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
    printf 'Project environment is missing. Run %s/install.sh first.\n' "$PROJECT_ROOT" >&2
    exit 1
fi

export LAB_HOST="${LAB_HOST:-127.0.0.1}"
export LAB_PORT="${LAB_PORT:-8000}"
export LAB_DATABASE_URL="${LAB_DATABASE_URL:-sqlite:///$PROJECT_ROOT/data/soc_lab.db}"

printf 'Starting local SOC API at http://%s:%s\n' "$LAB_HOST" "$LAB_PORT"
printf 'API documentation: http://%s:%s/docs\n' "$LAB_HOST" "$LAB_PORT"
cd "$PROJECT_ROOT"
exec "$PROJECT_ROOT/.venv/bin/uvicorn" backend.app.main:app --host "$LAB_HOST" --port "$LAB_PORT"
