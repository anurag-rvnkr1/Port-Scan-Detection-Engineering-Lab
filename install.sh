#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
    printf 'Python 3.10 or newer is required.\n' >&2
    exit 1
fi
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    printf 'Node.js and npm are required for the frontend. Install Node.js 20 or newer, then rerun this script.\n' >&2
    exit 1
fi
if ! node -e 'const major = Number(process.versions.node.split(".")[0]); process.exit(major < 20 ? 1 : 0)'; then
    printf 'Node.js 20 or newer is required. Found %s.\n' "$(node --version)" >&2
    exit 1
fi

python3 -m venv "$PROJECT_ROOT/.venv"
"$PROJECT_ROOT/.venv/bin/python" -m pip install --upgrade pip
"$PROJECT_ROOT/.venv/bin/pip" install -r "$PROJECT_ROOT/requirements.lock"
npm --prefix "$PROJECT_ROOT" ci
mkdir -p "$PROJECT_ROOT/data"

printf '\nInstallation complete. No system packages or root privileges were required.\n'
printf 'Start the API with: %s/run_lab.sh\n' "$PROJECT_ROOT"
printf 'Start the dashboard in another terminal with: cd %q && npm run dev\n' "$PROJECT_ROOT"
