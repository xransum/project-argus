#!/usr/bin/env bash
# scripts/start.sh — Build assets then start the server in production mode

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Building assets..."
bash "$ROOT/scripts/build.sh"

echo "==> Starting server..."
cd "$ROOT"
uv run uvicorn project_argus.main:app \
    --host 0.0.0.0 \
    --port 8000
