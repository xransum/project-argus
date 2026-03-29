#!/usr/bin/env bash
# scripts/start.sh — Build assets then start the server in production mode

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Building assets..."
bash "$ROOT/scripts/build.sh"

echo "==> Starting server..."
cd "$ROOT"
uv run gunicorn project_argus.main:app \
    -k uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --workers 2 \
    --timeout 120
