#!/usr/bin/env bash
# scripts/dev.sh — Build assets then start the server in reload mode

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Building assets..."
bash "$ROOT/scripts/build.sh"

echo "==> Starting dev server (hot-reload)..."
cd "$ROOT"
.venv/bin/uvicorn project_argus.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload \
    --reload-dir src/project_argus
