#!/usr/bin/env bash
# scripts/test.sh — Run the Python test suite via pytest inside the venv

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Running tests..."
.venv/bin/pytest tests/ "$@"
