#!/usr/bin/env bash
# scripts/build.sh — Install npm deps and copy vendor files to static/vendor

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATIC="$ROOT/src/project_argus/static"
VENDOR="$STATIC/vendor"

echo "==> Installing Python dependencies..."
cd "$ROOT"
uv sync

echo "==> Installing npm dependencies..."
cd "$ROOT"
npm install

echo "==> Copying vendor files to $VENDOR..."
mkdir -p "$VENDOR/js"
mkdir -p "$VENDOR/css/images"

# jQuery
cp "$ROOT/node_modules/jquery/dist/jquery.min.js"  "$VENDOR/js/jquery.min.js"
cp "$ROOT/node_modules/jquery/dist/jquery.min.map" "$VENDOR/js/jquery.min.map" 2>/dev/null || true

# jQuery UI — JS
cp "$ROOT/node_modules/jquery-ui/dist/jquery-ui.min.js" "$VENDOR/js/jquery-ui.min.js"

# jQuery UI — dark-hive theme CSS + images
cp "$ROOT/node_modules/jquery-ui/dist/themes/dark-hive/jquery-ui.min.css" "$VENDOR/css/jquery-ui.min.css"
cp "$ROOT/node_modules/jquery-ui/dist/themes/dark-hive/images/"*           "$VENDOR/css/images/" 2>/dev/null || true

echo "==> Build complete."
