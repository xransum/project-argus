#!/usr/bin/env bash
# scripts/clean.sh - Stop and remove project-argus Docker resources and build artifacts

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/infra/local/docker-compose.yml"

echo "==> Stopping and removing project-argus containers..."
docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true

echo "==> Removing project-argus Docker images..."
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' \
  | grep '^project-argus' \
  | awk '{print $2}' \
  | xargs -r docker rmi -f

echo "==> Removing build artifacts..."
for target in \
  "$ROOT/.build" \
  "$ROOT/.localstack" \
  "$ROOT/src/project_argus/static/vendor" \
  "$ROOT/node_modules"
do
  if [ -e "$target" ]; then
    echo "    removing $target"
    rm -rf "$target"
  else
    echo "    skipping $target (not found)"
  fi
done

echo "==> Done. To rebuild from scratch, run: ./scripts/build.sh"
