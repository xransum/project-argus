#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT/.build/lambdas"
PYTHONPATH_SRC="$ROOT/src"
PACKAGE_DIR="$BUILD_DIR/package"
ZIP_PATH="$BUILD_DIR/project-argus-lambda.zip"
PIP_TARGET_DIR="$BUILD_DIR/python"
LAMBDA_BUILD_IMAGE="${LAMBDA_BUILD_IMAGE:-public.ecr.aws/lambda/python:3.11}"
VOLUME_NAME="project_argus_lambda_build"
CONTAINER_PIP_TARGET_DIR="/opt/python"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

mkdir -p "$PACKAGE_DIR"
cp -R "$PYTHONPATH_SRC/project_argus" "$PACKAGE_DIR/"
rm -rf \
  "$PACKAGE_DIR/project_argus/api" \
  "$PACKAGE_DIR/project_argus/web" \
  "$PACKAGE_DIR/project_argus/templates" \
  "$PACKAGE_DIR/project_argus/static" \
  "$PACKAGE_DIR/project_argus/db.py" \
  "$PACKAGE_DIR/project_argus/main.py" \
  "$PACKAGE_DIR/project_argus/services/job_service.py"

mkdir -p "$PIP_TARGET_DIR"
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to build Lambda-compatible packages" >&2
  exit 1
fi

docker volume rm -f "$VOLUME_NAME" >/dev/null 2>&1 || true
docker run --rm \
  --platform linux/amd64 \
  --entrypoint /bin/sh \
  -v "$VOLUME_NAME":"$CONTAINER_PIP_TARGET_DIR" \
  "$LAMBDA_BUILD_IMAGE" \
  -lc "python -m pip install --upgrade pip >/dev/null && python -m pip install --target '$CONTAINER_PIP_TARGET_DIR' --upgrade boto3 'httpx[socks]' python-whois dnspython cryptography pydantic idna beautifulsoup4 lxml >/dev/null"

docker run --rm \
  --user "$HOST_UID:$HOST_GID" \
  -v "$VOLUME_NAME":"$CONTAINER_PIP_TARGET_DIR":ro \
  -v "$ROOT:/workspace:Z" \
  --entrypoint /bin/sh \
  "$LAMBDA_BUILD_IMAGE" \
  -lc "cp -R '$CONTAINER_PIP_TARGET_DIR'/. /workspace/.build/lambdas/python/"

cp -R "$PIP_TARGET_DIR"/. "$PACKAGE_DIR/"
docker volume rm -f "$VOLUME_NAME" >/dev/null 2>&1 || true

PACKAGE_DIR="$PACKAGE_DIR" ZIP_PATH="$ZIP_PATH" python3 - <<'PY'
from pathlib import Path
import zipfile
import os

package_dir = Path(os.environ["PACKAGE_DIR"])
zip_path = Path(os.environ["ZIP_PATH"])
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
    for path in package_dir.rglob("*"):
        if path.is_file():
            archive.write(path, path.relative_to(package_dir))
PY

du -sh "$ZIP_PATH"
