#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
APP_NAME="defenseclaw_local_mode"
APP_SOURCE_DIR="${SCRIPT_DIR}/apps/${APP_NAME}"
BUILD_DIR="${SCRIPT_DIR}/build"
PACKAGE_PATH="${BUILD_DIR}/${APP_NAME}.tgz"

if [[ ! -d "${APP_SOURCE_DIR}" ]]; then
  echo "App source directory not found: ${APP_SOURCE_DIR}" >&2
  exit 1
fi

mkdir -p "${BUILD_DIR}"
rm -f "${PACKAGE_PATH}"

tar \
  --exclude='*/__pycache__' \
  --exclude='*/__pycache__/*' \
  --exclude='*.pyc' \
  --sort=name \
  --mtime='UTC 2026-01-01' \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -czf "${PACKAGE_PATH}" \
  -C "${SCRIPT_DIR}/apps" \
  "${APP_NAME}"

echo "${PACKAGE_PATH}"
