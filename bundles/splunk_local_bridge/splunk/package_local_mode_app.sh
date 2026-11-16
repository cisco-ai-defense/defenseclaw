#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0


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

if [[ -L "${BUILD_DIR}" || -L "${PACKAGE_PATH}" ]]; then
  echo "Refusing a linked Splunk app output; remove the link and run defenseclaw setup splunk --logs again" >&2
  exit 1
fi
mkdir -p "${BUILD_DIR}"
# Only this public app directory and archive are mounted into Splunk. Keep
# credentials private while making these assets readable under umask 077.
chmod 755 "${BUILD_DIR}"
rm -f "${PACKAGE_PATH}"

if tar --version 2>/dev/null | grep -q 'GNU tar'; then
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
else
  COPYFILE_DISABLE=1 tar \
    --exclude='*/__pycache__' \
    --exclude='*.pyc' \
    --exclude='._*' \
    -czf "${PACKAGE_PATH}" \
    -C "${SCRIPT_DIR}/apps" \
    "${APP_NAME}"
fi

chmod 644 "${PACKAGE_PATH}"
echo "${PACKAGE_PATH}"
