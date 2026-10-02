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

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-gateway-admin-tests.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT
MODULE_CACHE="$BUILD_DIR/ModuleCache"
mkdir -p "$MODULE_CACHE"

CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" xcrun swiftc \
  -module-cache-path "$MODULE_CACHE" \
  "$ROOT/DefenseClawMac/DataLayer/InstallationContext.swift" \
  "$ROOT/DefenseClawMac/DataLayer/ConfigStore.swift" \
  "$ROOT/DefenseClawMac/DataLayer/CLIRunner.swift" \
  "$ROOT/DefenseClawMac/DataLayer/GatewayAdminProtocol.swift" \
  "$ROOT/DefenseClawMac/DataLayer/GatewayAdministratorClient.swift" \
  "$ROOT/Tests/GatewayAdministratorTests.swift" \
  -o "$BUILD_DIR/GatewayAdministratorTests"
"$BUILD_DIR/GatewayAdministratorTests"

# Compile the real helper and verify that direct unprivileged execution refuses
# before opening a listener or mutating any state.
CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" xcrun swiftc -parse-as-library \
  -module-cache-path "$MODULE_CACHE" \
  "$ROOT/DefenseClawMac/DataLayer/GatewayAdminProtocol.swift" \
  "$ROOT/GatewayAdminHelper/main.swift" \
  -o "$BUILD_DIR/DefenseClawGatewayHelper"
set +e
"$BUILD_DIR/DefenseClawGatewayHelper" > "$BUILD_DIR/helper-output" 2>&1
status=$?
set -e
if [[ "$status" != 77 ]]; then
  cat "$BUILD_DIR/helper-output"
  echo "Expected direct helper execution to refuse with status 77" >&2
  exit 1
fi
