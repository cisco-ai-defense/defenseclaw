#!/bin/bash
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
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-setup-parity-tests.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT
MODULE_CACHE="$BUILD_DIR/ModuleCache"
mkdir -p "$MODULE_CACHE"

CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" xcrun swiftc \
  -module-cache-path "$MODULE_CACHE" \
  "$ROOT/DefenseClawMac/DataLayer/ConnectorOnboarding.swift" \
  "$ROOT/DefenseClawMac/Features/SetupDefinitions.swift" \
  "$ROOT/Tests/SetupDefinitionsParityTests.swift" \
  -o "$BUILD_DIR/SetupDefinitionsParityTests"

"$BUILD_DIR/SetupDefinitionsParityTests"

# Setup secrets travel in the child environment the runtime defines, never on argv.
for required in DEFENSECLAW_SETUP_SPLUNK_ACCESS_TOKEN DEFENSECLAW_SETUP_SPLUNK_HEC_TOKEN \
  SPLUNK_ACCESS_TOKEN DEFENSECLAW_SPLUNK_HEC_TOKEN \
  DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN SFX_AUTH_TOKEN; do
  if ! grep -Fq "$required" "$ROOT/DefenseClawMac/Features/SetupDefinitions.swift"; then
    echo "setup secret is missing its runtime-defined child environment: $required" >&2
    exit 1
  fi
done

