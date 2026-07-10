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
REPOSITORY_ROOT="$(cd "$ROOT/../.." && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-secret-file-tests.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT
MODULE_CACHE="$BUILD_DIR/ModuleCache"
mkdir -p "$MODULE_CACHE"

CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" xcrun swiftc \
  -module-cache-path "$MODULE_CACHE" \
  "$ROOT/DefenseClawMac/DataLayer/CommandRegistry.swift" \
  "$ROOT/DefenseClawMac/DataLayer/ConfigStore.swift" \
  "$ROOT/Tests/SecretAndFileSafetyTests.swift" \
  -o "$BUILD_DIR/SecretAndFileSafetyTests"

"$BUILD_DIR/SecretAndFileSafetyTests"

if grep -F -- '<ENV_NAME> --value <secret>' \
    "$ROOT/DefenseClawMac/DataLayer/CommandRegistry.swift" \
    "$REPOSITORY_ROOT/cli/defenseclaw/tui/registry_data.py"; then
  echo "keys set still advertises a secret-bearing argv flag" >&2
  exit 1
fi
