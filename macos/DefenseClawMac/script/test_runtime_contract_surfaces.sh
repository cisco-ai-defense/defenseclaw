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
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-runtime-contract-tests.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT
MODULE_CACHE="$BUILD_DIR/ModuleCache"
mkdir -p "$MODULE_CACHE"

CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" xcrun swiftc \
  -module-cache-path "$MODULE_CACHE" \
  "$ROOT/DefenseClawMac/DataLayer/AlertDispositionCommand.swift" \
  "$ROOT/DefenseClawMac/DataLayer/CommandRegistry.swift" \
  "$ROOT/Tests/RuntimeContractSurfaceTests.swift" \
  -o "$BUILD_DIR/RuntimeContractSurfaceTests"

"$BUILD_DIR/RuntimeContractSurfaceTests"

if grep -Fq 'key: "otel.' "$ROOT/DefenseClawMac/Features/ConfigEditorDefinitions.swift"; then
  echo "Legacy config-v7 otel.* editor fields remain" >&2
  exit 1
fi

if grep -Fq 'migrate-splunk' "$ROOT/DefenseClawMac/DataLayer/CommandRegistry.swift"; then
  echo "Retired migrate-splunk command remains" >&2
  exit 1
fi

if grep -Fq 'Search 226 commands' "$ROOT/DefenseClawMac/Features/CommandPaletteView.swift"; then
  echo "Command palette still contains a stale hard-coded count" >&2
  exit 1
fi

if ! grep -Fq 'DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN' "$ROOT/DefenseClawMac/Features/SetupDefinitions.swift"; then
  echo "Observability token is not using the runtime 0.8.9 secret environment contract" >&2
  exit 1
fi

if ! sed -n '/case \.secure:/,/default:/p' "$ROOT/DefenseClawMac/Features/SetupDefinitions.swift" \
    | grep -Fq 'continue'; then
  echo "Generic setup fields no longer fail closed for secure values" >&2
  exit 1
fi

if ! grep -Fq 'commandEnvironment.keys.sorted().map' "$ROOT/DefenseClawMac/Features/SetupView.swift"; then
  echo "Setup review no longer displays masked child-environment keys" >&2
  exit 1
fi

for secret_key in SPLUNK_ACCESS_TOKEN DEFENSECLAW_SPLUNK_HEC_TOKEN SFX_AUTH_TOKEN; do
  if ! grep -Fq "$secret_key" "$ROOT/DefenseClawMac/Features/SetupDefinitions.swift"; then
    echo "Setup secret is missing its child-environment transport: $secret_key" >&2
    exit 1
  fi
done

if sed -n '/func observabilityCommands/,/func observabilityValidation/p' \
    "$ROOT/DefenseClawMac/Features/SetupDefinitions.swift" | grep -Fq -- '--connector'; then
  echo "Observability command still emits the removed runtime --connector option" >&2
  exit 1
fi
