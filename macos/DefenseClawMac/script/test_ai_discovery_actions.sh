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
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-ai-discovery-action-tests.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT
MODULE_CACHE="$BUILD_DIR/ModuleCache"
mkdir -p "$MODULE_CACHE"

CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" xcrun swiftc \
  -module-cache-path "$MODULE_CACHE" \
  "$ROOT/DefenseClawMac/DataLayer/AIDiscoveryActionPolicy.swift" \
  "$ROOT/DefenseClawMac/DataLayer/Models.swift" \
  "$ROOT/Tests/AIDiscoveryActionPolicyTests.swift" \
  -o "$BUILD_DIR/AIDiscoveryActionPolicyTests"

"$BUILD_DIR/AIDiscoveryActionPolicyTests"

if grep -Fq 'try await appState.gateway.aiScan()' \
  "$ROOT/DefenseClawMac/Features/DiscoverViews.swift"; then
  echo "AI Discovery still bypasses the canonical CLI action workflow" >&2
  exit 1
fi

SCAN_NOTIFICATION="$(
  sed -n \
    '/publisher(for: \.dcScanAIDiscovery)/,/^        }/p' \
    "$ROOT/DefenseClawMac/Features/DiscoverViews.swift"
)"
if ! grep -Fq 'requestScan()' <<<"$SCAN_NOTIFICATION" ||
   grep -Fq 'guard' <<<"$SCAN_NOTIFICATION"; then
  echo "The Scan AI Components command must queue until initial status loading completes" >&2
  exit 1
fi

AI_DISCOVERY_LOAD="$(
  sed -n \
    '/private func load() async/,/private func run(/p' \
    "$ROOT/DefenseClawMac/Features/DiscoverViews.swift"
)"
if grep -Fq 'guard appState.gatewayReachable else' <<<"$AI_DISCOVERY_LOAD"; then
  echo "AI Discovery status load must not depend on stale startup reachability" >&2
  exit 1
fi

AI_DISCOVERY_SETUP="$(
  sed -n \
    '/private static let aiDiscovery =/,/private static let splunkDashboards =/p;
     /private static func aiDiscoveryCommands/,/private static func splunkDashboardCommands/p' \
    "$ROOT/DefenseClawMac/Features/SetupDefinitions.swift"
)"
if grep -Fq 'emit-otel' <<<"$AI_DISCOVERY_SETUP"; then
  echo "AI Discovery setup still emits the removed --emit-otel runtime option" >&2
  exit 1
fi

echo "AI Discovery source contract tests passed"
