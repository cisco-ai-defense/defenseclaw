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

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
# The helper accepts only canonical paths inside the invoking account's home,
# so the fixtures live under the (git-ignored) app build directory rather than
# the system temporary directory.
mkdir -p "$ROOT/build"
TEST_DIRECTORY="$(mktemp -d "$ROOT/build/gateway-admin-helper-test.XXXXXX")"
trap 'rm -rf "$TEST_DIRECTORY"' EXIT
MODULE_CACHE="$TEST_DIRECTORY/ModuleCache"
mkdir -p "$MODULE_CACHE"

CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" xcrun swiftc -parse-as-library -swift-version 5 \
  -D GATEWAY_ADMIN_HELPER_TESTING \
  -module-cache-path "$MODULE_CACHE" \
  "$ROOT/DefenseClawMac/DataLayer/GatewayAdminProtocol.swift" \
  "$ROOT/GatewayAdminHelper/main.swift" \
  "$ROOT/Tests/GatewayAdminHelperTests.swift" \
  -framework Foundation -framework Security \
  -o "$TEST_DIRECTORY/gateway-admin-helper-tests"

"$TEST_DIRECTORY/gateway-admin-helper-tests" "$TEST_DIRECTORY"
