#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#
# Live driver for Cursor Agent (cursor-agent CLI).
#   - install:  curl https://cursor.com/install -fsS | bash
#   - headless: cursor-agent -p "<prompt>" --output-format json --force
#   - auth:     CURSOR_API_KEY
#   - hooks:    beforeShellExecution can deny (can_ask_native), so block is
#               testable headless.
#
# GATING: live Cursor coverage is only meaningful if headless `cursor-agent -p`
# actually fires ~/.cursor/hooks.json. Run cursor-validation.sh first; the
# workflow gates this driver on its result.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
. "${HERE}/../lib/assert.sh"
. "${HERE}/../lib/setup.sh"
. "${HERE}/_driver_common.sh"

DC_DRIVER_MODE=action
DC_DRIVER_SUPPORTS_BLOCK=1
DC_DRIVER_SUPPORTS_OTLP=0

agent_install() {
  if ! command -v cursor-agent >/dev/null 2>&1; then
    curl https://cursor.com/install -fsS | bash || return 1
    export PATH="${HOME}/.local/bin:${PATH}"
  fi
  DC_E2E_AGENT_VERSION="$(dc_capture_version cursor cursor-agent --version)"
  export DC_E2E_AGENT_VERSION
  dc_write_env_key CURSOR_API_KEY "${CURSOR_API_KEY:-}"
}

agent_run() {
  local prompt="$1"
  dc_timeout 180 cursor-agent -p "${prompt}" --output-format json --force
}

dc_driver_main cursor
