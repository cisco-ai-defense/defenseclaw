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
# Live driver for Google Gemini CLI.
#   - install:  npm i -g @google/gemini-cli@${GEMINI_VERSION:-latest}
#   - headless: gemini -p "<prompt>" -o json --approval-mode yolo
#   - auth:     GEMINI_API_KEY (or GOOGLE_API_KEY)
#   - hooks:    Gemini's hook events are advisory (SessionStart / PreCompress /
#               Notification / BeforeTool) — the harness records them but does
#               not honor a deny verdict, so we assert fires + observe + OTLP
#               only and skip the block assertion (DC_DRIVER_SUPPORTS_BLOCK=0).
#   - OTLP:     native exporter wired by `defenseclaw setup geminicli`.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
. "${HERE}/../lib/assert.sh"
. "${HERE}/../lib/setup.sh"
. "${HERE}/_driver_common.sh"

DC_DRIVER_MODE=action
DC_DRIVER_SUPPORTS_BLOCK=0   # advisory events cannot block
DC_DRIVER_SUPPORTS_OTLP=1

GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.5-flash}"

agent_install() {
  npm install -g "@google/gemini-cli@${GEMINI_VERSION:-latest}" || return 1
  DC_E2E_AGENT_VERSION="$(dc_capture_version geminicli gemini --version)"
  export DC_E2E_AGENT_VERSION
  dc_write_env_key GEMINI_API_KEY "${GEMINI_API_KEY:-${GOOGLE_API_KEY:-}}"
}

agent_run() {
  local prompt="$1"
  dc_timeout 180 gemini -p "${prompt}" -o json \
    --model "${GEMINI_MODEL}" \
    --approval-mode yolo
}

dc_driver_main geminicli
