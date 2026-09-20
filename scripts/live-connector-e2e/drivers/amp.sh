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
# Live driver for Amp.
#   - install:  npm i -g @ampcode/cli@${AMP_VERSION:-latest}
#   - headless: amp -x "<prompt>" --plugin-ready-timeout 30
#   - auth:     AMP_API_KEY
#   - hooks:    session.start / agent.start / tool.call / tool.result /
#               agent.end. tool.call can reject before execution, so block
#               enforcement is testable in headless mode.
#   - OTLP:     Amp has no documented native customer OTLP exporter surface;
#               DefenseClaw's canonical hook observability is still asserted.
#
# `--plugin-ready-timeout 30` is required in execute mode so Amp waits for the
# DefenseClaw plugin lifecycle before it starts the headless turn.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
. "${HERE}/../lib/assert.sh"
. "${HERE}/../lib/setup.sh"
. "${HERE}/_driver_common.sh"

DC_DRIVER_MODE="${DC_DRIVER_MODE:-action}"
DC_DRIVER_SUPPORTS_BLOCK=1
DC_DRIVER_SUPPORTS_OTLP=0

agent_install() {
  if [ -z "${AMP_API_KEY:-}" ]; then
    dc_err "AMP_API_KEY is required for the Amp live driver"
    return 1
  fi
  npm install -g "@ampcode/cli@${AMP_VERSION:-latest}" || return 1
  DC_E2E_AGENT_VERSION="$(dc_capture_version amp amp --version)"
  export DC_E2E_AGENT_VERSION
  dc_write_env_key AMP_API_KEY "${AMP_API_KEY}"
}

agent_run() {
  local prompt="$1"
  dc_timeout 180 amp -x "${prompt}" --plugin-ready-timeout 30
}

dc_driver_main amp
