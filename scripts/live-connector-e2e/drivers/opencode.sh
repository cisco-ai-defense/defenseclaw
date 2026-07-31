#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Live driver for the official OpenCode npm distribution. This cell is manual
# until OPENAI_API_KEY is provisioned; a green hosted artifact is required
# before maintainers populate last_validated_version.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
. "${HERE}/../lib/assert.sh"
. "${HERE}/../lib/setup.sh"
. "${HERE}/_driver_common.sh"

DC_DRIVER_MODE=action
DC_DRIVER_SUPPORTS_BLOCK=1
DC_DRIVER_SUPPORTS_OTLP=0
OPENCODE_MODEL="${OPENCODE_MODEL:-openai/gpt-5-mini}"

agent_install() {
  local requested="${DC_E2E_AGENT_VERSION_REQUEST:-latest}"
  requested="${requested#v}"
  npm install -g "opencode-ai@${requested}" || return 1
  DC_E2E_AGENT_VERSION="$(dc_capture_version opencode opencode --version)"
  export DC_E2E_AGENT_VERSION
  dc_write_env_key OPENAI_API_KEY "${OPENAI_API_KEY:-}"
}

agent_run() {
  local prompt="$1"
  dc_timeout 180 opencode run --format json --model "${OPENCODE_MODEL}" "${prompt}"
}

dc_driver_main opencode
