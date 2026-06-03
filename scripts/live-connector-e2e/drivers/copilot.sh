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
# Live driver for GitHub Copilot CLI.
#   - install:  npm i -g @github/copilot@${COPILOT_VERSION:-latest}
#   - headless: copilot -p "<prompt>" --allow-all-tools
#   - auth:     an ENTITLED GitHub token (Copilot subscription). Provide it via
#               the COPILOT_CLI_TOKEN secret; we export it as GH_COPILOT_TOKEN
#               and GITHUB_TOKEN so the CLI picks it up.
#   - hooks:    USER-LEVEL ONLY. Repo-level .github/hooks/*.json do NOT load in
#               `-p` mode (upstream bug github/copilot-cli#3345), so
#               `defenseclaw setup copilot` must write ~/.copilot/hooks/*.json.
#               We force user scope by NOT passing --workspace.
#   - status:   continue-on-error in the workflow until proven stable.

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
  npm install -g "@github/copilot@${COPILOT_VERSION:-latest}" || return 1
  DC_E2E_AGENT_VERSION="$(dc_capture_version copilot copilot --version)"
  export DC_E2E_AGENT_VERSION
  # Copilot CLI reads an entitled token from the environment.
  export GH_COPILOT_TOKEN="${COPILOT_CLI_TOKEN:-${GH_COPILOT_TOKEN:-}}"
  export GITHUB_TOKEN="${COPILOT_CLI_TOKEN:-${GITHUB_TOKEN:-}}"
}

agent_run() {
  local prompt="$1"
  dc_timeout 180 copilot -p "${prompt}" --allow-all-tools
}

dc_driver_main copilot
