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
# Live driver for Google Antigravity CLI (`agy`). The official versioned
# artifact is downloaded into a run-owned directory and verified against the
# official manifest SHA-512; it never replaces the logged-in user's
# ~/.local/bin/agy. Agent execution keeps the real HOME so macOS Keychain/login
# state is reused.

set -euo pipefail
DRIVER_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${DRIVER_HERE}/../lib/common.sh"
. "${DRIVER_HERE}/../lib/assert.sh"
. "${DRIVER_HERE}/../lib/setup.sh"
. "${DRIVER_HERE}/_driver_common.sh"

DC_DRIVER_MODE="${DC_DRIVER_MODE:-action}"
# As of agy 1.1.x, PreToolUse is the empirically proven headless event. Keep
# lifecycle explicitly skipped instead of claiming coverage from old JSONL.
DC_DRIVER_SUPPORTS_LIFECYCLE=0
DC_DRIVER_SUPPORTS_BLOCK=1
DC_DRIVER_SUPPORTS_OTLP=0

AGY_BIN=""

_agy_version_number() {
  local raw="$1"
  if [[ "${raw}" =~ ([0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

agent_install() {
  local root raw record resolved requested
  root="${DC_E2E_AGENT_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/dc-antigravity-live-$$}"
  requested="${ANTIGRAVITY_VERSION:-latest}"
  record="$(dc_install_antigravity_release "${root}" "${requested}")" || return 1
  IFS=$'\t' read -r AGY_BIN resolved <<< "${record}"
  [ -x "${AGY_BIN}" ] || return 1
  raw="$(dc_capture_version antigravity "${AGY_BIN}" --version)"
  if [ "$(_agy_version_number "${raw}")" != "${resolved}" ]; then
    dc_err "agy binary version does not match its verified release manifest"
    return 1
  fi
  DC_E2E_AGENT_VERSION="${resolved}"
  export DC_E2E_AGENT_VERSION AGY_BIN
}

agent_run() {
  local prompt="$1"
  # DefenseClaw's PreToolUse deny still overrides this auto-approval flag.
  dc_timeout 180 "${AGY_BIN}" --print --dangerously-skip-permissions "${prompt}"
}

dc_driver_main antigravity
