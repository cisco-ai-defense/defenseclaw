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
# One-time gate: does headless `cursor-agent -p` actually fire
# ~/.cursor/hooks.json? Cursor exposes both a project cli-config.json and a
# user hooks.json; it is not guaranteed the agentic-print mode honors the hook
# bus. This script installs cursor-agent, wires DefenseClaw, drives a trivial
# prompt, and checks whether any cursor-tagged event reached the gateway.
#
# Exit 0 + "CURSOR_HOOKS_FIRE=1" on $GITHUB_OUTPUT  -> live Cursor coverage is
# valid; the workflow then runs drivers/cursor.sh.
# Exit non-zero                                     -> Cursor stays Layer-A only.

set -euo pipefail
export DC_E2E_CONNECTOR=cursor

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/lib/common.sh"
. "${HERE}/lib/assert.sh"
. "${HERE}/lib/setup.sh"

dc_section "cursor headless hook validation"

if ! command -v cursor-agent >/dev/null 2>&1; then
  curl https://cursor.com/install -fsS | bash || dc_die "cursor-agent install failed"
  export PATH="${HOME}/.local/bin:${PATH}"
fi
DC_E2E_AGENT_VERSION="$(dc_capture_version cursor cursor-agent --version)"
export DC_E2E_AGENT_VERSION
dc_write_env_key CURSOR_API_KEY "${CURSOR_API_KEY:-}"

dc_init_defenseclaw
dc_setup_connector cursor action

before="$(dc_gateway_jsonl_count)"
dc_log "driving trivial headless prompt through cursor-agent"
dc_timeout 120 cursor-agent -p "Reply with only the word ready. Do not use any tools." \
  --output-format json --force >/tmp/dc-cursor-validation.log 2>&1 || \
  dc_warn "cursor-agent exited non-zero (see /tmp/dc-cursor-validation.log)"
sleep 2

fired=1
if dc_assert_fired cursor "${before}"; then
  dc_log "RESULT: cursor-agent -p FIRES ~/.cursor/hooks.json"
  dc_record_result "validation:hooks-fire" pass ""
else
  fired=0
  dc_log "RESULT: cursor-agent -p did NOT fire the hook bus"
  dc_record_result "validation:hooks-fire" fail "no cursor events reached gateway in -p mode"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'cursor_hooks_fire=%s\n' "${fired}" >> "${GITHUB_OUTPUT}"
fi
dc_teardown_connector cursor || true

[ "${fired}" = "1" ]
