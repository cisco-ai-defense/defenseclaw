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
# Layer A — Contract entrypoint smoke (deterministic, no LLM, no secrets,
# every OS). For one connector this script:
#
#   1. `defenseclaw setup <connector> --mode action` (installs the hook
#      entrypoint + wires the agent config + restarts the gateway).
#   2. Feeds every golden stdin payload under golden/<connector>/ into the
#      *installed* hook entrypoint:
#        - unix:    ~/.defenseclaw/hooks/<connector>-hook.sh
#        - windows: defenseclaw-gateway hook --connector <name> --event <ev>
#   3. Asserts the gateway received the event (fires) and that the entrypoint
#      shaped the verdict correctly (allow -> exit 0; block -> exit 2 or a
#      decision JSON carrying block/deny).
#   4. Tears down and asserts the agent config is restored clean.
#
# This proves the decode -> map -> respond contract through the real installed
# entrypoint on every OS, complementing the Go contract matrix (which proves
# the same chain at the handler level). The block payload reads /etc/shadow
# (rule PATH-ETC-SHADOW, CRITICAL) so it is denied deterministically without
# an LLM and is harmless if a regression ever lets it through.
#
# Usage: contract-smoke.sh <connector>

set -euo pipefail

DC_E2E_CONNECTOR="${1:?usage: contract-smoke.sh <connector>}"
export DC_E2E_CONNECTOR

# Layer A deliberately runs with NO upstream agent installed — it feeds golden
# stdin payloads into the installed hook entrypoint, never the real CLI. With no
# agent on disk the cached agent version is empty, so ResolveHookContract returns
# "unversioned". In action mode the gateway boot path
# (internal/gateway/sidecar.go) then refuses to run Connector.Setup() unless this
# override is set, which would leave ~/.defenseclaw/hooks/<connector>-hook.sh
# unwritten and make every hook invocation exit 127. This is exactly the
# exploratory/no-agent scenario the override exists for, so opt in here. The
# export propagates to `defenseclaw setup` and the gateway daemon it restarts.
# Scoped to Layer A only: the live drivers don't source this file, so Layer B
# keeps the real agent-version hook-contract gate.
export DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "${HERE}/lib/common.sh"
# shellcheck source=lib/assert.sh
. "${HERE}/lib/assert.sh"
# shellcheck source=lib/setup.sh
. "${HERE}/lib/setup.sh"

golden_dir="${DC_E2E_GOLDEN_DIR}/${DC_E2E_CONNECTOR}"
if [ ! -d "${golden_dir}" ]; then
  dc_die "no golden payloads for connector ${DC_E2E_CONNECTOR} (expected ${golden_dir})"
fi

dc_section "contract smoke: ${DC_E2E_CONNECTOR} ($(dc_detect_os))"

dc_init_defenseclaw
dc_setup_connector "${DC_E2E_CONNECTOR}" action

overall_rc=0

# drive_event <event_label> <payload_file> <expect:allow|block>
drive_event() {
  local label="$1" payload="$2" expect="$3"
  local before after out code
  before="$(dc_gateway_jsonl_count)"
  out="$(dc_invoke_hook "${DC_E2E_CONNECTOR}" "${label}" "${payload}")"
  code="$(printf '%s\n' "${out}" | sed -n 's/^exit:\([0-9]\+\)$/\1/p' | tail -1)"
  # Give the gateway a beat to flush the JSONL line.
  sleep 1
  after="$(dc_gateway_jsonl_count)"

  # Fires: gateway received an event attributed to this connector.
  if dc_assert_fired "${DC_E2E_CONNECTOR}" "${before}"; then
    dc_record_result "${label}:fires" pass "jsonl ${before}->${after}"
  else
    dc_record_result "${label}:fires" fail "jsonl ${before}->${after} exit=${code}"
    overall_rc=1
  fi

  case "${expect}" in
    block)
      # Verdict shaping: the entrypoint must signal block — either a
      # non-zero (exit 2) deny or a decision JSON carrying block/deny.
      if [ "${code}" = "2" ] || printf '%s' "${out}" | grep -Eqi '"(decision|action|permissionDecision)"\s*:\s*"(block|deny)"|\bdeny\b|\bblock\b'; then
        dc_record_result "${label}:verdict-shape" pass "exit=${code}"
      else
        dc_record_result "${label}:verdict-shape" fail "expected block shaping, exit=${code}"
        overall_rc=1
      fi
      # Corroborate with a gateway-side block verdict.
      if dc_assert_verdict_block "${before}"; then
        dc_record_result "${label}:verdict-gateway" pass ""
      else
        dc_record_result "${label}:verdict-gateway" fail "no block verdict recorded"
        overall_rc=1
      fi
      ;;
    allow)
      if [ "${code}" = "0" ]; then
        dc_record_result "${label}:verdict-shape" pass "exit=0"
      else
        dc_record_result "${label}:verdict-shape" fail "expected allow (exit 0), exit=${code}"
        overall_rc=1
      fi
      ;;
  esac
}

# Drive whatever golden payloads exist for this connector.
[ -f "${golden_dir}/session_start.json" ] && drive_event "SessionStart" "${golden_dir}/session_start.json" allow
[ -f "${golden_dir}/pre_tool_allow.json" ] && drive_event "PreTool-allow" "${golden_dir}/pre_tool_allow.json" allow
[ -f "${golden_dir}/pre_tool_block.json" ] && drive_event "PreTool-block" "${golden_dir}/pre_tool_block.json" block

# Schema invariant over everything emitted so far.
if dc_assert_schema 1; then
  dc_record_result "schema" pass ""
else
  dc_record_result "schema" fail "gateway.jsonl schema validation failed"
  overall_rc=1
fi

# Teardown + clean-state assertion.
cfg="$(dc_connector_config_file "${DC_E2E_CONNECTOR}")"
if dc_teardown_connector "${DC_E2E_CONNECTOR}"; then
  if dc_assert_teardown "${DC_E2E_CONNECTOR}" "${cfg}"; then
    dc_record_result "teardown" pass ""
  else
    dc_record_result "teardown" fail "config not restored: ${cfg}"
    overall_rc=1
  fi
else
  dc_record_result "teardown" fail "connector verify reported residual state"
  overall_rc=1
fi

exit "${overall_rc}"
