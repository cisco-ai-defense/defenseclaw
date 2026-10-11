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
# Orchestrator for the live connector hook E2E harness. The workflow invokes
# one cell at a time (one connector x one OS), but this dispatcher also
# supports `--connector all` for local runs.
#
#   run.sh --layer contract --connector <name|all>   # Layer A entrypoint smoke
#   run.sh --layer live     --connector <name|all>   # Layer B live agent
#
# --connector also takes a space-separated list ("codex amp"); the macOS
# contract cell uses this to run every connector after a single install.
#
# Layer A targets connectors with an executable shell-hook contract (golden
# payload -> installed hook entrypoint). Plugin/policy transports are covered
# by focused tests instead. Layer B only targets connectors that ship a driver
# under drivers/; contract-only connectors (Hermes, Devin, and Antigravity)
# are skipped with a recorded `skip` so the matrix stays honest.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/lib/common.sh"
# shellcheck source=lib/setup.sh
. "${HERE}/lib/setup.sh"

LAYER=""
CONNECTOR=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --layer)     LAYER="$2"; shift 2 ;;
    --connector) CONNECTOR="$2"; shift 2 ;;
    --os)        DC_E2E_OS="$2"; export DC_E2E_OS; shift 2 ;;
    -h|--help)
      sed -n '12,30p' "$0"; exit 0 ;;
    *) dc_die "unknown argument: $1" ;;
  esac
done

[ -n "${LAYER}" ]     || dc_die "--layer contract|live is required"
[ -n "${CONNECTOR}" ] || dc_die "--connector <name|all> is required"

# Executable shell-hook connectors (Layer B covers the subset with drivers).
ALL_CONNECTORS=(codex claudecode amp cursor copilot hermes devin antigravity)

resolve_connectors() {
  if [ "${CONNECTOR}" = "all" ]; then
    printf '%s\n' "${ALL_CONNECTORS[@]}"
  else
    # shellcheck disable=SC2086 # intentional word split of a connector list
    printf '%s\n' ${CONNECTOR}
  fi
}

run_contract() {
  bash "${HERE}/contract-smoke.sh" "$1"
}

run_live() {
  local c="$1" driver="${HERE}/drivers/${c}.sh"
  if [ ! -f "${driver}" ]; then
    DC_E2E_CONNECTOR="${c}" dc_record_result "live" skip "contract-only connector (no live driver)"
    return 0
  fi
  bash "${driver}"
}

overall=0
while read -r c; do
  [ -n "${c}" ] || continue
  case "${LAYER}" in
    contract) run_contract "${c}" || overall=1 ;;
    live)     run_live "${c}"     || overall=1 ;;
    *)        dc_die "unknown layer: ${LAYER} (use contract|live)" ;;
  esac
done < <(resolve_connectors)

# Always stage logs so the workflow can upload them as an artifact. Prefer
# RUNNER_TEMP so the staged dir matches the actions/upload-artifact path in
# connector-live-e2e.yml ("${{ runner.temp }}/defenseclaw-live-e2e-logs"); on
# hosted macOS runners $TMPDIR is a per-user /var/folders path that the upload
# step never looks at, which silently dropped the gateway logs on failure.
dc_stage_logs "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/defenseclaw-live-e2e-logs" >/dev/null || true

exit "${overall}"
