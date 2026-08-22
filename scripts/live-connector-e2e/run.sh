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

# Executable shell-hook connectors. Keep plugin/policy transports out of this
# Layer-A roster even when they have a real-agent live driver.
ALL_CONNECTORS=(codex claudecode amp cursor copilot openhands hermes devin antigravity)
LIVE_CONNECTORS=(codex claudecode amp cursor copilot openhands hermes devin antigravity opencode)

resolve_connectors() {
  if [ "${CONNECTOR}" = "all" ]; then
    if [ "${LAYER}" = "live" ]; then
      printf '%s\n' "${LIVE_CONNECTORS[@]}"
    else
      printf '%s\n' "${ALL_CONNECTORS[@]}"
    fi
  else
    printf '%s\n' "${CONNECTOR}"
  fi
}

run_contract() {
  local c="$1" fixture_dir="" fixture_bin="" fixture_src="" fixture_trusted=0 rc=0 cleanup_rc=0

  if [ "${c}" != "openhands" ] || [ "$(dc_detect_os)" != "macos" ]; then
    bash "${HERE}/contract-smoke.sh" "${c}"
    return
  fi

  # Darwin OpenHands setup deliberately requires a fresh protected executable
  # selection. Layer A never runs a real agent, so compile a minimal native
  # Mach-O that implements only the deterministic version probe. A script
  # fixture would incorrectly bypass the protected live execution boundary.
  fixture_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/dc-contract-openhands.XXXXXX")" || return 1
  fixture_bin="${fixture_dir}/openhands"
  fixture_src="${fixture_dir}/openhands.c"
  chmod 700 "${fixture_dir}" || rc=1
  if [ "${rc}" -eq 0 ]; then
    printf '%s\n' \
      '#include <stdio.h>' \
      '#include <string.h>' \
      'int main(int argc, char **argv) {' \
      '  if (argc == 2 && strcmp(argv[1], "--version") == 0) {' \
      '    puts("OpenHands CLI 1.16.0");' \
      '    return 0;' \
      '  }' \
      '  fputs("Layer A OpenHands fixture only supports --version\\n", stderr);' \
      '  return 64;' \
      '}' > "${fixture_src}" || rc=1
  fi
  if [ "${rc}" -eq 0 ]; then
    /usr/bin/cc -Os -o "${fixture_bin}" "${fixture_src}" || rc=1
  fi
  if [ "${rc}" -eq 0 ]; then
    chmod 700 "${fixture_bin}" || rc=1
  fi

  # Persist the run-owned directory through the supported trusted-paths API;
  # agent_selection.py intentionally ignores ambient trust variables for this
  # protected setup authority. Prefixing PATH lets ordinary discovery select
  # the same exact file that the receipt and Darwin lock later seal by digest.
  if [ "${rc}" -eq 0 ]; then
    dc_init_defenseclaw || rc=1
  fi
  if [ "${rc}" -eq 0 ]; then
    PATH="${fixture_dir}:${PATH}" \
      defenseclaw setup trusted-paths add "${fixture_dir}" --json >/dev/null || rc=1
    [ "${rc}" -ne 0 ] || fixture_trusted=1
  fi
  if [ "${rc}" -eq 0 ]; then
    PATH="${fixture_dir}:${PATH}" bash "${HERE}/contract-smoke.sh" "${c}" || rc=$?
  fi

  if [ "${fixture_trusted}" -eq 1 ]; then
    PATH="${fixture_dir}:${PATH}" \
      defenseclaw setup trusted-paths remove "${fixture_dir}" --json >/dev/null || cleanup_rc=1
  fi
  if [ -f "${fixture_bin}" ]; then
    rm -f "${fixture_bin}" || cleanup_rc=1
  fi
  if [ -f "${fixture_src}" ]; then
    rm -f "${fixture_src}" || cleanup_rc=1
  fi
  rmdir "${fixture_dir}" 2>/dev/null || cleanup_rc=1

  if [ "${rc}" -ne 0 ]; then
    return "${rc}"
  fi
  return "${cleanup_rc}"
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
