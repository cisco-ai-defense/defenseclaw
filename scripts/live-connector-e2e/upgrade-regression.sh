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
# Persistent-macOS connector upgrade regression harness.
#
# The baseline and candidate executables are installed into a run-owned
# scratch directory. The user's global codex/claude/agy binaries are never
# installed over or updated. They are only queried with `--version` when no
# explicit baseline is supplied; native Claude is additionally invoked as an
# exact-version installer under an isolated HOME. The real HOME is retained
# when probes run so Keychain/login state can be reused.
# DefenseClaw itself gets a separate DEFENSECLAW_HOME and loopback ports; the
# user's ~/.defenseclaw is neither read nor removed. The one connector config
# file that DefenseClaw setup patches is snapshotted and restored exactly.
#
# Exit codes:
#   0 pass
#   2 candidate_regression (baseline passed; candidate failed)
#   3 auth_failure (baseline login expired/missing)
#   4 infrastructure_failure (install/setup/gateway/restore failure)
#   5 baseline_failure (baseline ran but its compatibility probes failed)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONNECTOR=""
BASELINE_VERSION=""
CANDIDATE_VERSION="latest"
RESULTS_PATH=""
CLASSIFICATION_OUTPUT=""
ARTIFACTS_DIR=""
MODE="action"
FRESH_SETUP_ON_FAILURE=1
KEEP_SCRATCH=0

usage() {
  cat <<'EOF'
Usage: upgrade-regression.sh --connector codex|claudecode|antigravity [options]

Required:
  --connector NAME              Connector to test.

Version selection:
  --baseline-version VERSION    Exact known-good version. When omitted, use
                                the installed CLI's reported version.
  --candidate-version VERSION   Exact candidate version, or latest (default).

Outputs:
  --results PATH                Result JSONL path.
  --classification-output PATH  Machine-readable classification JSON.
  --artifacts-dir DIR           Probe/gateway log directory.
                                Also writes outputs to $GITHUB_OUTPUT when set.

Behavior:
  --mode action|observe         DefenseClaw mode (default: action).
  --fresh-setup-on-failure      Re-run setup against a failing candidate
                                to classify whether setup repairs the upgrade
                                (default).
  --no-fresh-setup-on-failure   Skip the recovery classification phase.
  --keep-scratch                Retain isolated binaries/config for debugging.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --connector) CONNECTOR="${2:-}"; shift 2 ;;
    --baseline-version) BASELINE_VERSION="${2:-}"; shift 2 ;;
    --candidate-version) CANDIDATE_VERSION="${2:-}"; shift 2 ;;
    --results) RESULTS_PATH="${2:-}"; shift 2 ;;
    --classification-output) CLASSIFICATION_OUTPUT="${2:-}"; shift 2 ;;
    --artifacts-dir) ARTIFACTS_DIR="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --fresh-setup-on-failure) FRESH_SETUP_ON_FAILURE=1; shift ;;
    --no-fresh-setup-on-failure) FRESH_SETUP_ON_FAILURE=0; shift ;;
    --keep-scratch) KEEP_SCRATCH=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf '[upgrade-regression][error] unknown argument: %s\n' "$1" >&2; usage >&2; exit 4 ;;
  esac
done

case "${CONNECTOR}" in
  codex|claudecode|antigravity) ;;
  *) printf '[upgrade-regression][error] --connector must be codex, claudecode, or antigravity\n' >&2; exit 4 ;;
esac
case "${MODE}" in
  action|observe) ;;
  *) printf '[upgrade-regression][error] --mode must be action or observe\n' >&2; exit 4 ;;
esac
if [ -z "${CANDIDATE_VERSION}" ]; then
  printf '[upgrade-regression][error] --candidate-version cannot be empty\n' >&2
  exit 4
fi

umask 077
TEMP_PARENT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
mkdir -p "${TEMP_PARENT}"
SCRATCH="$(mktemp -d "${TEMP_PARENT%/}/dc-connector-upgrade.XXXXXX")"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
if [ -z "${ARTIFACTS_DIR}" ]; then
  ARTIFACTS_DIR="${TEMP_PARENT%/}/defenseclaw-connector-upgrade-artifacts/${CONNECTOR}/${RUN_ID}"
fi
mkdir -p "${ARTIFACTS_DIR}/probes" "${ARTIFACTS_DIR}/gateway"
if [ -z "${RESULTS_PATH}" ]; then
  RESULTS_PATH="${ARTIFACTS_DIR}/results.jsonl"
fi
if [ -z "${CLASSIFICATION_OUTPUT}" ]; then
  CLASSIFICATION_OUTPUT="${ARTIFACTS_DIR}/classification.json"
fi
mkdir -p "$(dirname "${RESULTS_PATH}")" "$(dirname "${CLASSIFICATION_OUTPUT}")"
: > "${RESULTS_PATH}"

# Set every harness path before common.sh captures its defaults.
export DEFENSECLAW_HOME="${SCRATCH}/defenseclaw"
export DC_E2E_RESULTS="${RESULTS_PATH}"
export DC_E2E_PROBE_LOG_DIR="${ARTIFACTS_DIR}/probes"
export DC_E2E_AGENT_WORKSPACE="${SCRATCH}/workspace"
export DC_E2E_SENTINEL_DIR="${DC_E2E_AGENT_WORKSPACE}/sentinels"
export DC_E2E_OS=macos
mkdir -p "${DC_E2E_AGENT_WORKSPACE}"

. "${HERE}/lib/common.sh"
. "${HERE}/lib/assert.sh"
. "${HERE}/lib/setup.sh"
. "${HERE}/drivers/_driver_common.sh"
. "${HERE}/lib/persistent-macos.sh"

ORIGINAL_PATH="${PATH}"
LOCK_DIR="${TEMP_PARENT%/}/defenseclaw-connector-upgrade-${UID}.lock"
LOCK_ACQUIRED=0
SNAPSHOT_READY=0
GATEWAY_STARTED=0
RESTORE_OK=1
CLASSIFICATION="infrastructure_failure"
DETAIL="harness exited before classification"
BASELINE_STATUS="not_run"
CANDIDATE_STATUS="not_run"
FRESH_SETUP_STATUS="not_run"
RECOVERY="not_attempted"
RESOLVED_BASELINE_VERSION=""
RESOLVED_CANDIDATE_VERSION=""
BASELINE_BIN=""
CANDIDATE_BIN=""
HARNESS_EXIT_CODE=4

dc_upgrade_copy_artifacts() {
  local name
  # The cleanup trap stops the gateway first, so these SQLite files are
  # quiescent and can be copied byte-for-byte as canonical v8 evidence.
  for name in gateway.log audit.db judge_bodies.db watchdog.log; do
    if [ -f "${DEFENSECLAW_HOME}/${name}" ]; then
      /bin/cp -p "${DEFENSECLAW_HOME}/${name}" "${ARTIFACTS_DIR}/gateway/${name}" 2>/dev/null || true
    fi
  done
}

dc_upgrade_write_classification() {
  python3 - \
    "${CLASSIFICATION_OUTPUT}" "${CONNECTOR}" "${CLASSIFICATION}" "${DETAIL}" \
    "${RESOLVED_BASELINE_VERSION}" "${RESOLVED_CANDIDATE_VERSION}" \
    "${BASELINE_STATUS}" "${CANDIDATE_STATUS}" "${FRESH_SETUP_STATUS}" \
    "${RECOVERY}" "${RESULTS_PATH}" "${ARTIFACTS_DIR}" <<'PY'
import json, os, sys
(
    output, connector, classification, detail, baseline_version,
    candidate_version, baseline_status, candidate_status,
    fresh_setup_status, recovery, results, artifacts,
) = sys.argv[1:]
payload = {
    "connector": connector,
    "classification": classification,
    "detail": detail,
    "baseline_version": baseline_version,
    "candidate_version": candidate_version,
    "baseline_status": baseline_status,
    "candidate_status": candidate_status,
    "fresh_setup_status": fresh_setup_status,
    "recovery": recovery,
    "candidate_regression": classification == "candidate_regression",
    "should_open_fix_pr": classification == "candidate_regression",
    "results": os.path.abspath(results),
    "artifacts": os.path.abspath(artifacts),
}
tmp = output + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write("\n")
os.replace(tmp, output)
PY

  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      printf 'classification=%s\n' "${CLASSIFICATION}"
      printf 'candidate_regression=%s\n' "$([ "${CLASSIFICATION}" = candidate_regression ] && printf true || printf false)"
      printf 'should_open_fix_pr=%s\n' "$([ "${CLASSIFICATION}" = candidate_regression ] && printf true || printf false)"
      printf 'baseline_version=%s\n' "${RESOLVED_BASELINE_VERSION}"
      printf 'candidate_version=%s\n' "${RESOLVED_CANDIDATE_VERSION}"
      printf 'classification_output=%s\n' "${CLASSIFICATION_OUTPUT}"
      printf 'results=%s\n' "${RESULTS_PATH}"
      printf 'artifacts=%s\n' "${ARTIFACTS_DIR}"
    } >> "${GITHUB_OUTPUT}"
  fi
}

dc_upgrade_cleanup() {
  local original_rc=$?
  trap - EXIT INT TERM HUP
  set +e
  if [ "${GATEWAY_STARTED}" = "1" ]; then
    PATH="${ORIGINAL_PATH}" defenseclaw-gateway stop >/dev/null 2>&1 || true
  fi
  dc_upgrade_copy_artifacts
  if [ "${SNAPSHOT_READY}" = "1" ]; then
    if ! dc_persist_restore_files; then
      RESTORE_OK=0
      CLASSIFICATION="infrastructure_failure"
      DETAIL="connector config restore failed; recovery snapshot retained at ${SCRATCH}/snapshot"
      HARNESS_EXIT_CODE=4
    fi
  fi
  if [ "${LOCK_ACQUIRED}" = "1" ]; then
    dc_persist_release_lock "${LOCK_DIR}" || true
  fi
  dc_upgrade_write_classification || {
    printf '[upgrade-regression][error] could not write classification output\n' >&2
    HARNESS_EXIT_CODE=4
  }
  if [ "${KEEP_SCRATCH}" = "1" ] || [ "${RESTORE_OK}" != "1" ]; then
    dc_warn "retained scratch directory: ${SCRATCH}"
  else
    dc_persist_cleanup_scratch "${SCRATCH}" || true
  fi
  dc_log "classification=${CLASSIFICATION} detail=${DETAIL}"
  dc_log "classification output: ${CLASSIFICATION_OUTPUT}"
  if [ "${HARNESS_EXIT_CODE}" -eq 0 ] && [ "${original_rc}" -ne 0 ]; then
    HARNESS_EXIT_CODE="${original_rc}"
  fi
  exit "${HARNESS_EXIT_CODE}"
}

trap dc_upgrade_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if ! dc_persist_acquire_lock "${LOCK_DIR}"; then
  DETAIL="could not acquire the per-user upgrade harness lock"
  exit 4
fi
LOCK_ACQUIRED=1

case "$(uname -s 2>/dev/null || true)" in
  Darwin) ;;
  *)
    if [ "${DC_UPGRADE_ALLOW_NON_MACOS:-0}" != "1" ]; then
      DETAIL="persistent upgrade harness requires macOS (set DC_UPGRADE_ALLOW_NON_MACOS=1 only for tests)"
      exit 4
    fi
    ;;
esac

dc_upgrade_version_number() {
  local raw="$1"
  if [[ "${raw}" =~ ([0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

dc_upgrade_binary_version() {
  local connector="$1" binary="$2" raw
  raw="$("${binary}" --version 2>&1)" || return 1
  dc_upgrade_version_number "${raw}"
}

dc_upgrade_installed_version() {
  local name path
  case "${CONNECTOR}" in
    codex) name=codex ;;
    claudecode) name=claude ;;
    antigravity) name=agy ;;
  esac
  path="$(command -v "${name}" 2>/dev/null)" || {
    dc_err "${name} is not installed and --baseline-version was not supplied"
    return 1
  }
  dc_upgrade_binary_version "${CONNECTOR}" "${path}"
}

dc_upgrade_install_npm() {
  local prefix="$1" package="$2" requested="$3" bin_name="$4" spec actual
  mkdir -p "${prefix}"
  spec="${package}@${requested}"
  dc_log "installing isolated ${spec}"
  npm install --prefix "${prefix}" --no-save --no-package-lock --no-audit --no-fund "${spec}" \
    >"${ARTIFACTS_DIR}/$(basename "${prefix}")-install.log" 2>&1 || return 1
  [ -x "${prefix}/node_modules/.bin/${bin_name}" ] || return 1
  actual="$(dc_upgrade_binary_version "${CONNECTOR}" "${prefix}/node_modules/.bin/${bin_name}")" || return 1
  if [ "${requested}" != "latest" ] && [ "${actual}" != "${requested}" ]; then
    dc_err "isolated ${bin_name} version ${actual}, requested ${requested}"
    return 1
  fi
  printf '%s\t%s' "${prefix}/node_modules/.bin/${bin_name}" "${actual}"
}

# Claude's npm package cannot access a macOS subscription login stored in the
# Keychain, while the signed native build can. Ask the already-installed native
# Claude binary to install an exact release under an isolated HOME, then run
# that binary later with the real HOME so authentication is reused. The user's
# global ~/.local/bin/claude symlink and native version store are never changed.
dc_upgrade_install_claude_native() {
  local prefix="$1" requested="$2" source install_home link binary actual log
  source="$(command -v claude 2>/dev/null)" || {
    dc_err "the logged-in native Claude binary is not installed"
    return 1
  }
  source="$(dc_persist_realpath "${source}")" || return 1
  [ -x "${source}" ] || return 1
  install_home="${prefix}/installer-home"
  log="${ARTIFACTS_DIR}/$(basename "${prefix}")-native-install.log"
  mkdir -p "${install_home}"
  install_home="$(dc_persist_realpath "${install_home}")" || return 1
  link="${install_home}/.local/bin/claude"
  dc_log "installing isolated native Claude Code ${requested}"
  HOME="${install_home}" DISABLE_AUTOUPDATER=1 \
    dc_timeout 240 "${source}" install "${requested}" \
    >"${log}" 2>&1 || return 1
  [ -x "${link}" ] || return 1
  binary="$(dc_persist_realpath "${link}")" || return 1
  case "${binary}" in
    "${install_home}"/.local/share/claude/versions/*) ;;
    *)
      dc_err "isolated Claude installer resolved outside its run-owned HOME"
      return 1
      ;;
  esac
  actual="$(HOME="${install_home}" DISABLE_AUTOUPDATER=1 \
    dc_upgrade_binary_version claudecode "${binary}")" || return 1
  if [ "${requested}" != "latest" ] && [ "${actual}" != "${requested}" ]; then
    dc_err "isolated native Claude version ${actual}, requested ${requested}"
    return 1
  fi
  printf '%s\t%s' "${binary}" "${actual}"
}

dc_upgrade_install_antigravity_candidate() {
  local prefix="$1" requested="$2" record binary manifest_version actual
  record="$(dc_install_antigravity_release "${prefix}" "${requested}")" || return 1
  IFS=$'\t' read -r binary manifest_version <<< "${record}"
  [ -x "${binary}" ] || return 1
  actual="$(dc_upgrade_binary_version antigravity "${binary}")" || return 1
  if [ "${actual}" != "${manifest_version}" ]; then
    dc_err "isolated agy version ${actual}, verified manifest version ${manifest_version}"
    return 1
  fi
  printf '%s\t%s' "${binary}" "${actual}"
}

dc_upgrade_install_antigravity_baseline() {
  local prefix="$1" requested="$2" global actual
  global="$(command -v agy 2>/dev/null)" || return 1
  actual="$(dc_upgrade_binary_version antigravity "${global}")" || return 1
  if [ -n "${requested}" ] && [ "${actual}" != "${requested}" ]; then
    dc_err "Antigravity cannot install historical builds; global agy=${actual}, requested baseline=${requested}"
    return 1
  fi
  mkdir -p "${prefix}/bin"
  /bin/cp -p "$(dc_persist_realpath "${global}")" "${prefix}/bin/agy" || return 1
  chmod 500 "${prefix}/bin/agy"
  # Keep the run-owned parent private but writable so validated scratch
  # cleanup can unlink the read-only baseline binary.
  chmod 700 "${prefix}/bin"
  printf '%s\t%s' "${prefix}/bin/agy" "${actual}"
}

if [ -z "${BASELINE_VERSION}" ]; then
  BASELINE_VERSION="$(dc_upgrade_installed_version)" || {
    DETAIL="could not resolve the installed baseline version"
    exit 4
  }
fi

# Snapshot only the connector file DefenseClaw is authorized to patch. Auth
# databases, keyrings, session files, and their parent directories are never
# copied or removed.
dc_persist_snapshot_init "${SCRATCH}/snapshot"
dc_persist_snapshot_file "$(dc_connector_config_file "${CONNECTOR}")" || {
  DETAIL="could not snapshot connector config safely"
  exit 4
}
SNAPSHOT_READY=1

install_record=""
case "${CONNECTOR}" in
  codex)
    install_record="$(dc_upgrade_install_npm "${SCRATCH}/baseline" '@openai/codex' "${BASELINE_VERSION}" codex)" || {
      DETAIL="isolated Codex baseline install failed"
      exit 4
    }
    IFS=$'\t' read -r BASELINE_BIN RESOLVED_BASELINE_VERSION <<< "${install_record}"
    install_record="$(dc_upgrade_install_npm "${SCRATCH}/candidate" '@openai/codex' "${CANDIDATE_VERSION}" codex)" || {
      DETAIL="isolated Codex candidate install failed"
      exit 4
    }
    IFS=$'\t' read -r CANDIDATE_BIN RESOLVED_CANDIDATE_VERSION <<< "${install_record}"
    ;;
  claudecode)
    # Disable background updates before any native Claude process starts. The
    # explicit `install` subcommand below still installs the requested release
    # into its isolated HOME; probes later reuse the real HOME only for login.
    export DISABLE_AUTOUPDATER=1
    install_record="$(dc_upgrade_install_claude_native "${SCRATCH}/baseline" "${BASELINE_VERSION}")" || {
      DETAIL="isolated native Claude Code baseline install failed"
      exit 4
    }
    IFS=$'\t' read -r BASELINE_BIN RESOLVED_BASELINE_VERSION <<< "${install_record}"
    install_record="$(dc_upgrade_install_claude_native "${SCRATCH}/candidate" "${CANDIDATE_VERSION}")" || {
      DETAIL="isolated native Claude Code candidate install failed"
      exit 4
    }
    IFS=$'\t' read -r CANDIDATE_BIN RESOLVED_CANDIDATE_VERSION <<< "${install_record}"
    ;;
  antigravity)
    install_record="$(dc_upgrade_install_antigravity_baseline "${SCRATCH}/baseline" "${BASELINE_VERSION}")" || {
      DETAIL="isolated Antigravity baseline copy failed"
      exit 4
    }
    IFS=$'\t' read -r BASELINE_BIN RESOLVED_BASELINE_VERSION <<< "${install_record}"
    install_record="$(dc_upgrade_install_antigravity_candidate "${SCRATCH}/candidate" "${CANDIDATE_VERSION}")" || {
      DETAIL="isolated Antigravity candidate install failed"
      exit 4
    }
    IFS=$'\t' read -r CANDIDATE_BIN RESOLVED_CANDIDATE_VERSION <<< "${install_record}"
    ;;
esac

[ -x "${BASELINE_BIN}" ] && [ -x "${CANDIDATE_BIN}" ] || {
  DETAIL="isolated baseline or candidate binary is not executable"
  exit 4
}

dc_section "upgrade regression: ${CONNECTOR} ${RESOLVED_BASELINE_VERSION} -> ${RESOLVED_CANDIDATE_VERSION}"
dc_init_defenseclaw
# `defenseclaw init` starts a sidecar using the freshly-created default
# ports. Stop that run before assigning the harness-owned ports; otherwise
# `start` sees the old PID and health probes read a different API port than
# the running sidecar.
if ! defenseclaw-gateway stop >/dev/null; then
  DETAIL="could not stop the post-init isolated gateway before port assignment"
  exit 4
fi
dc_persist_isolate_gateway_config || {
  DETAIL="could not configure the isolated DefenseClaw gateway"
  exit 4
}

# Trust only the two run-owned bin directories in the isolated DefenseClaw
# config. This never changes ~/.defenseclaw. --force is intentional because
# user-owned npm prefixes are writable by the dedicated runner account.
for trusted in "${SCRATCH}/baseline" "${SCRATCH}/candidate"; do
  defenseclaw setup trusted-paths add "${trusted}" --force --json >/dev/null || {
    DETAIL="could not trust isolated connector binary path ${trusted}"
    exit 4
  }
done

dc_upgrade_setup_without_restart() {
  local binary="$1" sub
  sub="$(dc_setup_subcommand "${CONNECTOR}")"
  PATH="$(dirname "${binary}"):${ORIGINAL_PATH}" \
    defenseclaw setup "${sub}" --yes --mode "${MODE}" --no-restart
  # setup enables discovery by design; turn it back off before this dedicated
  # test gateway starts so it never scans the runner user's home directory.
  dc_persist_isolate_gateway_config
}

if ! dc_upgrade_setup_without_restart "${BASELINE_BIN}"; then
  dc_record_result "baseline:setup" fail "DefenseClaw baseline setup failed"
  DETAIL="DefenseClaw setup failed against the known-good baseline"
  exit 4
fi
dc_record_result "baseline:setup" pass "mode=${MODE}"
if ! PATH="$(dirname "${BASELINE_BIN}"):${ORIGINAL_PATH}" defenseclaw-gateway start; then
  DETAIL="isolated gateway failed to start for the baseline"
  exit 4
fi
GATEWAY_STARTED=1
if ! PATH="$(dirname "${BASELINE_BIN}"):${ORIGINAL_PATH}" dc_wait_for_gateway 30; then
  DETAIL="isolated gateway did not become healthy for the baseline"
  exit 4
fi

# Driver adapter: every phase swaps only DC_UPGRADE_ACTIVE_BIN. HOME remains
# the logged-in runner user's HOME so subscription/Keychain auth is reused.
DC_DRIVER_MODE="${MODE}"
case "${CONNECTOR}" in
  codex)
    DC_DRIVER_SUPPORTS_LIFECYCLE=1
    DC_DRIVER_SUPPORTS_BLOCK=1
    DC_DRIVER_SUPPORTS_OTLP=1
    ;;
  claudecode)
    DC_DRIVER_SUPPORTS_LIFECYCLE=1
    DC_DRIVER_SUPPORTS_BLOCK=1
    DC_DRIVER_SUPPORTS_OTLP=1
    ;;
  antigravity)
    # PreToolUse is the currently proven headless event. Antigravity has no
    # native OTLP export in the DefenseClaw connector contract.
    DC_DRIVER_SUPPORTS_LIFECYCLE=0
    DC_DRIVER_SUPPORTS_BLOCK=1
    DC_DRIVER_SUPPORTS_OTLP=0
    ;;
esac

agent_run() {
  local prompt="$1"
  (
    cd "${DC_E2E_AGENT_WORKSPACE}"
    case "${CONNECTOR}" in
      codex)
        dc_timeout 180 "${DC_UPGRADE_ACTIVE_BIN}" exec --json --full-auto \
          --skip-git-repo-check "${prompt}"
        ;;
      claudecode)
        dc_timeout 180 "${DC_UPGRADE_ACTIVE_BIN}" -p "${prompt}" \
          --output-format json --permission-mode acceptEdits --allowedTools Bash
        ;;
      antigravity)
        # agy treats every argument after --print as prompt text. Keep the
        # permission flag first so tool calls are actually auto-approved.
        dc_timeout 180 "${DC_UPGRADE_ACTIVE_BIN}" \
          --dangerously-skip-permissions --print "${prompt}"
        ;;
    esac
  )
}

PHASE_AGENT_FAILURE=0
PHASE_AUTH_FAILURE=0
dc_upgrade_run_phase() {
  local phase="$1" binary="$2" version="$3" rc=0
  export DC_UPGRADE_ACTIVE_BIN="${binary}"
  export DC_E2E_AGENT_VERSION="${version}"
  export DC_E2E_PROBE_PREFIX="${phase}"
  DC_DRIVER_RESULT_PREFIX="${phase}:"
  PATH="$(dirname "${binary}"):${ORIGINAL_PATH}"
  export PATH
  if dc_driver_run_probes "${CONNECTOR}"; then
    rc=0
  else
    rc=1
  fi
  PHASE_AGENT_FAILURE="${DC_DRIVER_LAST_AGENT_FAILURE}"
  PHASE_AUTH_FAILURE="${DC_DRIVER_LAST_AUTH_FAILURE}"
  return "${rc}"
}

if dc_upgrade_run_phase baseline "${BASELINE_BIN}" "${RESOLVED_BASELINE_VERSION}"; then
  BASELINE_STATUS="pass"
else
  BASELINE_STATUS="fail"
  if [ "${PHASE_AUTH_FAILURE}" = "1" ]; then
    CLASSIFICATION="auth_failure"
    DETAIL="known-good baseline could not authenticate; refresh the connector login"
    HARNESS_EXIT_CODE=3
  elif [ "${PHASE_AGENT_FAILURE}" = "1" ]; then
    CLASSIFICATION="baseline_failure"
    DETAIL="known-good baseline agent failed before compatibility could be established"
    HARNESS_EXIT_CODE=5
  else
    CLASSIFICATION="baseline_failure"
    DETAIL="known-good baseline no longer passes DefenseClaw live probes"
    HARNESS_EXIT_CODE=5
  fi
  exit "${HARNESS_EXIT_CODE}"
fi

# Upgrade invariant: do not call setup here. The connector config hash is
# recorded immediately before switching executable versions as audit evidence.
BASELINE_SETUP_HASH="$(dc_persist_sha256 "$(dc_connector_config_file "${CONNECTOR}")")"
printf '%s\n' "${BASELINE_SETUP_HASH}" > "${ARTIFACTS_DIR}/baseline-setup-config.sha256"
dc_log "switching to isolated candidate without re-running DefenseClaw setup"

if dc_upgrade_run_phase candidate-upgrade "${CANDIDATE_BIN}" "${RESOLVED_CANDIDATE_VERSION}"; then
  CANDIDATE_STATUS="pass"
  CLASSIFICATION="pass"
  DETAIL="baseline and in-place candidate upgrade probes passed"
  HARNESS_EXIT_CODE=0
  exit 0
fi

CANDIDATE_STATUS="fail"
CLASSIFICATION="candidate_regression"
DETAIL="baseline passed but candidate failed without re-running DefenseClaw setup"
HARNESS_EXIT_CODE=2

if [ "${FRESH_SETUP_ON_FAILURE}" = "1" ]; then
  RECOVERY="attempted"
  dc_log "candidate failed; testing explicit DefenseClaw setup as recovery"
  if dc_upgrade_setup_without_restart "${CANDIDATE_BIN}" && \
     PATH="$(dirname "${CANDIDATE_BIN}"):${ORIGINAL_PATH}" defenseclaw-gateway restart && \
     PATH="$(dirname "${CANDIDATE_BIN}"):${ORIGINAL_PATH}" dc_wait_for_gateway 30; then
    if dc_upgrade_run_phase candidate-fresh "${CANDIDATE_BIN}" "${RESOLVED_CANDIDATE_VERSION}"; then
      FRESH_SETUP_STATUS="pass"
      RECOVERY="fresh_setup_passed"
      DETAIL="candidate upgrade failed with baseline wiring but passed after fresh setup"
    else
      FRESH_SETUP_STATUS="fail"
      RECOVERY="fresh_setup_failed"
      DETAIL="candidate failed both in-place upgrade and fresh-setup probes"
    fi
  else
    FRESH_SETUP_STATUS="setup_failed"
    RECOVERY="fresh_setup_failed"
    DETAIL="candidate upgrade failed and candidate DefenseClaw setup/restart also failed"
  fi
fi

exit 2
