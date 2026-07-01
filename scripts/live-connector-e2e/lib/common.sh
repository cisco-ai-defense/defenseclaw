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
# Shared helpers for the live connector hook E2E harness. Sourced by
# run.sh, contract-smoke.sh, cursor-validation.sh, and every per-connector
# driver under drivers/. This file defines functions only — callers own
# `set -euo pipefail`.
#
# Cross-OS note: on Linux/macOS the agent invokes the installed Bash hook
# script (~/.defenseclaw/hooks/<connector>-hook.sh). On native Windows the
# agent invokes `defenseclaw-hook hook --connector <name> --event <ev>`
# (PR #308). Both forward the stdin event payload to the local gateway, so
# every assertion below works against canonical ~/.defenseclaw/audit.db history
# regardless of OS.

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# DC_E2E_LIB_DIR resolves to .../scripts/live-connector-e2e/lib.
DC_E2E_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DC_E2E_ROOT="$(cd "${DC_E2E_LIB_DIR}/.." && pwd)"
DC_E2E_REPO_ROOT="$(cd "${DC_E2E_ROOT}/../.." && pwd)"
DC_E2E_GOLDEN_DIR="${DC_E2E_ROOT}/golden"

# DefenseClaw home (where the gateway writes canonical SQLite history and
# where `defenseclaw setup` installs the hook scripts + .token).
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
DC_AUDIT_DB="${DEFENSECLAW_HOME}/audit.db"

# Results sink. Every per-event outcome is appended here as one JSON object
# per line so report.py can roll the matrix up and decide whether to open a
# connector-regression issue. Defaults to a run-scoped file the workflow
# uploads as an artifact.
DC_E2E_RESULTS="${DC_E2E_RESULTS:-${DC_E2E_REPO_ROOT}/connector-live-e2e-results.jsonl}"

# Sentinel side-effect directory. The forced-tool probes write/avoid-writing
# a marker file here so we can prove enforcement rather than trusting logs.
DC_E2E_SENTINEL_DIR="${DC_E2E_SENTINEL_DIR:-${TMPDIR:-/tmp}/dc-e2e-sentinels}"

# Per-cell identity (connector + os). Drivers set DC_E2E_CONNECTOR; the OS is
# derived. These flow into record_result and the job summary.
DC_E2E_OS="${DC_E2E_OS:-}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

dc_log()     { printf '[live-e2e] %s\n' "$*" >&2; }
dc_warn()    { printf '[live-e2e][warn] %s\n' "$*" >&2; }
dc_err()     { printf '[live-e2e][error] %s\n' "$*" >&2; }
dc_section() { printf '\n[live-e2e] ===== %s =====\n' "$*" >&2; }

# dc_die <message> — log and exit non-zero.
dc_die() { dc_err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

# dc_detect_os — echoes linux|macos|windows. Honors DC_E2E_OS override (set by
# the workflow matrix) so the value matches the runner label exactly.
dc_detect_os() {
  if [ -n "${DC_E2E_OS}" ]; then
    printf '%s' "${DC_E2E_OS}"
    return 0
  fi
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux*)             printf 'linux' ;;
    Darwin*)            printf 'macos' ;;
    MINGW*|MSYS*|CYGWIN*) printf 'windows' ;;
    *)                  printf 'unknown' ;;
  esac
}

dc_is_windows() { [ "$(dc_detect_os)" = "windows" ]; }

# ---------------------------------------------------------------------------
# Gateway lifecycle
# ---------------------------------------------------------------------------

# dc_wait_for_gateway [timeout_seconds] — poll `defenseclaw-gateway status`
# until healthy. Mirrors the 30s readiness poll in .github/workflows/e2e.yml
# so behavior is identical to the OpenClaw stack gate.
dc_wait_for_gateway() {
  local timeout="${1:-30}" i
  for i in $(seq 1 "${timeout}"); do
    if defenseclaw-gateway status >/dev/null 2>&1; then
      dc_log "gateway healthy after ${i}s"
      return 0
    fi
    sleep 1
  done
  dc_err "gateway did not become healthy within ${timeout}s"
  dc_dump_gateway_logs
  return 1
}

# dc_dump_gateway_logs — tail the sidecar logs for failure triage. Same files
# the e2e.yml failure path inspects.
dc_dump_gateway_logs() {
  local f
  for f in gateway.log watchdog.log; do
    if [ -f "${DEFENSECLAW_HOME}/${f}" ]; then
      dc_log "--- ${f} (tail) ---"
      tail -n 80 "${DEFENSECLAW_HOME}/${f}" >&2 2>/dev/null || true
    fi
  done
}

# dc_event_cursor — greatest canonical SQLite audit row id currently on disk.
# Used to bound assertions to "events emitted since the probe" rather than the
# whole history. A missing/not-yet-migrated store has cursor zero.
dc_event_cursor() {
  [ -f "${DC_AUDIT_DB}" ] || { printf '0'; return 0; }
  python3 - "${DC_AUDIT_DB}" <<'PY'
import sqlite3
import sys

try:
    connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=2)
    value = connection.execute("SELECT COALESCE(MAX(rowid), 0) FROM audit_events").fetchone()[0]
except (OSError, sqlite3.Error, TypeError):
    value = 0
finally:
    try:
        connection.close()
    except (NameError, sqlite3.Error):
        pass
print(int(value or 0))
PY
}

# ---------------------------------------------------------------------------
# Version capture
# ---------------------------------------------------------------------------

# dc_capture_version <connector> <cmd> [args...] — resolve and record the
# upstream agent version. Tolerant of agents that print to stderr or use a
# non-standard flag; never fails the run on a version-probe error.
dc_capture_version() {
  local connector="$1"; shift
  local raw
  raw="$("$@" 2>&1 | head -n 3 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')" || raw="unknown"
  [ -n "${raw}" ] || raw="unknown"
  dc_log "resolved ${connector} version: ${raw}"
  printf '%s' "${raw}"
}

# ---------------------------------------------------------------------------
# Sentinel side-effects (real-enforcement proof)
# ---------------------------------------------------------------------------

# dc_new_sentinel_token — unique token for one probe, namespaced to the cell.
dc_new_sentinel_token() {
  printf 'dc-%s-%s-%s' "${DC_E2E_CONNECTOR:-x}" "$(dc_detect_os)" "$(date +%s)$RANDOM"
}

# dc_sentinel_path <token> — absolute path of the marker file for a token.
dc_sentinel_path() {
  mkdir -p "${DC_E2E_SENTINEL_DIR}"
  printf '%s/%s.marker' "${DC_E2E_SENTINEL_DIR}" "$1"
}

# dc_sentinel_present <token> — true if the probe's command actually ran.
dc_sentinel_present() { [ -e "$(dc_sentinel_path "$1")" ]; }

# dc_clear_sentinels — wipe markers between probes.
dc_clear_sentinels() { rm -rf "${DC_E2E_SENTINEL_DIR}" 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# Result recording
# ---------------------------------------------------------------------------

# dc_record_result <event> <status> [detail] — append one matrix cell outcome.
# status is one of: pass | fail | skip. DC_E2E_CONNECTOR + version come from
# the driver context. Also mirrors a human line to $GITHUB_STEP_SUMMARY.
dc_record_result() {
  local event="$1" status="$2" detail="${3:-}"
  local connector="${DC_E2E_CONNECTOR:-unknown}"
  local os; os="$(dc_detect_os)"
  local version="${DC_E2E_AGENT_VERSION:-unknown}"
  mkdir -p "$(dirname "${DC_E2E_RESULTS}")"
  python3 - "$connector" "$os" "$event" "$status" "$version" "$detail" >> "${DC_E2E_RESULTS}" <<'PY'
import json, sys
connector, os_, event, status, version, detail = sys.argv[1:7]
print(json.dumps({
    "connector": connector,
    "os": os_,
    "event": event,
    "status": status,
    "version": version,
    "detail": detail,
}))
PY
  local glyph="PASS"
  case "${status}" in
    fail) glyph="FAIL" ;;
    skip) glyph="SKIP" ;;
  esac
  dc_log "[${glyph}] ${connector}/${os}/${event} ${detail}"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '| %s | %s | %s | %s | %s |\n' \
      "${connector}" "${os}" "${event}" "${glyph}" "${detail//|/\\|}" \
      >> "${GITHUB_STEP_SUMMARY}"
  fi
}

# ---------------------------------------------------------------------------
# Log staging (artifact upload on failure)
# ---------------------------------------------------------------------------

# dc_stage_logs <stage_dir> — copy gateway logs + the result records into a
# directory the workflow uploads with actions/upload-artifact. Mirrors the
# "Stage DefenseClaw logs" step in e2e.yml.
dc_stage_logs() {
  local stage="${1:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/defenseclaw-live-e2e-logs}"
  rm -rf "${stage}"; mkdir -p "${stage}"
  if [ -d "${DEFENSECLAW_HOME}" ]; then
    local pat
    for pat in '*.log' '*.jsonl' 'config.yaml'; do
      find "${DEFENSECLAW_HOME}" -maxdepth 2 -type f -name "${pat}" \
        -exec cp {} "${stage}/" \; 2>/dev/null || true
    done
    # A file copy can race WAL commits. Use SQLite's online backup API so a
    # failed connector cell uploads one internally consistent canonical
    # history snapshot for diagnosis on every OS.
    if [ -f "${DC_AUDIT_DB}" ]; then
      python3 - "${DC_AUDIT_DB}" "${stage}/audit.db" <<'PY' || true
import sqlite3
import sys

source = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=2)
destination = sqlite3.connect(sys.argv[2])
try:
    source.backup(destination)
finally:
    destination.close()
    source.close()
PY
    fi
  fi
  cp "${DC_E2E_RESULTS}" "${stage}/" 2>/dev/null || true
  dc_log "staged logs in ${stage}"
  printf '%s' "${stage}"
}

# ---------------------------------------------------------------------------
# Hook entrypoint (cross-OS)
# ---------------------------------------------------------------------------

# dc_hook_script <connector> — installed Bash hook path for unix. The claude
# connector's script is named claude-code-hook.sh; everything else follows
# <connector>-hook.sh (see internal/gateway/connector/hooks/ + cmd_setup.py).
dc_hook_script() {
  local connector="$1" base
  case "${connector}" in
    claudecode) base="claude-code-hook.sh" ;;
    *)          base="${connector}-hook.sh" ;;
  esac
  printf '%s/hooks/%s' "${DEFENSECLAW_HOME}" "${base}"
}

# dc_invoke_hook <connector> <event> <payload_file> — feed a golden event
# payload into the installed hook entrypoint and echo "exit:<code>" on the
# last line so callers can assert verdict shaping. On Windows this targets the
# native no-console `defenseclaw-hook hook` subcommand instead of the Bash script.
#
# Stdout of the hook (the agent-native decision JSON) is forwarded verbatim
# before the trailing exit line.
dc_invoke_hook() {
  local connector="$1" event="$2" payload="$3" code out
  if dc_is_windows; then
    out="$(defenseclaw-hook hook --connector "${connector}" --event "${event}" < "${payload}" 2>&1)" && code=0 || code=$?
  else
    local script; script="$(dc_hook_script "${connector}")"
    if [ ! -x "${script}" ]; then
      dc_err "hook script not found/executable: ${script}"
      printf 'exit:127\n'
      return 0
    fi
    out="$(bash "${script}" < "${payload}" 2>&1)" && code=0 || code=$?
  fi
  printf '%s\n' "${out}"
  printf 'exit:%s\n' "${code}"
}
