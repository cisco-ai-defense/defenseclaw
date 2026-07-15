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
# Safety helpers for upgrade-regression.sh. This library deliberately manages
# individual files only: it never recursively copies, replaces, or deletes an
# agent auth directory or the user's real ~/.defenseclaw directory.

DC_PERSIST_SNAPSHOT_INDEX=""
DC_PERSIST_SNAPSHOT_DIR=""
DC_PERSIST_WS_PORT="${DC_PERSIST_WS_PORT:-}"
DC_PERSIST_API_PORT="${DC_PERSIST_API_PORT:-}"
DC_PERSIST_SCANNER_PORT="${DC_PERSIST_SCANNER_PORT:-}"

# dc_persist_realpath <path> — portable macOS/Linux canonical path helper.
dc_persist_realpath() {
  if command -v realpath >/dev/null 2>&1; then
    realpath "$1"
  else
    python3 - "$1" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
  fi
}

# dc_persist_safe_scratch <path> — require a harness-owned scratch location.
# This guard is used before any recursive cleanup.
dc_persist_safe_scratch() {
  local path resolved base
  path="${1:-}"
  [ -n "${path}" ] || return 1
  resolved="$(dc_persist_realpath "${path}" 2>/dev/null)" || return 1
  base="$(basename "${resolved}")"
  case "${base}" in
    dc-connector-upgrade.*) ;;
    *) return 1 ;;
  esac
  case "${resolved}" in
    "${HOME}"|"${HOME}/.defenseclaw"|"${HOME}/.codex"|"${HOME}/.claude"|"${HOME}/.gemini") return 1 ;;
  esac
  [ -d "${resolved}" ]
}

# dc_persist_cleanup_scratch <path> — remove only a validated run scratch
# tree. find -delete avoids an unbounded recursive-remove command and the
# basename/realpath checks above prevent auth/home paths from entering it.
dc_persist_cleanup_scratch() {
  local path="$1"
  dc_persist_safe_scratch "${path}" || {
    dc_err "refusing unsafe scratch cleanup: ${path}"
    return 1
  }
  find "${path}" -depth -delete
}

dc_persist_snapshot_init() {
  local dir="$1"
  [ -n "${dir}" ] || return 1
  mkdir -p "${dir}/files"
  chmod 700 "${dir}" "${dir}/files"
  DC_PERSIST_SNAPSHOT_DIR="${dir}"
  DC_PERSIST_SNAPSHOT_INDEX="${dir}/index.tsv"
  : > "${DC_PERSIST_SNAPSHOT_INDEX}"
  chmod 600 "${DC_PERSIST_SNAPSHOT_INDEX}"
}

# dc_persist_snapshot_file <absolute-path> — capture existence, bytes,
# permissions, timestamps, ACLs, and xattrs (where cp -p supports them).
# Symlinks and non-regular files are rejected so restore cannot be redirected.
dc_persist_snapshot_file() {
  local path="$1" count backup
  case "${path}" in
    /*) ;;
    *) dc_err "snapshot path must be absolute: ${path}"; return 1 ;;
  esac
  if [ -L "${path}" ]; then
    dc_err "refusing to snapshot symlinked config: ${path}"
    return 1
  fi
  count="$(wc -l < "${DC_PERSIST_SNAPSHOT_INDEX}" | tr -d ' ')"
  backup="${DC_PERSIST_SNAPSHOT_DIR}/files/${count}.snapshot"
  if [ -e "${path}" ]; then
    if [ ! -f "${path}" ]; then
      dc_err "refusing to snapshot non-regular config: ${path}"
      return 1
    fi
    /bin/cp -p "${path}" "${backup}"
    printf 'present\t%s\t%s\n' "${path}" "${backup}" >> "${DC_PERSIST_SNAPSHOT_INDEX}"
  else
    printf 'absent\t%s\t-\n' "${path}" >> "${DC_PERSIST_SNAPSHOT_INDEX}"
  fi
}

# dc_persist_restore_files — restore in reverse order. Existing symlinks and
# non-regular replacements cause a hard failure. Files absent at snapshot time
# are removed only when they are regular files created at the exact path; no
# parent directory is ever removed.
dc_persist_restore_files() {
  local reverse state path backup parent tmp rc=0
  [ -f "${DC_PERSIST_SNAPSHOT_INDEX}" ] || return 0
  reverse="${DC_PERSIST_SNAPSHOT_DIR}/restore.tsv"
  awk '{ line[NR]=$0 } END { for (i=NR; i>0; i--) print line[i] }' \
    "${DC_PERSIST_SNAPSHOT_INDEX}" > "${reverse}"
  while IFS=$'\t' read -r state path backup; do
    [ -n "${path}" ] || continue
    if [ -L "${path}" ]; then
      dc_err "restore blocked by symlink at ${path}"
      rc=1
      continue
    fi
    case "${state}" in
      present)
        if [ -e "${path}" ] && [ ! -f "${path}" ]; then
          dc_err "restore blocked by non-regular file at ${path}"
          rc=1
          continue
        fi
        parent="$(dirname "${path}")"
        mkdir -p "${parent}"
        tmp="${parent}/.dc-upgrade-restore.$$"
        if /bin/cp -p "${backup}" "${tmp}" && /bin/mv -f "${tmp}" "${path}"; then
          :
        else
          /bin/rm -f "${tmp}" 2>/dev/null || true
          dc_err "failed to restore ${path}"
          rc=1
        fi
        ;;
      absent)
        if [ -e "${path}" ]; then
          if [ -f "${path}" ]; then
            /bin/rm -f "${path}" || rc=1
          else
            dc_err "refusing to remove non-regular path created at ${path}"
            rc=1
          fi
        fi
        ;;
      *)
        dc_err "invalid snapshot state ${state} for ${path}"
        rc=1
        ;;
    esac
  done < "${reverse}"
  return "${rc}"
}

# dc_persist_acquire_lock <lock-dir> — one mutating connector run per user.
# Stale locks are removed only when their recorded PID is no longer alive.
dc_persist_acquire_lock() {
  local lock_dir="$1" stale_pid=""
  if mkdir "${lock_dir}" 2>/dev/null; then
    printf '%s\n' "$$" > "${lock_dir}/pid"
    return 0
  fi
  if [ -f "${lock_dir}/pid" ]; then
    IFS= read -r stale_pid < "${lock_dir}/pid" || stale_pid=""
  fi
  case "${stale_pid}" in
    ''|*[!0-9]*) ;;
    *)
      if kill -0 "${stale_pid}" 2>/dev/null; then
        dc_err "another connector upgrade harness is active (pid ${stale_pid})"
        return 1
      fi
      ;;
  esac
  /bin/rm -f "${lock_dir}/pid" 2>/dev/null || return 1
  rmdir "${lock_dir}" 2>/dev/null || return 1
  mkdir "${lock_dir}" || return 1
  printf '%s\n' "$$" > "${lock_dir}/pid"
}

dc_persist_release_lock() {
  local lock_dir="$1" owner=""
  [ -d "${lock_dir}" ] || return 0
  if [ -f "${lock_dir}/pid" ]; then
    IFS= read -r owner < "${lock_dir}/pid" || owner=""
  fi
  if [ "${owner}" != "$$" ]; then
    dc_err "refusing to release a connector upgrade lock owned by pid ${owner:-unknown}"
    return 1
  fi
  /bin/rm -f "${lock_dir}/pid" 2>/dev/null || true
  rmdir "${lock_dir}" 2>/dev/null || true
}

# dc_persist_cli_python — resolve the interpreter that owns the installed
# defenseclaw entry point so isolated config edits use the same package/runtime.
dc_persist_cli_python() {
  local cli first
  cli="$(command -v defenseclaw 2>/dev/null)" || return 1
  IFS= read -r first < "${cli}" || return 1
  case "${first}" in
    '#!'*)
      first="${first#\#!}"
      [ -x "${first}" ] || return 1
      printf '%s' "${first}"
      ;;
    *) return 1 ;;
  esac
}

# dc_persist_isolate_gateway_config — assign three free loopback ports and
# disable background home scanning/watchers. DEFENSECLAW_HOME must already
# point at the run-owned data directory.
dc_persist_isolate_gateway_config() {
  local py ports
  py="$(dc_persist_cli_python)" || {
    dc_err "could not resolve the Python runtime behind defenseclaw"
    return 1
  }
  if [ -z "${DC_PERSIST_WS_PORT}" ] || \
     [ -z "${DC_PERSIST_API_PORT}" ] || \
     [ -z "${DC_PERSIST_SCANNER_PORT}" ]; then
    ports="$("${py}" - <<'PY'
import socket
sockets = []
try:
    for _ in range(3):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        sockets.append(s)
    print(" ".join(str(s.getsockname()[1]) for s in sockets))
finally:
    for s in sockets:
        s.close()
PY
)" || return 1
    read -r DC_PERSIST_WS_PORT DC_PERSIST_API_PORT DC_PERSIST_SCANNER_PORT <<< "${ports}"
  fi
  "${py}" - "${DC_PERSIST_WS_PORT}" "${DC_PERSIST_API_PORT}" "${DC_PERSIST_SCANNER_PORT}" <<'PY'
import sys
from defenseclaw.config import load

cfg = load()
cfg.gateway.host = "127.0.0.1"
cfg.gateway.port = int(sys.argv[1])
cfg.gateway.api_port = int(sys.argv[2])
cfg.guardrail.host = "127.0.0.1"
cfg.guardrail.port = int(sys.argv[3])
cfg.ai_discovery.enabled = False
if getattr(cfg.gateway, "watcher", None) is not None:
    cfg.gateway.watcher.enabled = False
if getattr(cfg, "watch", None) is not None:
    cfg.watch.rescan_enabled = False
cfg.save()
PY
  dc_log "isolated gateway ports: ws=${DC_PERSIST_WS_PORT} api=${DC_PERSIST_API_PORT} scanner=${DC_PERSIST_SCANNER_PORT}"
}

dc_persist_sha256() {
  local path="$1"
  if [ ! -f "${path}" ]; then
    printf 'absent'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${path}" | awk '{print $1}'
  else
    sha256sum "${path}" | awk '{print $1}'
  fi
}
