#!/usr/bin/env bash
#
# DefenseClaw macOS installer — pure-function helpers.
#
# This library contains the side-effect-free pieces of install.sh so they
# can be unit-tested without touching /Library, sudo, or the LaunchDaemon.
# install.sh sources this file. tests/ also sources it.
#
# Functions in this file MUST NOT:
#   - call sudo, chown, chmod, install(8), launchctl
#   - write outside paths the caller passed in
#   - depend on globals other than what the caller exports
#
# They DO:
#   - parse strings, render YAML, run pure file I/O against caller-owned
#     paths (e.g. a tmpdir under /tmp/dctest-XXXX).

# ---- connector list parsing --------------------------------------------

# parse_connectors LIST -> echoes one normalized connector per line.
# Splits on comma, trims whitespace, lowercases. Empty entries are an
# error (caller's job to die() on non-zero return).
parse_connectors() {
  local raw="$1"
  if [[ -z "${raw}" ]]; then
    return 1
  fi
  local -a out=()
  local IFS=','
  read -ra out <<< "${raw}"
  local c
  # Guard for bash 3.2: ${array[@]} on an empty array under `set -u`
  # would trip an "unbound variable" error.
  if [[ ${#out[@]} -eq 0 ]]; then
    return 1
  fi
  for c in "${out[@]}"; do
    c="$(printf '%s' "${c}" | tr '[:upper:]' '[:lower:]' | awk '{$1=$1};1')"
    if [[ -z "${c}" ]]; then
      return 1
    fi
    printf '%s\n' "${c}"
  done
}

# is_supported_connector NAME -> exit 0 if name is auto-wireable.
is_supported_connector() {
  case "$1" in
    codex|claudecode|cursor) return 0;;
    *) return 1;;
  esac
}

# ---- home perms ---------------------------------------------------------

# home_perms_ok PATH -> exit 0 iff path has no group/other write bits.
# Mirrors validateUserHome() in internal/enterprisehooks/installer.go.
home_perms_ok() {
  local home="$1"
  local mode
  mode="$(stat -f '%Lp' "${home}" 2>/dev/null || stat -c '%a' "${home}" 2>/dev/null || echo "")"
  [[ -z "${mode}" ]] && return 0
  (( (8#${mode} & 8#022) == 0 ))
}

# ---- agent version discovery -------------------------------------------

# discover_agent_version CONNECTOR HOME -> echoes the agent version or "".
# Reads HOME-relative files; never executes installed agents under sudo.
discover_agent_version() {
  local connector="$1"
  local home="$2"
  case "${connector}" in
    codex)
      if command -v codex >/dev/null 2>&1; then
        codex --version 2>/dev/null | head -1 || true
      fi
      ;;
    claudecode)
      if command -v claude >/dev/null 2>&1; then
        local v
        v="$(claude --version 2>/dev/null | head -1 || true)"
        if [[ -n "${v}" ]]; then echo "${v}"; return; fi
      fi
      local ext_pkg
      for ext_pkg in \
        "${home}"/.cursor/extensions/anthropic.claude-code-*/package.json \
        "${home}"/.vscode/extensions/anthropic.claude-code-*/package.json; do
        [[ -f "${ext_pkg}" ]] || continue
        /usr/bin/python3 -c '
import json, sys
try:
  with open(sys.argv[1]) as f:
    print(json.load(f).get("version",""))
except Exception:
  pass
' "${ext_pkg}" 2>/dev/null && return
      done
      ;;
    cursor)
      if [[ -f /Applications/Cursor.app/Contents/Info.plist ]]; then
        /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" \
          /Applications/Cursor.app/Contents/Info.plist 2>/dev/null || true
      fi
      ;;
  esac
}

# ---- per-connector userspace prep --------------------------------------
#
# Each prepare_* writes the connector's native hook config file under HOME
# if missing. They do NOT chown — the caller is expected to be running as
# the target user (the test harness) or as root with a follow-up chown
# (the real installer). They use install(8)/chmod for parents and writes.

prepare_codex_userspace() {
  local home="$1"
  local cfg="${home}/.codex/config.toml"
  if [[ ! -f "${cfg}" ]]; then
    mkdir -p "${home}/.codex"
    chmod 0700 "${home}/.codex"
    cat > "${cfg}" <<'TOML'
# Created by DefenseClaw installer so the enterprise hook guardian can
# repair this file. Edit freely; DefenseClaw only owns [hooks], [otel],
# and the top-level notify entries.
TOML
    chmod 0600 "${cfg}"
  fi
}

prepare_claudecode_userspace() {
  local home="$1"
  local cfg="${home}/.claude/settings.json"
  if [[ ! -f "${cfg}" ]]; then
    mkdir -p "${home}/.claude"
    chmod 0700 "${home}/.claude"
    printf '{}\n' > "${cfg}"
    chmod 0600 "${cfg}"
  fi
}

prepare_cursor_userspace() {
  local home="$1"
  local cfg="${home}/.cursor/hooks.json"
  if [[ ! -f "${cfg}" ]]; then
    mkdir -p "${home}/.cursor"
    chmod 0700 "${home}/.cursor"
    printf '{"version":1,"hooks":{}}\n' > "${cfg}"
    chmod 0600 "${cfg}"
  fi
}

prepare_userspace_for() {
  local connector="$1"
  local home="$2"
  case "${connector}" in
    codex)      prepare_codex_userspace      "${home}";;
    claudecode) prepare_claudecode_userspace "${home}";;
    cursor)     prepare_cursor_userspace     "${home}";;
  esac
}

# ---- config rendering --------------------------------------------------

# render_config MODE PRIMARY API_PORT DISABLE_REDACTION SUPPORT_DIR CONN... -> stdout
# Renders the full config.yaml. Pure stdout, no file writes.
# Extra args after SUPPORT_DIR are the full connector list (primary + others).
render_config() {
  local mode="$1"
  local primary="$2"
  local api_port="$3"
  local disable_redaction="$4"
  local support_dir="$5"
  shift 5
  local -a connectors=("$@")

  cat <<EOF
config_version: 6
deployment_mode: managed_enterprise

data_dir: "${support_dir}"
audit_db: "${support_dir}/audit.db"
judge_bodies_db: "${support_dir}/judge_bodies.db"

gateway:
  api_bind: 127.0.0.1
  api_port: ${api_port}

privacy:
  disable_redaction: ${disable_redaction}

guardrail:
  enabled: true
  mode: ${mode}
  scanner_mode: both
  connector: ${primary}
EOF

  if (( ${#connectors[@]} > 1 )); then
    echo "  connectors:"
    local c
    for c in "${connectors[@]}"; do
      cat <<EOF
    ${c}:
      enabled: true
      mode: ${mode}
EOF
    done
  fi

  cat <<EOF

asset_policy:
  enabled: true
  mode: ${mode}
  mcp:
    default: deny
    registry_required: false
  skill:
    default: allow
  plugin:
    default: allow

application_protection:
  enabled: false
EOF
}
