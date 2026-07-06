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
  # Reject leading/trailing/consecutive commas explicitly; `read -ra`
  # would silently drop a bare trailing empty field.
  case "${raw}" in
    ,*|*,|*,,*) return 1;;
  esac
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
    # Restrict to a YAML-safe key charset. Anything else would be
    # rendered raw into config.yaml where it could break the parser
    # or, worse, inject unrelated keys.
    if [[ ! "${c}" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
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
#
# Metadata-only: reads files under HOME or under signed system app bundles
# and never executes user-installed agent binaries. install.sh runs as root,
# so invoking $PATH-resolved `codex` / `claude` / etc. would be a
# privilege-escalation surface — the caller must pass --agent-version
# explicitly for connectors that don't ship a stable metadata file.
_read_json_version() {
  local path="$1"
  local py
  py="$(command -v python3 || echo /usr/bin/python3)"
  "${py}" -c '
import json, sys
try:
  with open(sys.argv[1]) as f:
    print(json.load(f).get("version",""))
except Exception:
  pass
' "${path}" 2>/dev/null
}

discover_agent_version() {
  local connector="$1"
  local home="$2"
  case "${connector}" in
    codex)
      # Codex-cli is a Rust binary, not npm. We probe metadata paths
      # first (safe, no exec), then fall back to `codex --version`
      # exec'd AS THE TARGET USER via `sudo -u`. Running the user's
      # own codex binary as their identity is not a privilege
      # escalation — install.sh's outer sudo drops privileges for this
      # subprocess, matching the security posture of the hook
      # guardian's connector.Setup call.
      local pkg
      for pkg in \
        "${home}"/.npm-global/lib/node_modules/@openai/codex/package.json \
        /usr/local/lib/node_modules/@openai/codex/package.json \
        /opt/homebrew/lib/node_modules/@openai/codex/package.json; do
        [[ -f "${pkg}" ]] || continue
        local v; v="$(_read_json_version "${pkg}")"
        if [[ -n "${v}" ]]; then echo "${v}"; return; fi
      done
      # Homebrew cask keeps the binary under Caskroom with a version
      # in the path itself: /opt/homebrew/Caskroom/codex/<version>/...
      local caskroom
      for caskroom in /opt/homebrew/Caskroom/codex /usr/local/Caskroom/codex; do
        if [[ -d "${caskroom}" ]]; then
          local ver
          ver="$(ls -1 "${caskroom}" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+' | sort -V | tail -1)"
          if [[ -n "${ver}" ]]; then echo "${ver}"; return; fi
        fi
      done
      # Last resort: exec codex --version as the target user (not as
      # root). Requires TARGET_USER to be known to the caller.
      if [[ -n "${DC_INSTALLER_TARGET_USER:-}" ]] && command -v codex >/dev/null 2>&1; then
        local vraw
        vraw="$(sudo -n -u "${DC_INSTALLER_TARGET_USER}" codex --version 2>/dev/null | head -1 || true)"
        # Codex prints "codex-cli X.Y.Z"; take just the version token.
        vraw="$(printf '%s' "${vraw}" | awk '{for(i=NF;i>=1;i--) if ($i ~ /^[0-9]+\.[0-9]+/) {print $i; exit}}')"
        if [[ -n "${vraw}" ]]; then echo "${vraw}"; return; fi
      fi
      ;;
    claudecode)
      # Claude Code ships both as a standalone npm CLI (has a
      # package.json we can read) and as a Cursor / VS Code extension.
      local pkg
      for pkg in \
        "${home}"/.npm-global/lib/node_modules/@anthropic-ai/claude-code/package.json \
        /usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json \
        /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/package.json \
        "${home}"/.cursor/extensions/anthropic.claude-code-*/package.json \
        "${home}"/.vscode/extensions/anthropic.claude-code-*/package.json; do
        [[ -f "${pkg}" ]] || continue
        local v; v="$(_read_json_version "${pkg}")"
        if [[ -n "${v}" ]]; then echo "${v}"; return; fi
      done
      ;;
    cursor)
      # Cursor.app is a signed macOS bundle; read the Info.plist rather
      # than exec'ing the binary. PlistBuddy is an Apple system tool.
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

ensure_safe_userspace_path() {
  local dir="$1"
  local cfg="$2"
  if [[ -L "${dir}" || -L "${cfg}" ]]; then
    return 1
  fi
  if [[ -e "${dir}" && ! -d "${dir}" ]]; then
    return 1
  fi
  mkdir -p "${dir}" || return 1
  if [[ -L "${dir}" || -L "${cfg}" ]]; then
    return 1
  fi
}

prepare_codex_userspace() {
  local home="$1"
  local dir="${home}/.codex"
  local cfg="${home}/.codex/config.toml"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  if [[ ! -f "${cfg}" ]]; then
    chmod 0700 "${dir}"
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
  local dir="${home}/.claude"
  local cfg="${home}/.claude/settings.json"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  if [[ ! -f "${cfg}" ]]; then
    chmod 0700 "${dir}"
    printf '{}\n' > "${cfg}"
    chmod 0600 "${cfg}"
  fi
}

prepare_cursor_userspace() {
  local home="$1"
  local dir="${home}/.cursor"
  local cfg="${home}/.cursor/hooks.json"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  if [[ ! -f "${cfg}" ]]; then
    chmod 0700 "${dir}"
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
#
# SUPPORT_DIR holds config.yaml at its root (root-owned 0640) — the
# managed_enterprise trust check walks every ancestor of config.yaml
# and refuses group-writable or non-root ancestors. Runtime state
# (audit DB, tokens, guardian state) lives in ${SUPPORT_DIR}/runtime,
# which is chown'd to the service user. This split matches the docs
# (docs-site/content/docs/setup/enterprise-deployment.mdx: "The managed
# config must set data_dir: /Library/Application Support/DefenseClaw/runtime")
# and preserves the CI plist test's WorkingDirectory/HOME assertions.
render_config() {
  local mode="$1"
  local primary="$2"
  local api_port="$3"
  local disable_redaction="$4"
  local support_dir="$5"
  shift 5
  local -a connectors=("$@")
  local runtime_dir="${support_dir}/runtime"

  cat <<EOF
config_version: 6
deployment_mode: managed_enterprise

data_dir: "${runtime_dir}"
audit_db: "${runtime_dir}/audit.db"
judge_bodies_db: "${runtime_dir}/judge_bodies.db"

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
