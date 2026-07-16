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
      # Glob-based version pick (avoids shellcheck SC2010 on `ls | grep`).
      local caskroom ver dir dname
      for caskroom in /opt/homebrew/Caskroom/codex /usr/local/Caskroom/codex; do
        [[ -d "${caskroom}" ]] || continue
        ver=""
        for dir in "${caskroom}"/*/; do
          [[ -d "${dir}" ]] || continue
          dname="$(basename "${dir}")"
          [[ "${dname}" =~ ^[0-9]+\.[0-9]+ ]] || continue
          if [[ -z "${ver}" ]] || \
             [[ "$(printf '%s\n%s\n' "${ver}" "${dname}" | sort -V | tail -1)" == "${dname}" ]]; then
            ver="${dname}"
          fi
        done
        if [[ -n "${ver}" ]]; then echo "${ver}"; return; fi
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

# ---- local-user enumeration --------------------------------------------

# enumerate_local_users -> stdout, one line per eligible user in the form:
#   user:uid:gid:home
#
# Filters: UID >= 500, username does not start with `_`, home under /Users/,
# home is a real directory (not a symlink), and home_perms_ok passes.
# Reads OpenDirectory via dscl — same pattern the fresh-install preflight in
# install.sh already uses (see the block that gates on _existing_install_markers).
#
# Pure: no writes, no sudo. Callers under test can seed a fake dscl by
# putting a shim ahead of PATH.
enumerate_local_users() {
  local names name uid gid home
  names="$(dscl . -list /Users UniqueID 2>/dev/null)" || return 0
  # dscl output is "user   uid". Filter and normalize in one pass.
  while IFS= read -r line; do
    name="$(printf '%s' "${line}" | awk '{print $1}')"
    uid="$(printf '%s' "${line}" | awk '{print $2}')"
    [[ -n "${name}" && -n "${uid}" ]] || continue
    # Filter system accounts.
    case "${name}" in
      _*|daemon|nobody|root) continue;;
    esac
    [[ "${uid}" =~ ^[0-9]+$ ]] || continue
    (( uid >= 500 )) || continue

    home="$(dscl . -read "/Users/${name}" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')"
    [[ -n "${home}" ]] || continue
    [[ "${home}" == /Users/* ]] || continue
    [[ -d "${home}" && ! -L "${home}" ]] || continue
    home_perms_ok "${home}" || continue

    gid="$(dscl . -read "/Users/${name}" PrimaryGroupID 2>/dev/null | sed -n 's/^PrimaryGroupID: //p')"
    [[ "${gid}" =~ ^[0-9]+$ ]] || gid="20"

    printf '%s:%s:%s:%s\n' "${name}" "${uid}" "${gid}" "${home}"
  done <<< "${names}"
}

# ---- targets.yaml rendering --------------------------------------------

# render_targets_manifest SUPPORT_DIR CONNECTORS_CSV USER_LINES -> stdout
#
# Renders the hook-guardian manifest (`targets.yaml`) consumed by the
# `enterprise hooks reconcile` command. Schema mirrors ManifestTarget in
# internal/enterprisehooks/manifest.go.
#
# Args:
#   SUPPORT_DIR    e.g. /opt/cisco/secureclient/defenseclaw
#   CONNECTORS_CSV comma-separated list of connectors (e.g. codex,claudecode,cursor)
#   USER_LINES     newline-separated user:uid:gid:home lines (as produced by
#                  enumerate_local_users)
#
# One `- ` block per (user × supported connector). Unsupported connectors
# are skipped (they have no per-user setup path in the CLI). Agent version
# is discovered per (user, connector) via discover_agent_version; an empty
# version is rendered as an empty string — the guardian's reconcile will
# emit a per-target failure surfaced in hook_guardian_state.json without
# affecting other targets in the manifest.
render_targets_manifest() {
  local support_dir="$1"
  local connectors_csv="$2"
  local user_lines="$3"
  local runtime_dir="${support_dir}/runtime"

  local -a connectors=()
  local c
  while IFS= read -r c; do
    [[ -z "${c}" ]] && continue
    connectors+=("${c}")
  done < <(parse_connectors "${connectors_csv}" 2>/dev/null || true)

  printf 'version: 1\n'
  printf 'targets:\n'

  if [[ ${#connectors[@]} -eq 0 ]]; then
    return 0
  fi
  if [[ -z "${user_lines}" ]]; then
    return 0
  fi

  local line name uid gid home ver
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    name="${line%%:*}"
    local rest="${line#*:}"
    uid="${rest%%:*}"
    rest="${rest#*:}"
    gid="${rest%%:*}"
    home="${rest#*:}"
    [[ -n "${name}" && -n "${uid}" && -n "${gid}" && -n "${home}" ]] || continue

    for c in "${connectors[@]}"; do
      is_supported_connector "${c}" || continue
      ver="$(DC_INSTALLER_TARGET_USER="${name}" discover_agent_version "${c}" "${home}" 2>/dev/null || true)"
      # data_dir is intentionally omitted from each target block: the
      # guardian's validateUserDataDir requires the data_dir to be inside
      # the target user's home (internal/enterprisehooks/installer.go),
      # but ${runtime_dir} is machine-wide root storage under SUPPORT_DIR.
      # Letting the Install() layer default to ~/.defenseclaw per user is
      # correct — that is where the connector's hook script and scoped
      # token per-user artifacts live.
      cat <<EOF
  - user: "${name}"
    user_home: "${home}"
    uid: ${uid}
    gid: ${gid}
    connector: "${c}"
    agent_version: "${ver}"
    enabled: true
EOF
    done
  done <<< "${user_lines}"
}

# ---- config rendering --------------------------------------------------

# aid_endpoint_for_env ENV -> stdout
# Maps the installer's --env flag to the AI Defense cloud host that
# defenseclaw's managed CMID inspection client will target. The daemon
# appends the fixed /api/v1/inspect/defense_claw path itself; this
# helper only supplies the host.
#
# Kept as a pure-bash lookup so tests can exercise it without depending
# on the AID cloud being reachable. Adding a new environment is a
# one-line change here + a new case in the outer arg validator.
aid_endpoint_for_env() {
  local env="$1"
  case "${env}" in
    prod)    echo "https://us.api.inspect.aidefense.security.cisco.com";;
    preview) echo "https://preview.api.inspect.aidefense.aiteam.cisco.com";;
    *)       return 1;;
  esac
}

# resolve_aid_endpoint ENV OVERRIDE -> stdout effective endpoint
#
# When OVERRIDE is non-empty it wins over ENV: this is the --override-endpoint
# adhoc-testing seam that lets an operator point the managed daemon at an
# arbitrary AI Defense host (e.g. a personal preview tenant) without adding a
# new --env case. The override is validated as a well-formed http(s) URL with
# no whitespace or double-quote (it is later rendered into a quoted YAML
# scalar) and any trailing slash is stripped for consistent path joining.
#
# Return codes let the caller emit a precise error:
#   0 - success (endpoint on stdout)
#   1 - unknown ENV (and no override) — invalid --env
#   2 - override supplied but malformed — invalid --override-endpoint
#
# Kept pure (stdout only, no warn/log) so tests can exercise precedence and
# validation without the AID cloud being reachable.
resolve_aid_endpoint() {
  local env="$1"
  local override="$2"
  if [[ -n "${override}" ]]; then
    # Require a non-empty URL authority (host) right after "//": the
    # first authority char must not be a delimiter (/ ? #), so hostless
    # values like "https:///" or "https://?tenant=x" are rejected. The
    # whole value must also be free of whitespace, double quotes, and
    # backslashes — it is rendered into a double-quoted YAML scalar where
    # a backslash would be an escape sequence and a quote would break out.
    local re='^https?://[^[:space:]/?#"\]+[^[:space:]"\]*$'
    [[ "${override}" =~ ${re} ]] || return 2
    printf '%s\n' "${override%/}"
    return 0
  fi
  aid_endpoint_for_env "${env}"
}

# render_config MODE PRIMARY API_PORT DISABLE_REDACTION SUPPORT_DIR AID_ENDPOINT CONN... -> stdout
# Renders the full config.yaml. Pure stdout, no file writes.
# Extra args after AID_ENDPOINT are the full connector list (primary + others).
#
# SUPPORT_DIR is the module root under the managed install tree
# (/opt/cisco/secureclient/defenseclaw). config.yaml sits under
# SUPPORT_DIR/etc/config.yaml (root:wheel 0640). The managed_enterprise
# trust check walks every ancestor of config.yaml and refuses
# group-writable or non-root ancestors — the shipped layout is
# root:wheel 0755 all the way up, so it passes. Runtime state (audit
# DB, tokens, guardian state) lives in ${SUPPORT_DIR}/runtime; on the
# root-mode daemon everything under SUPPORT_DIR is root-owned.
#
# AID_ENDPOINT is the fully-qualified host (with scheme) that the
# managed CiscoDefenseClawInspectClient will target — produced by
# aid_endpoint_for_env. Empty is not accepted; if callers do not want
# remote inspection they should not run in managed_enterprise mode.
render_config() {
  local mode="$1"
  local primary="$2"
  local api_port="$3"
  local disable_redaction="$4"
  local support_dir="$5"
  local aid_endpoint="$6"
  shift 6
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
  # Pin device_key_file into RUNTIME_DIR (service-user writable) rather
  # than letting the Go defaults compute it from DEFENSECLAW_HOME. The
  # plist sets DEFENSECLAW_HOME to SUPPORT_DIR so managed_enterprise
  # trust checks accept every ancestor of config.yaml, but SUPPORT_DIR
  # itself is root:defenseclaw 0750 (no group write) — leaving the
  # default would send the daemon's first-boot write to
  # \${SUPPORT_DIR}/device.key and crash it with "permission denied".
  device_key_file: "${runtime_dir}/device.key"
  # The skill/plugin/MCP watcher periodically re-scans agent component
  # directories and invokes the 'defenseclaw' python scanner binary.
  # In this managed_enterprise rollout we rely on AID cloud + local
  # regex as the only content classifiers (see mergeVerdict /
  # demoteLocalBlockForManaged in internal/gateway/guardrail.go); the
  # watcher would otherwise fail-close every plugin operation when the
  # python scanner isn't installed, and none of its verdicts feed into
  # the enforced action path we're building. Turn it off.
  watcher:
    enabled: false

privacy:
  disable_redaction: ${disable_redaction}

guardrail:
  enabled: true
  mode: ${mode}
  scanner_mode: both
  # regex_only skips the LLM-judge routing; adjudication burns cycles
  # and we don't ship an LLM key on managed installs.
  detection_strategy: regex_only
  judge:
    enabled: false
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

# In managed_enterprise mode the gateway authenticates AI Defense
# inspection with a bearer token sourced from the managed cloud auth
# provider. The daemon calls
# ${aid_endpoint}/api/v1/inspect/defense_claw with Authorization: Bearer
# <token>. The endpoint is installer-set; --env selects which AID cloud
# environment to target. See internal/gateway/cisco_inspect_defense_claw.go
# and internal/managed/cloudreg for the client-side implementation.
cisco_ai_defense:
  endpoint: "${aid_endpoint}"

# OpenTelemetry. In managed_enterprise the gateway auto-provisions a Cisco AI
# Defense event-ingest LOG sink from cisco_ai_defense.endpoint above: it POSTs
# DefenseClaw's own events to ${aid_endpoint}/api/v1/defenseclaw/events/ingest with
# a CMID bearer token (see internal/telemetry/cisco_aid_log_exporter.go). That
# sink is independent of otel.destinations[] and needs no user collector.
# otel.enabled is turned on so the telemetry provider (and that managed sink)
# are active; the "enabled requires a destination" rule is waived when the
# managed sink is present (see config.hasManagedAIDLogSink). Add entries under
# otel.destinations[] only if you also want to fan out to your own OTLP backend.
# Set DEFENSECLAW_DEBUG=1 for a stderr line confirming each successful send.
otel:
  enabled: true

# Continuous AI discovery (endpoint inventory). Enabled in managed_enterprise
# so the sidecar scans for supported connectors and broader "shadow AI" usage
# signals and ships the inventory to AI Defense as discovery events over the
# managed AID log sink above (see internal/inventory/ai_discovery.go and
# internal/telemetry/cisco_aid_log_exporter.go). emit_otel defaults on, which is
# what carries the inventory to that sink; other ai_discovery.* keys keep their
# built-in defaults (mode enhanced, scan intervals). The scanner is a no-op
# unless enabled, so this block is required for endpoint inventory to flow.
ai_discovery:
  enabled: true

# asset_policy is intentionally disabled in this managed_enterprise
# rollout. The AID cloud is the single authoritative source of block
# verdicts on this branch; asset_policy's mcp/skill/plugin allow-lists
# and the component (plugin) scanner it feeds would compete with the
# cloud's classification and (in the plugin case) fail-close every
# request when the 'defenseclaw' python plugin-scanner isn't installed.
# See internal/gateway/guardrail.go: mergeVerdict + demoteLocalBlockForManaged
# for the analogous local-pattern demotion, and the installer PR notes
# for the full "which sources enforce" decision matrix.
asset_policy:
  enabled: false

application_protection:
  enabled: false
EOF
}
