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
# _read_json_field PATH FIELD -> echoes the top-level FIELD or "".
#
# Reads a JSON document from PATH and echoes the value of the given
# top-level string field, or empty on any error (missing file,
# unreadable file, malformed JSON, missing field, non-string value).
# Metadata-only: no shell interpolation of the payload, no exec of
# any binary the payload names. The python3 sub-invocation stays
# hard-scoped to json.load + dict.get; the field name is passed as a
# separate argv (not concatenated into the script) so a caller
# feeding a hostile FIELD cannot inject python.
_read_json_field() {
  local path="$1"
  local field="$2"
  local py
  py="$(command -v python3 || echo /usr/bin/python3)"
  "${py}" -c '
import json, sys
try:
  with open(sys.argv[1]) as f:
    v = json.load(f).get(sys.argv[2], "")
  if isinstance(v, str):
    print(v)
except Exception:
  pass
' "${path}" "${field}" 2>/dev/null
}

# _read_json_version PATH -> convenience shim for the .version field.
# Kept as a named helper so the connector-version-discovery code in
# discover_agent_version reads clearly; delegates to _read_json_field
# so we don't grow two copies of the same python3 one-liner.
_read_json_version() {
  _read_json_field "$1" "version"
}

# _native_claudecode_version_from_dir BASE -> echoes the version or "".
#
# Reads Claude Code's native-installer layout under BASE, which looks
# like:
#
#   BASE/
#     current            symlink to versions/<X.Y.Z>
#     versions/
#       <X.Y.Z>/         actual install root
#       <X.Y.Z-1>/       (older, kept for rollback)
#
# Metadata-only (matches the module's security posture — see the doc
# block on discover_agent_version). No binary is exec'd; we readlink
# the `current` pointer and basename it, or fall back to picking the
# highest version-shaped subdir under versions/. BASE typically resolves
# to `${home}/.local/share/claude`, `/opt/claude`, or
# `/usr/local/share/claude`.
_native_claudecode_version_from_dir() {
  local base="$1"
  [[ -n "${base}" && -d "${base}" ]] || return 0
  local current target dname ver
  local -r semver_re='^[0-9]+\.[0-9]+\.[0-9]+([._+-].*)?$'

  # 1. `current` symlink — user's active version.
  #    A user with multiple installed versions may have `claude version
  #    rollback`-ed to an older one; the `current` pointer reflects the
  #    active choice, so it wins over the highest-versions/* fallback.
  #    Only accept a `current` whose target actually resolves — a
  #    dangling symlink (aborted upgrade, manual rm -rf) is treated as
  #    absent and falls through to the versions/*/ scan below.
  current="${base}/current"
  if [[ -L "${current}" && -e "${current}" ]]; then
    target="$(readlink -n "${current}" 2>/dev/null || true)"
    if [[ -n "${target}" ]]; then
      dname="$(basename -- "${target}")"
      if [[ "${dname}" =~ ${semver_re} ]]; then
        echo "${dname}"
        return
      fi
    fi
  fi

  # 2. Highest versions/* dir. Same sort -V idiom used by the codex
  #    Homebrew Caskroom probe. Handles partial installs where the
  #    `current` symlink hasn't been flipped yet, and hosts that
  #    never publish a `current` pointer.
  local versions_dir="${base}/versions" dir
  if [[ -d "${versions_dir}" ]]; then
    ver=""
    for dir in "${versions_dir}"/*/; do
      [[ -d "${dir}" ]] || continue
      dname="$(basename "${dir}")"
      [[ "${dname}" =~ ${semver_re} ]] || continue
      if [[ -z "${ver}" ]] || \
         [[ "$(printf '%s\n%s\n' "${ver}" "${dname}" | sort -V | tail -1)" == "${dname}" ]]; then
        ver="${dname}"
      fi
    done
    if [[ -n "${ver}" ]]; then
      echo "${ver}"
      return
    fi
  fi
}

discover_agent_version() {
  local connector="$1"
  local home="$2"
  case "${connector}" in
    codex)
      # Codex-cli is a Rust binary that ships from three OpenAI-owned
      # channels on macOS. Probe order picks the first-party
      # ChatGPT.app bundled copy FIRST because it is the newest
      # distribution (auto-updated with the desktop app) and it is
      # what customers actually have on a fresh Mac — stray old
      # `npm i -g @openai/codex` installs from an earlier engagement
      # frequently linger and would otherwise win with a stale
      # version that fails our MinAgentVersion contract gate.
      #
      # Order:
      #   1. ChatGPT.app bundled binary       (Codex 0.145.0+ current)
      #   2. Homebrew Caskroom                (versioned dir name)
      #   3. npm module package.json         (user-global then system)
      #   4. `command -v codex` last resort   (arbitrary PATH install)
      #
      # Every probe runs as the target user via sudo -u (not root).
      # The app bundle is Gatekeeper-signed and world-readable by
      # design; running its --version as an unprivileged user is
      # safe. install.sh's outer sudo already dropped privs before
      # calling this helper, matching the security posture of the
      # hook guardian's connector.Setup call.
      local vraw

      # 1. ChatGPT.app bundled codex — /Applications/ChatGPT.app/
      # Contents/Resources/codex is the current stable location; the
      # older MacOS/ path is kept as a fallback for pre-2026 builds.
      local chatgpt_codex
      for chatgpt_codex in \
        /Applications/ChatGPT.app/Contents/Resources/codex \
        /Applications/ChatGPT.app/Contents/MacOS/codex; do
        [[ -x "${chatgpt_codex}" ]] || continue
        if [[ -n "${DC_INSTALLER_TARGET_USER:-}" ]]; then
          vraw="$(sudo -n -u "${DC_INSTALLER_TARGET_USER}" "${chatgpt_codex}" --version 2>/dev/null | head -1 || true)"
        else
          vraw="$("${chatgpt_codex}" --version 2>/dev/null | head -1 || true)"
        fi
        # Codex prints "codex-cli X.Y.Z" (or "codex-cli X.Y.Z-alpha.N");
        # take the first token that looks like a version.
        vraw="$(printf '%s' "${vraw}" | awk '{for(i=NF;i>=1;i--) if ($i ~ /^[0-9]+\.[0-9]+/) {print $i; exit}}')"
        if [[ -n "${vraw}" ]]; then echo "${vraw}"; return; fi
      done

      # 2. Homebrew cask keeps the binary under Caskroom with a
      # version in the path itself:
      #   /opt/homebrew/Caskroom/codex/<version>/...
      # Glob-based version pick (avoids shellcheck SC2010 on ls|grep).
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

      # 3. npm module package.json — user-global first (most likely
      # up to date on developer boxes), then system dirs.
      local pkg
      for pkg in \
        "${home}"/.npm-global/lib/node_modules/@openai/codex/package.json \
        /usr/local/lib/node_modules/@openai/codex/package.json \
        /opt/homebrew/lib/node_modules/@openai/codex/package.json; do
        [[ -f "${pkg}" ]] || continue
        local v; v="$(_read_json_version "${pkg}")"
        if [[ -n "${v}" ]]; then echo "${v}"; return; fi
      done

      # 4. Last resort: exec codex --version as the target user (not
      # as root). Requires TARGET_USER to be known to the caller.
      if [[ -n "${DC_INSTALLER_TARGET_USER:-}" ]] && command -v codex >/dev/null 2>&1; then
        vraw="$(sudo -n -u "${DC_INSTALLER_TARGET_USER}" codex --version 2>/dev/null | head -1 || true)"
        vraw="$(printf '%s' "${vraw}" | awk '{for(i=NF;i>=1;i--) if ($i ~ /^[0-9]+\.[0-9]+/) {print $i; exit}}')"
        if [[ -n "${vraw}" ]]; then echo "${vraw}"; return; fi
      fi
      ;;
    claudecode)
      # Claude Code ships through four channels:
      #
      #   1. Native installer (curl -fsSL https://claude.ai/install.sh
      #      | bash) — per-user under ~/.local/share/claude/versions/
      #      with a `current` symlink pointer. This is the officially
      #      recommended installer and what most users have today; the
      #      `~/.local/bin/claude` shim on PATH resolves through the
      #      `current` symlink to `.../versions/<X.Y.Z>/claude`.
      #   2. System-wide native install — /opt/claude or
      #      /usr/local/share/claude, same {current,versions/*} shape.
      #      Present when an admin installs Claude for all users.
      #   3. npm-global CLI — @anthropic-ai/claude-code — legacy
      #      channel, still supported. package.json carries version.
      #   4. Cursor / VS Code editor extensions — the extension dir
      #      name embeds the version (matches the codex probe pattern).
      #
      # Probe order picks native FIRST because it is what customers
      # actually run today; leaving it for a stale npm-global fallback
      # to win would surface a stale version to the hook-contract
      # validator and (in managed_enterprise mode=action) fail the
      # reconcile for that user's claudecode row.

      # 1. + 2. Native installer layouts. Per-user first, then Linux
      # system-wide paths. `installer_lib.sh` is macOS-only in
      # today's shipping bundle, but the render-targets script is
      # copied into the managed tree and runs against every local
      # user's home; the extra probes cost one stat each on macOS
      # (which does not have /opt/claude) and future-proof against
      # a Linux managed rollout that consumes this helper.
      local base v
      for base in \
        "${home}/.local/share/claude" \
        /opt/claude \
        /usr/local/share/claude; do
        v="$(_native_claudecode_version_from_dir "${base}")"
        if [[ -n "${v}" ]]; then echo "${v}"; return; fi
      done

      # 3. + 4. npm module package.json + editor-extension probes.
      #    Kept intact so operators with a legacy npm install or an
      #    editor-extension install continue to work.
      local pkg
      for pkg in \
        "${home}"/.npm-global/lib/node_modules/@anthropic-ai/claude-code/package.json \
        /usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json \
        /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/package.json \
        "${home}"/.cursor/extensions/anthropic.claude-code-*/package.json \
        "${home}"/.vscode/extensions/anthropic.claude-code-*/package.json; do
        [[ -f "${pkg}" ]] || continue
        v="$(_read_json_version "${pkg}")"
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

# _enumerate_users_warn — internal helper that emits a per-filter drop
# reason when DC_INSTALLER_ENUMERATE_VERBOSE=1. install.sh flips this on
# so its install.log records why user X was excluded from targets.yaml;
# unit tests leave it off so the sourced-library harness stays quiet.
_enumerate_users_warn() {
  [[ "${DC_INSTALLER_ENUMERATE_VERBOSE:-}" == "1" ]] || return 0
  printf '[install] WARN: enumerate_local_users skipping %s: %s\n' "$1" "$2" >&2
}

# enumerate_local_users -> stdout, one line per eligible user in the form:
#   user:uid:gid:home
#
# Filters: UID >= 500, username does not start with `_`, home under /Users/,
# home is a real directory (not a symlink), and home_perms_ok passes.
# Reads OpenDirectory via dscl — same pattern the fresh-install preflight in
# install.sh already uses (see the block that gates on _existing_install_markers).
#
# Pure: no writes, no sudo. When DC_INSTALLER_ENUMERATE_VERBOSE=1 each
# filter drop emits a WARN on stderr so install.log captures why a
# specific user was excluded. Off by default (tests source this library
# and would otherwise emit spurious warns).
enumerate_local_users() {
  local names name uid gid home
  names="$(dscl . -list /Users UniqueID 2>/dev/null)" || {
    _enumerate_users_warn "(all users)" "dscl . -list /Users UniqueID failed — cannot enumerate local users"
    return 0
  }
  # dscl output is "user   uid". Filter and normalize in one pass.
  while IFS= read -r line; do
    name="$(printf '%s' "${line}" | awk '{print $1}')"
    uid="$(printf '%s' "${line}" | awk '{print $2}')"
    if [[ -z "${name}" || -z "${uid}" ]]; then
      _enumerate_users_warn "${name:-?}" "dscl row is missing name or uid: '${line}'"
      continue
    fi
    # Filter system accounts.
    case "${name}" in
      _*|daemon|nobody|root)
        _enumerate_users_warn "${name}" "system account (name matches system-user pattern)"
        continue;;
    esac
    if ! [[ "${uid}" =~ ^[0-9]+$ ]]; then
      _enumerate_users_warn "${name}" "uid '${uid}' is not numeric"
      continue
    fi
    if (( uid < 500 )); then
      _enumerate_users_warn "${name}" "uid ${uid} is below the local-user threshold (500)"
      continue
    fi

    home="$(dscl . -read "/Users/${name}" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')"
    if [[ -z "${home}" ]]; then
      _enumerate_users_warn "${name}" "NFSHomeDirectory is empty in Open Directory"
      continue
    fi
    if [[ "${home}" != /Users/* ]]; then
      _enumerate_users_warn "${name}" "home '${home}' is not under /Users/ (network / mobile / MDM account)"
      continue
    fi
    if [[ ! -d "${home}" ]]; then
      _enumerate_users_warn "${name}" "home '${home}' is not a directory (may not be mounted)"
      continue
    fi
    if [[ -L "${home}" ]]; then
      _enumerate_users_warn "${name}" "home '${home}' is a symlink — refusing to follow"
      continue
    fi
    if ! home_perms_ok "${home}"; then
      local _mode
      _mode="$(stat -f '%Lp' "${home}" 2>/dev/null || stat -c '%a' "${home}" 2>/dev/null || echo '?')"
      _enumerate_users_warn "${name}" "home '${home}' is group/other writable (mode ${_mode}) — hook guardian will refuse"
      continue
    fi

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
yaml_double_quoted_scalar() {
  local value="$1"
  case "${value}" in
    *$'\n'*|*$'\r'*|*$'\t'*) return 1;;
  esac
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "${value}"
}

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

  local line name uid gid home ver q_name q_home q_connector q_ver
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    name="${line%%:*}"
    local rest="${line#*:}"
    uid="${rest%%:*}"
    rest="${rest#*:}"
    gid="${rest%%:*}"
    home="${rest#*:}"
    [[ -n "${name}" && -n "${uid}" && -n "${gid}" && -n "${home}" ]] || continue
    q_name="$(yaml_double_quoted_scalar "${name}")" || continue
    q_home="$(yaml_double_quoted_scalar "${home}")" || continue

    for c in "${connectors[@]}"; do
      is_supported_connector "${c}" || continue
      q_connector="$(yaml_double_quoted_scalar "${c}")" || continue
      ver="$(DC_INSTALLER_TARGET_USER="${name}" discover_agent_version "${c}" "${home}" 2>/dev/null || true)"
      q_ver="$(yaml_double_quoted_scalar "${ver}")" || q_ver='""'
      # data_dir is intentionally omitted from each target block: the
      # guardian's validateUserDataDir requires the data_dir to be inside
      # the target user's home (internal/enterprisehooks/installer.go),
      # but ${runtime_dir} is machine-wide root storage under SUPPORT_DIR.
      # Letting the Install() layer default to ~/.defenseclaw per user is
      # correct — that is where the connector's hook script and scoped
      # token per-user artifacts live.
      cat <<EOF
  - user: ${q_name}
    user_home: ${q_home}
    uid: ${uid}
    gid: ${gid}
    connector: ${q_connector}
    agent_version: ${q_ver}
    enabled: true
EOF
    done
  done <<< "${user_lines}"
}

# ---- config rendering --------------------------------------------------

# _valid_aid_endpoint_url URL -> exit 0 iff URL is a well-formed
# HTTPS bare-origin AID endpoint. Enforces every property the
# downstream managed CMID inspection client and OTel AID ingest need:
#
#   - HTTPS only. CMID bearer tokens ride in the Authorization header;
#     accepting plaintext http:// would let a misconfigured
#     --override-endpoint (or a hostile env_config.json) exfiltrate
#     enterprise credentials on the wire.
#   - No userinfo (`user@host`, `user:pass@host`). URL userinfo is
#     silently dropped by Go's net/http on some redirect paths and is
#     never the right place to encode auth for the AID endpoint —
#     letting it through opens a credential-in-config leak.
#   - No path, query, fragment. The daemon appends
#     `/api/v1/inspect/defense_claw` and other suffixes itself; an
#     operator-supplied path would double-append (or silently override)
#     the routing. Query/fragment on the endpoint are equally
#     nonsensical.
#   - No whitespace, double quotes, or backslashes. Belt-and-braces so
#     the value can safely land inside a double-quoted YAML scalar in
#     render_config's cisco_ai_defense block.
#   - Optional `:port` on the host (integer only).
#
# Kept as a named helper so callers exercise the same regex regardless
# of whether the URL came from --override-endpoint or the AVC-owned
# env_config.json.
_valid_aid_endpoint_url() {
  local candidate="$1"
  # Reject early on whitespace, quotes, backslashes anywhere.
  case "${candidate}" in
    *[[:space:]]*|*'"'*|*'\'*) return 1 ;;
  esac
  # Bare-origin shape:
  #   https://<host>[:port]
  # <host> = one or more hostname labels (letters, digits, hyphen)
  # separated by dots. No userinfo, no path, no query, no fragment.
  local re='^https://[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:[0-9]+)?$'
  [[ "${candidate}" =~ ${re} ]]
}

# resolve_aid_endpoint OVERRIDE CONFIG_FILE -> stdout effective endpoint
#
# Under the managed_enterprise contract the AI Defense endpoint that
# the daemon inspects against is authored by the AVC module and dropped
# at CONFIG_FILE (default
# /opt/cisco/secureclient/defenseclaw/env_config.json) as a single-
# field JSON document:
#
#   {
#     "cisco_ai_defense_endpoint": "https://us.api.inspect.aidefense.security.cisco.com"
#   }
#
# --override-endpoint is preserved as the release-owned adhoc-testing
# seam (personal preview tenants, sam-aid boxes, etc.) and wins over
# the file. Any trailing slash is stripped for consistent path joining
# — the daemon appends /api/v1/inspect/defense_claw itself.
#
# Return codes let the caller emit a precise per-source error:
#   0 - success (endpoint on stdout)
#   1 - config file missing / unreadable / not a regular file
#   2 - config file present but malformed (bad JSON, missing field,
#       URL failed the regex)
#   3 - override supplied but malformed — invalid --override-endpoint
#
# rc 3 is a new code (the previous version used rc 2 for the override
# case); callers wanting per-flag error messages should key off the
# new numbering.
#
# Kept pure (stdout only, no warn/log) so tests can exercise precedence
# and validation without the AID cloud being reachable.
resolve_aid_endpoint() {
  local override="$1"
  local config_file="$2"
  if [[ -n "${override}" ]]; then
    # Strip a lone trailing slash BEFORE validation so
    # "https://host.example.com/" is accepted (common paste). Any
    # other path component fails the bare-origin regex.
    local stripped="${override%/}"
    _valid_aid_endpoint_url "${stripped}" || return 3
    printf '%s\n' "${stripped}"
    return 0
  fi
  if [[ -z "${config_file}" || ! -f "${config_file}" ]]; then
    return 1
  fi
  local endpoint
  endpoint="$(_read_json_field "${config_file}" "cisco_ai_defense_endpoint")"
  if [[ -z "${endpoint}" ]]; then
    return 2
  fi
  local stripped_cfg="${endpoint%/}"
  _valid_aid_endpoint_url "${stripped_cfg}" || return 2
  printf '%s\n' "${stripped_cfg}"
  return 0
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
# <token>. The endpoint is sourced from the AVC-authored env_config.json
# at /opt/cisco/secureclient/defenseclaw/env_config.json (see the
# --config-file flag on install.sh); --override-endpoint on install.sh
# takes precedence for adhoc testing. See
# internal/gateway/cisco_inspect_defense_claw.go and
# internal/managed/cloudreg for the client-side implementation.
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
# Continuous AI discovery. home_dirs below is refreshed by
# com.cisco.secureclient.defenseclaw.hook-enumerator on every tick from
# the same eligible-user pass that renders hook-guardian/targets.yaml —
# do not hand-edit; changes will be overwritten. Without this list a
# launchd/root-launched daemon walks /var/root only and misses every
# user's per-user data (editor extensions, MCP configs, shell history).
ai_discovery:
  enabled: true
  home_dirs:
    - "__DEFENSECLAW_HOME_DIRS_PLACEHOLDER__"

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

# apply_ai_discovery_home_dirs CONFIG_PATH USER_LINES -> exit 0 on success
#
# Replaces the ai_discovery.home_dirs block in a rendered config.yaml
# with one entry per user home in USER_LINES (newline-delimited
# user:uid:gid:home rows, the same format enumerate_local_users emits).
#
# The initial render_config output contains a single placeholder entry
# under ai_discovery.home_dirs (see `__DEFENSECLAW_HOME_DIRS_PLACEHOLDER__`
# above); on first install the installer calls this helper right after
# render_config so the config that lands on disk already has the right
# list. On every subsequent enumerator tick, render-targets.sh calls
# this helper again with the current user set — same in-place block
# replace, atomic mv-if-changed so callers can no-op when the list
# hasn't moved.
#
# When USER_LINES is empty the block collapses to `home_dirs: []` so
# the Go side falls back to $HOME. That is still wrong on a
# root-launched daemon (leaves discovery blind), so callers should
# treat empty enumeration as a warning; the file remains valid YAML.
#
# Idempotent: two calls with the same input produce the same on-disk
# bytes.
apply_ai_discovery_home_dirs() {
  local config_path="$1"
  local user_lines="$2"

  if [[ ! -f "${config_path}" ]]; then
    printf 'apply_ai_discovery_home_dirs: config not found: %s\n' "${config_path}" >&2
    return 1
  fi

  # Collect homes from user_lines. Skip empty rows so the newline at
  # end of a heredoc-produced list doesn't produce a phantom entry.
  local -a homes=()
  local line home
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    home="${line##*:}"
    [[ -z "${home}" ]] && continue
    homes+=("${home}")
  done <<< "${user_lines}"

  # Build the replacement block. Two-space indent under ai_discovery,
  # four-space indent for list entries — matches render_config's shape.
  local block=""
  if (( ${#homes[@]} == 0 )); then
    block=$'  home_dirs: []\n'
  else
    block=$'  home_dirs:\n'
    for home in "${homes[@]}"; do
      # Quote to survive any home path containing spaces (rare on macOS
      # but real on network-mounted homes). No home path on macOS should
      # contain a literal double-quote, but escape defensively.
      home="${home//\"/\\\"}"
      block+="    - \"${home}\""$'\n'
    done
  fi

  local tmp
  tmp="$(mktemp "${config_path}.hd.XXXXXX")" || return 1
  # Rewrite the ai_discovery block:
  #   - find `ai_discovery:` line
  #   - keep `enabled: true` and any other scalar children
  #   - drop the old home_dirs block (list or scalar or placeholder)
  #   - inject the new block right after the ai_discovery: header
  /usr/bin/python3 - "${config_path}" "${tmp}" "${block}" <<'PY'
import sys, re

src, dst, block = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src, "r", encoding="utf-8") as fh:
    lines = fh.readlines()

out = []
i = 0
n = len(lines)
while i < n:
    line = lines[i]
    if re.match(r'^ai_discovery:\s*$', line):
        out.append(line)
        i += 1
        # Consume the ai_discovery block until we hit a non-indented
        # non-empty line (next top-level key) or EOF. Drop any existing
        # home_dirs entry (list or scalar); keep every other child so
        # operator-added tuning (scan_interval_min, disabled_signature_ids,
        # ...) survives across enumerator passes.
        keep = []
        while i < n:
            child = lines[i]
            if child.strip() == "":
                keep.append(child); i += 1; continue
            # Non-indented (or ends the block) -> stop consuming.
            if not (child.startswith(" ") or child.startswith("\t")):
                break
            # home_dirs: <scalar>  OR  home_dirs:\n followed by "    - …"
            m = re.match(r'^(\s+)home_dirs:\s*(.*)$', child)
            if m:
                indent = m.group(1)
                i += 1
                # If the value was empty, swallow every subsequent line
                # that is more-indented than the home_dirs key itself
                # (list entries / block comments). Deeper-indent check
                # is len(indent)+1 so a sibling key at the same indent
                # correctly terminates the sweep.
                if m.group(2).strip() == "":
                    while i < n:
                        nxt = lines[i]
                        if nxt.strip() == "":
                            i += 1; continue
                        # count leading whitespace
                        stripped = nxt.lstrip()
                        nxt_indent = len(nxt) - len(stripped)
                        if nxt_indent > len(indent):
                            i += 1; continue
                        break
                continue
            keep.append(child); i += 1
        # Inject the fresh home_dirs block first, then re-emit the
        # preserved children so the file reads top-to-bottom naturally.
        out.append(block)
        out.extend(keep)
        continue
    out.append(line)
    i += 1

with open(dst, "w", encoding="utf-8") as fh:
    fh.writelines(out)
PY
  local rc=$?
  if (( rc != 0 )); then
    rm -f -- "${tmp}"
    return "${rc}"
  fi

  # Preserve mode + ownership from the existing config, then atomic-swap
  # only when the content actually changed so downstream reload
  # heuristics that watch mtime aren't triggered on a no-op tick.
  chown --reference="${config_path}" "${tmp}" 2>/dev/null || \
    chown "$(stat -f '%Su:%Sg' "${config_path}")" "${tmp}"
  chmod --reference="${config_path}" "${tmp}" 2>/dev/null || \
    chmod "$(stat -f '%A' "${config_path}")" "${tmp}"

  if cmp -s "${tmp}" "${config_path}"; then
    rm -f -- "${tmp}"
    return 0
  fi
  /bin/mv -f -- "${tmp}" "${config_path}"
}

# ---- legacy path relocation --------------------------------------------

# move_legacy_aside PATH BACKUP_ROOT VERSION [--dry-run] -> exit 0 on success
#
# Moves a legacy DefenseClaw path (e.g. /Library/DefenseClaw from a
# pre-Cisco-path install) aside under BACKUP_ROOT so an idempotent
# managed reinstall can proceed without silent data loss. Emits one
# `[install] ...` log line describing the action taken.
#
# Behavior:
#   - PATH missing / not a symlink target -> no-op, exit 0.
#   - PATH is a real file/dir/symlink -> renamed to
#     BACKUP_ROOT/<basename>.pre-<VERSION>-<TIMESTAMP>.
#   - --dry-run (may appear anywhere in the argv tail) -> logs the
#     intended action without touching disk. Used by tests and by
#     verbose install-log preview modes.
#
# Idempotent by design: two consecutive calls against the same
# already-relocated path both succeed (the second is a no-op).
#
# Kept in the pure-function library so tests can drive it under a
# tmpdir and so both installers (packaging/macos/install.sh and
# packaging/launchd/install-enterprise.sh) share one implementation.
# Callers are responsible for feeding a real absolute PATH; the helper
# does not sanitize input.
move_legacy_aside() {
  local path="$1" backup_root="$2" version="$3"
  shift 3
  local dry_run="false"
  local arg
  for arg in "$@"; do
    case "${arg}" in
      --dry-run) dry_run="true";;
      *) return 2;;
    esac
  done

  if [[ -z "${path}" || -z "${backup_root}" || -z "${version}" ]]; then
    return 2
  fi

  if [[ ! -e "${path}" && ! -L "${path}" ]]; then
    return 0
  fi

  # Reject a symlinked BACKUP_ROOT outright — mv into a symlink
  # target would follow the link and relocate legacy state into
  # whatever the symlink points at. The trust-check on the ancestor
  # chain in install.sh runs before we get here on real installs;
  # this second-line-of-defense guards direct call sites (tests,
  # future callers) that skip the outer check.
  if [[ -L "${backup_root}" ]]; then
    return 4
  fi

  local base timestamp target
  base="$(basename -- "${path}")"
  # No Date.now() here: date is fine (this runs on the operator's
  # machine, not under a fixed-clock replay), and the timestamp is
  # only a disambiguator against a re-run within the same version.
  timestamp="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo "unknown")"
  target="${backup_root}/${base}.pre-${version}-${timestamp}"

  if [[ "${dry_run}" == "true" ]]; then
    printf '[install] would move legacy path aside: %s -> %s\n' "${path}" "${target}"
    return 0
  fi

  # BACKUP_ROOT must exist and be a real directory; on a real install
  # it is created by the caller (LOGS_DIR is a fine landing zone).
  # Missing / non-directory backup_root is a caller bug, not a
  # runtime condition to swallow.
  if [[ ! -d "${backup_root}" ]]; then
    return 3
  fi

  # If the target collides (two-runs-in-one-second edge case), append
  # a short suffix rather than clobbering. Loop bounded to keep the
  # helper trivially terminating.
  local suffix=""
  local i
  for (( i = 0; i < 100; i++ )); do
    if [[ ! -e "${target}${suffix}" && ! -L "${target}${suffix}" ]]; then
      break
    fi
    suffix=".${i}"
  done
  target="${target}${suffix}"

  if ! /bin/mv -- "${path}" "${target}" 2>/dev/null; then
    return 4
  fi
  printf '[install] moved legacy path aside: %s -> %s\n' "${path}" "${target}"
  return 0
}
