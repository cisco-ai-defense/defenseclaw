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
import json, os, re, stat, sys

fd = -1
try:
  flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
  fd = os.open(sys.argv[1], flags)
  info = os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 256 * 1024:
    raise OSError("unsafe agent package metadata")
  chunks = []
  remaining = 256 * 1024 + 1
  while remaining > 0:
    chunk = os.read(fd, min(remaining, 64 * 1024))
    if not chunk:
      break
    chunks.append(chunk)
    remaining -= len(chunk)
  payload = b"".join(chunks)
  if len(payload) > 256 * 1024:
    raise OSError("agent package metadata exceeds its size bound")
  value = json.loads(payload).get("version", "")
  if isinstance(value, str) and re.fullmatch(r"[0-9A-Za-z.+_-]{1,128}", value):
    print(value)
except Exception:
  pass
finally:
  if fd >= 0:
    os.close(fd)
' "${path}" 2>/dev/null
}

_read_codex_version_as_user() {
  local user="$1"
  local py
  py="$(command -v python3 || echo /usr/bin/python3)"
  "${py}" -c '
import os
import select
import signal
import subprocess
import sys
import time

user = sys.argv[1]
process = subprocess.Popen(
    ["/usr/bin/sudo", "-n", "-u", user, "codex", "--version"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
output = bytearray()
deadline = time.monotonic() + 5.0
try:
    while len(output) < 512:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, 5.0)
        ready, _, _ = select.select([process.stdout], [], [], remaining)
        if not ready:
            raise subprocess.TimeoutExpired(process.args, 5.0)
        chunk = os.read(process.stdout.fileno(), min(512 - len(output), 4096))
        if not chunk:
            break
        output.extend(chunk)
        if b"\n" in chunk:
            break
finally:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait()
line = bytes(output).splitlines()[0] if output else b""
sys.stdout.buffer.write(line)
' "${user}" 2>/dev/null
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
        vraw="$(_read_codex_version_as_user "${DC_INSTALLER_TARGET_USER}" || true)"
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
# if missing. When a target UID/GID is supplied, creation and ownership are
# applied through already-open directory/file descriptors. This keeps the
# privileged installer from following a connector directory swapped by the
# target user between validation and chown.

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

# create_userspace_config_if_missing DIR NAME [UID GID] -> reads initial bytes
# on stdin.
#
# The installer can run as root while DIR belongs to the target user. Anchor
# the final-component lookup and creation to an already-opened directory file
# descriptor so replacing DIR or NAME with a symlink cannot redirect a
# privileged write. Existing regular files are left untouched.
create_userspace_config_if_missing() {
  local dir="$1"
  local name="$2"
  local uid="${3:-}"
  local gid="${4:-}"
  local py
  py="$(command -v python3 || echo /usr/bin/python3)"
  "${py}" -c '
import os
import re
import stat
import sys

directory, name, uid_raw, gid_raw = sys.argv[1:]
if not name or name in {".", ".."} or os.path.basename(name) != name:
    raise SystemExit("invalid userspace config filename")
if bool(uid_raw) != bool(gid_raw):
    raise SystemExit("userspace config ownership requires both UID and GID")
if uid_raw:
    if re.fullmatch(r"[0-9]+", uid_raw) is None or re.fullmatch(r"[0-9]+", gid_raw) is None:
        raise SystemExit("userspace config UID/GID must be decimal integers")
    target_uid = int(uid_raw, 10)
    target_gid = int(gid_raw, 10)
else:
    target_uid = None
    target_gid = None

payload = sys.stdin.buffer.read(64 * 1024 + 1)
if len(payload) > 64 * 1024:
    raise SystemExit("userspace config template exceeds its size bound")

directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
directory_flags |= getattr(os, "O_NOFOLLOW", 0)
directory_fd = os.open(directory, directory_flags)
created = False
file_fd = -1
file_info = None
try:
    opened_directory = os.fstat(directory_fd)
    if not stat.S_ISDIR(opened_directory.st_mode):
        raise OSError("userspace config parent is not a directory")
    try:
        existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if not stat.S_ISREG(existing.st_mode):
            raise OSError("userspace config path is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(name, flags, dir_fd=directory_fd)
        file_info = os.fstat(file_fd)
        if not stat.S_ISREG(file_info.st_mode) or not os.path.samestat(existing, file_info):
            raise OSError("userspace config changed while being opened")
    else:
        os.fchmod(directory_fd, 0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
        created = True
        view = memoryview(payload)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("short userspace config write")
            view = view[written:]
        os.fchmod(file_fd, 0o600)
        os.fsync(file_fd)
        file_info = os.fstat(file_fd)
        if not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1:
            raise OSError("created userspace config lost regular-file custody")

    if target_uid is not None:
        # Refuse to change ownership through a hard link: changing this inode
        # must affect only the named connector config under our open parent.
        if file_info.st_nlink != 1:
            raise OSError("userspace config must have exactly one link before ownership change")
        os.fchown(file_fd, target_uid, target_gid)
        os.fchown(directory_fd, target_uid, target_gid)
        os.fsync(file_fd)

    named_file = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(named_file.st_mode) or not os.path.samestat(
        os.fstat(file_fd), named_file
    ):
        raise OSError("userspace config changed during preparation")

    current_directory = os.lstat(directory)
    if stat.S_ISLNK(current_directory.st_mode) or not os.path.samestat(
        opened_directory, current_directory
    ):
        raise OSError("userspace config parent changed during creation")
    os.fsync(directory_fd)
except BaseException:
    if created:
        try:
            named_file = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if file_fd >= 0 and os.path.samestat(os.fstat(file_fd), named_file):
                os.unlink(name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        except OSError:
            pass
    raise
finally:
    if file_fd >= 0:
        os.close(file_fd)
    os.close(directory_fd)
' "${dir}" "${name}" "${uid}" "${gid}"
}

prepare_codex_userspace() {
  local home="$1"
  local uid="${2:-}"
  local gid="${3:-}"
  local dir="${home}/.codex"
  local cfg="${home}/.codex/config.toml"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  create_userspace_config_if_missing "${dir}" "config.toml" "${uid}" "${gid}" <<'TOML'
# Created by DefenseClaw installer so the enterprise hook guardian can
# repair this file. Edit freely; DefenseClaw only owns [hooks], [otel],
# and the top-level notify entries.
TOML
}

prepare_claudecode_userspace() {
  local home="$1"
  local uid="${2:-}"
  local gid="${3:-}"
  local dir="${home}/.claude"
  local cfg="${home}/.claude/settings.json"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  printf '{}\n' | create_userspace_config_if_missing "${dir}" "settings.json" "${uid}" "${gid}"
}

prepare_cursor_userspace() {
  local home="$1"
  local uid="${2:-}"
  local gid="${3:-}"
  local dir="${home}/.cursor"
  local cfg="${home}/.cursor/hooks.json"
  ensure_safe_userspace_path "${dir}" "${cfg}" || return 1
  printf '{"version":1,"hooks":{}}\n' | create_userspace_config_if_missing "${dir}" "hooks.json" "${uid}" "${gid}"
}

prepare_userspace_for() {
  local connector="$1"
  local home="$2"
  local uid="${3:-}"
  local gid="${4:-}"
  case "${connector}" in
    codex)      prepare_codex_userspace      "${home}" "${uid}" "${gid}";;
    claudecode) prepare_claudecode_userspace "${home}" "${uid}" "${gid}";;
    cursor)     prepare_cursor_userspace     "${home}" "${uid}" "${gid}";;
  esac
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
# validation seam that lets an operator point the managed daemon at another
# AI Defense origin (e.g. a personal preview tenant) without adding a new
# --env case. The override uses the same bare-origin boundary as the v8 managed
# destination: HTTPS, a non-empty host, an optional valid TCP port, and no
# userinfo, path, query, fragment, whitespace, quote, or backslash. A single
# trailing slash is accepted and stripped for consistent path joining.
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
    # Keep this dependency-free and compatible with the Bash 3.2 shipped by
    # macOS. Validation deliberately happens before root/preflight checks in
    # install.sh so a rejected endpoint cannot mutate an existing host.
    [[ ${#override} -le 2048 ]] || return 2
    [[ "${override}" == https://* ]] || return 2
    [[ ! "${override}" =~ [[:space:]] ]] || return 2
    [[ "${override}" != *'"'* && "${override}" != *"'"* && "${override}" != *'\'* ]] || return 2

    local authority="${override#https://}"
    [[ -n "${authority}" ]] || return 2
    [[ "${authority}" != *'?'* && "${authority}" != *'#'* && "${authority}" != *'@'* ]] || return 2

    # Only the root slash is accepted. Strip it before validating authority;
    # any remaining slash is a source-controlled path and must fail closed.
    if [[ "${authority}" == */ ]]; then
      authority="${authority%/}"
    fi
    [[ -n "${authority}" && "${authority}" != */* ]] || return 2

    local host="" port="" remainder="" colonless="" has_port="false"
    if [[ "${authority}" == \[* ]]; then
      # Bracketed host (normally IPv6). Match net/url's origin shape: require
      # one closing bracket and permit only an optional :port after it.
      [[ "${authority}" == *']'* ]] || return 2
      host="${authority#\[}"
      host="${host%%\]*}"
      remainder="${authority#*\]}"
      [[ -n "${host}" ]] || return 2
      [[ "${host}" =~ ^[0-9A-Fa-f:.]+$ ]] || return 2
      case "${remainder}" in
        "") ;;
        :*) port="${remainder#:}"; has_port="true" ;;
        *) return 2 ;;
      esac
      [[ "${host}" != *'['* && "${host}" != *']'* ]] || return 2
    else
      [[ "${authority}" != *'['* && "${authority}" != *']'* ]] || return 2
      colonless="${authority//:/}"
      # An unbracketed host can contain at most the one host/port separator.
      (( ${#authority} - ${#colonless} <= 1 )) || return 2
      if [[ "${authority}" == *:* ]]; then
        host="${authority%%:*}"
        port="${authority#*:}"
        has_port="true"
      else
        host="${authority}"
      fi
      [[ -n "${host}" ]] || return 2
      [[ "${host}" =~ ^[A-Za-z0-9.-]+$ ]] || return 2
    fi

    if [[ "${has_port}" == "true" ]]; then
      [[ -n "${port}" && "${port}" =~ ^[0-9]+$ ]] || return 2
      # Strip leading zeroes before the arithmetic comparison so Bash does
      # not interpret a value such as 0443 as octal.
      while [[ ${#port} -gt 1 && "${port}" == 0* ]]; do
        port="${port#0}"
      done
      [[ ${#port} -le 5 ]] || return 2
      (( port >= 1 && port <= 65535 )) || return 2
    fi

    printf '%s\n' "${override%/}"
    return 0
  fi
  aid_endpoint_for_env "${env}"
}

# render_config MODE PRIMARY API_PORT SUPPORT_DIR AID_ENDPOINT CONN... -> stdout
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
  local support_dir="$4"
  local aid_endpoint="$5"
  shift 5
  local -a connectors=("$@")
  local runtime_dir="${support_dir}/runtime"

  cat <<EOF
config_version: 8
deployment_mode: managed_enterprise

data_dir: "${runtime_dir}"

observability:
  local:
    path: "${runtime_dir}/audit.db"
    judge_bodies_path: "${runtime_dir}/judge_bodies.db"
  # Managed installs retain the previous secure-by-default behavior. To
  # change redaction, edit this profile (or add per-bucket overrides) and
  # validate the complete v8 source before restarting the daemon.
  defaults:
    redaction_profile: sensitive

gateway:
  api_bind: 127.0.0.1
  api_port: ${api_port}
  # Pin device_key_file into RUNTIME_DIR rather
  # than letting the Go defaults compute it from DEFENSECLAW_HOME. The
  # plist sets DEFENSECLAW_HOME to SUPPORT_DIR so managed_enterprise
  # trust checks accept every ancestor of config.yaml. Keeping mutable
  # runtime state below the dedicated runtime directory also preserves
  # the root-owned managed-install layout.
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

# Continuous AI discovery (endpoint inventory). Enabled in managed_enterprise
# so the sidecar scans for supported connectors and broader "shadow AI" usage
# signals. Observability v8 sends those observations through its canonical
# runtime and configured destinations; the removed v7 emit_otel switch is not
# restored. Other ai_discovery.* keys keep their built-in defaults (mode
# enhanced, scan intervals). The scanner is a no-op unless enabled, so this
# block is required for endpoint inventory to flow.
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
