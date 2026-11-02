#!/usr/bin/env bash
#
# render-targets.sh — regenerate the hook-guardian manifest for every
# eligible local user × configured connector on the machine.
#
# This script is invoked by the com.cisco.secureclient.defenseclaw.hook-enumerator
# LaunchDaemon (RunAtLoad + every 5 min) so that users provisioned after the
# initial pkg install get their hooks wired on the next hook-guardian tick.
#
# Reads:
#   ${SUPPORT_DIR}/etc/config.yaml  — for the connector list
#   dscl . -list /Users             — for the current set of eligible users
#
# Writes:
#   ${SUPPORT_DIR}/hook-guardian/targets.yaml (root:wheel 0640, atomic swap)
#   ${SUPPORT_DIR}/hook-guardian/.enumerator-skips (root:wheel 0600; which
#     users were already reported as skipped, so each is logged once per
#     streak)
#
# The hook-guardian LaunchDaemon is a long-running `enterprise hooks
# watch` process: it holds an fsnotify subscription on the manifest
# path and on every per-user hook artifact, and re-reads the file
# within ~1 s of an atomic replacement. A 60 s periodic backstop
# reconcile covers events fsnotify might miss (WAL replay after
# reboot, symlink swap, watcher errors). No signal / restart is
# needed here — atomic-swap the file and the guardian picks it up.
#
# Nothing here ends in a restart loop. A missing library or config, no
# connectors, or a directory-service failure is logged as
# defenseclaw_degraded and the previous manifest is kept (re-stamped, never
# replaced by an empty one). The only non-zero exits are an unsupported
# platform and not running as root.

set -uo pipefail

SUPPORT_DIR="${SUPPORT_DIR:-/opt/cisco/secureclient/defenseclaw}"
CONFIG_PATH="${DEFENSECLAW_CONFIG:-${SUPPORT_DIR}/etc/config.yaml}"
MANIFEST_DIR="${SUPPORT_DIR}/hook-guardian"
MANIFEST_PATH="${MANIFEST_DIR}/targets.yaml"
SKIP_STATE_PATH="${MANIFEST_DIR}/.enumerator-skips"
LIB_PATH="${SUPPORT_DIR}/lib/installer_lib.sh"

log() { printf '[hook-enumerator] %s\n' "$*"; }
warn() { printf '[hook-enumerator] WARN: %s\n' "$*" >&2; }
die() { printf '[hook-enumerator] ERROR: %s\n' "$*" >&2; exit 1; }

# rt_quote VALUE -> stdout: VALUE in Go strconv.Quote form (with the
# surrounding double quotes). Bytes at or above 0x80 are passed through,
# which matches Go for valid UTF-8.
rt_quote() {
  local s="$1" out="" c code i
  local LC_ALL=C
  for (( i = 0; i < ${#s}; i++ )); do
    c="${s:i:1}"
    case "${c}" in
      '\') out+='\\' ;;
      '"') out+='\"' ;;
      $'\a') out+='\a' ;;
      $'\b') out+='\b' ;;
      $'\f') out+='\f' ;;
      $'\n') out+='\n' ;;
      $'\r') out+='\r' ;;
      $'\t') out+='\t' ;;
      $'\v') out+='\v' ;;
      *)
        printf -v code '%d' "'${c}"
        if (( code >= 0 && code < 32 )) || (( code == 127 )); then
          printf -v c '\\x%02x' "${code}"
        fi
        out+="${c}"
        ;;
    esac
  done
  printf '"%s"' "${out}"
}

# rt_marker MARKER KEY VALUE [KEY VALUE ...] -> stderr
#
# Prints one resilience marker line in exactly the format the Go services
# write (managed.FormatResilienceEvent): `marker key="value" ...`, keys
# sorted, values Go-quoted. stderr is hook-enumerator.err.log.
rt_marker() {
  local marker="$1"; shift
  local -a pairs=()
  while (( $# >= 2 )); do
    pairs+=("$1"$'\t'"$(rt_quote "$2")")
    shift 2
  done
  local line="${marker}" pair sorted
  if (( ${#pairs[@]} > 0 )); then
    sorted="$(printf '%s\n' "${pairs[@]}" | LC_ALL=C sort -t $'\t' -k1,1)"
    while IFS= read -r pair; do
      line+=" ${pair%%$'\t'*}=${pair#*$'\t'}"
    done <<< "${sorted}"
  fi
  printf '%s\n' "${line}" >&2
}

# rt_object_state PATH -> stdout: owner, group, mode, flags and whether an
# ACL is present, read without following a link.
rt_object_state() {
  local path="$1" meta acl="noacl"
  meta="$(stat -f '%u:%g:%Lp:%f' "${path}" 2>/dev/null)" || meta="unreadable"
  # `ls -le` prints each ACL entry on its own numbered line; the `+` after
  # the mode is hidden when the object also carries extended attributes.
  if ls -led "${path}" 2>/dev/null | sed -n '2,$p' | grep -Eq '^ *[0-9]+: '; then
    acl="acl"
  fi
  printf '%s:%s' "${meta}" "${acl}"
}

# rt_move_aside PATH REASON: rename a structurally wrong DefenseClaw object
# aside (a rename never follows a link) so a canonical one can be recreated.
rt_move_aside() {
  local path="$1" reason="$2" moved
  moved="${path}.defenseclaw-moved-$(date -u '+%Y%m%dT%H%M%SZ')"
  if mv -f -- "${path}" "${moved}" 2>/dev/null; then
    rt_marker defenseclaw_boundary action moved_aside moved_to "${moved}" path "${path}" reason "${reason}"
    return 0
  fi
  rt_marker defenseclaw_boundary action moved_aside path "${path}" reason "${reason}" repair_error "rename failed"
  return 1
}

# rt_restamp PATH OWNER MODE: clear write-blocking flags, strip the ACL and
# set owner and mode, never following a link. Logs defenseclaw_repair when
# anything changed. Never fails the run.
rt_restamp() {
  local path="$1" owner="$2" mode="$3" before after errors=""
  before="$(rt_object_state "${path}")"
  chflags -h nouchg,nouappnd "${path}" 2>/dev/null || errors+="chflags "
  if [[ "${before}" == *":acl" ]]; then
    chmod -h -N "${path}" 2>/dev/null || errors+="acl "
  fi
  chown -h "${owner}" "${path}" 2>/dev/null || errors+="chown "
  chmod -h "${mode}" "${path}" 2>/dev/null || errors+="chmod "
  after="$(rt_object_state "${path}")"
  if [[ "${before}" != "${after}" ]]; then
    if [[ -n "${errors}" ]]; then
      rt_marker defenseclaw_repair after "${after}" before "${before}" path "${path}" reason "owner, mode, flag or ACL drift" repair_error "${errors% }"
    else
      rt_marker defenseclaw_repair after "${after}" before "${before}" path "${path}" reason "owner, mode, flag or ACL drift"
    fi
  fi
  return 0
}

# restamp_manifest_dir: the hook-guardian folder is DefenseClaw's. A symlink
# or a non-directory there is moved aside and recreated; the folder is then
# re-stamped root:wheel 0755. Its parent is root-owned, so path operations
# on it cannot be redirected once the link check passed.
restamp_manifest_dir() {
  if [[ -L "${MANIFEST_DIR}" ]]; then
    rt_move_aside "${MANIFEST_DIR}" "hook-guardian folder is a symlink; it is never followed" || return 1
  elif [[ -e "${MANIFEST_DIR}" && ! -d "${MANIFEST_DIR}" ]]; then
    rt_move_aside "${MANIFEST_DIR}" "hook-guardian folder is not a directory" || return 1
  fi
  if [[ ! -d "${MANIFEST_DIR}" ]]; then
    mkdir -p -- "${MANIFEST_DIR}" 2>/dev/null || {
      rt_marker defenseclaw_degraded component hook-enumerator path "${MANIFEST_DIR}" reason "cannot create the hook-guardian folder"
      return 1
    }
  fi
  rt_restamp "${MANIFEST_DIR}" "${RT_OWNER}" 0755
}

# restamp_manifest_file: targets.yaml is re-stamped on every run, even when
# its content is unchanged. A symlink or non-file is moved aside; a
# hard-linked file is replaced by a copy (a new inode), so the other link is
# never written through.
restamp_manifest_file() {
  [[ -e "${MANIFEST_PATH}" || -L "${MANIFEST_PATH}" ]] || return 0
  if [[ -L "${MANIFEST_PATH}" ]]; then
    rt_move_aside "${MANIFEST_PATH}" "targets.yaml is a symlink; it is never followed"
    return 0
  fi
  if [[ ! -f "${MANIFEST_PATH}" ]]; then
    rt_move_aside "${MANIFEST_PATH}" "targets.yaml is not a regular file"
    return 0
  fi
  local links
  links="$(stat -f '%l' "${MANIFEST_PATH}" 2>/dev/null || echo 1)"
  if [[ "${links}" =~ ^[0-9]+$ ]] && (( links > 1 )); then
    local copy
    copy="$(mktemp "${MANIFEST_PATH}.new.XXXXXX" 2>/dev/null)" || return 0
    if cat -- "${MANIFEST_PATH}" > "${copy}" 2>/dev/null && mv -f -- "${copy}" "${MANIFEST_PATH}" 2>/dev/null; then
      rt_marker defenseclaw_boundary action replaced path "${MANIFEST_PATH}" reason "targets.yaml had ${links} hard links; replaced by a new file"
    else
      rm -f -- "${copy}" 2>/dev/null
    fi
  fi
  rt_restamp "${MANIFEST_PATH}" "${RT_OWNER}" 0640
}

# degraded REASON PATH: keep the previous manifest (re-stamped), log once per
# run and exit 0, so launchd never sees a restart loop.
degraded() {
  rt_marker defenseclaw_degraded component hook-enumerator path "$2" reason "$1"
  restamp_manifest_dir && restamp_manifest_file
  exit 0
}

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only (uname -s != Darwin)"
if [[ "${DC_ENUMERATOR_TEST_UNPRIVILEGED:-}" == "1" ]]; then
  RT_OWNER="$(id -u):$(id -g)"
else
  [[ $EUID -eq 0 ]] || die "must run as root"
  RT_OWNER="root:wheel"
fi

[[ -f "${LIB_PATH}" ]] || degraded "installer library missing; previous manifest kept" "${LIB_PATH}"
[[ -f "${CONFIG_PATH}" ]] || degraded "config missing; previous manifest kept" "${CONFIG_PATH}"

# shellcheck source=/dev/null
. "${LIB_PATH}" || degraded "installer library failed to load; previous manifest kept" "${LIB_PATH}"

# Parse connector list out of the rendered config.yaml. The installer
# renders `guardrail.connector: <primary>` and optionally a
# `guardrail.connectors:` map with per-connector entries. Prefer the map
# when present; fall back to the primary. Keep this tiny and side-effect
# free — Python is available on every macOS box we ship to.
extract_connectors() {
  # Regex-only scanner over the shape render_config emits. Uses awk
  # (macOS base image, no CLT / interpreter dependency) rather than
  # `/usr/bin/python3` — the QA regression on stock macOS is that
  # `[ -x /usr/bin/python3 ]` passes but the stub fails to launch
  # without Xcode Command Line Tools. render_config's output is stable
  # and simple enough (two-space indent, keys on their own lines) that
  # a regex scan is more portable than a YAML library dependency.
  #
  # render_config emits BOTH:
  #   guardrail:
  #     connector: <primary>              <-- the single-scalar form
  #     connectors:                       <-- the multi-connector map
  #       amp:
  #       codex:
  #       claudecode:
  #       cursor:
  # So we prefer the map when present (returns every connector) and fall
  # back to the scalar (primary only) when the map is absent. Duplicates
  # are dropped preserving first-seen order.
  awk '
    BEGIN {
      in_guardrail = 0
      in_connectors = 0
      primary = ""
      n_map = 0
      # seen[] tracks first-seen dedupe order across BOTH sources so
      # a future edit to render_config that lists the primary under
      # both forms produces exactly one output line.
    }
    /^guardrail:[ \t]*$/ {
      in_guardrail = 1
      in_connectors = 0
      next
    }
    {
      if (in_guardrail && $0 != "" && substr($0, 1, 1) != " " && substr($0, 1, 1) != "\t") {
        # Left the guardrail block.
        in_guardrail = 0
        in_connectors = 0
      }
      if (!in_guardrail) next
      # Clear in_connectors BEFORE the dispatch below when a sibling
      # key at the connectors-parent depth ends the map block, so the
      # terminating line still gets a chance to match the
      # `  connector: <primary>` scalar branch. The prior placement
      # (at the tail of the else-branch) consumed that line inside the
      # block-exit and would have lost the primary if render_config
      # ever emitted `connectors:` (empty) before `connector:`.
      # Purely defensive — the current emitter order is stable — but
      # it makes the scanner robust to a future config-generation
      # reordering that would otherwise silently drop the primary.
      if (in_connectors && $0 != "" && $0 !~ /^      / && $0 !~ /^    /) {
        in_connectors = 0
      }
      if (!in_connectors) {
        if ($0 ~ /^  connectors:[ \t]*$/) {
          in_connectors = 1
          next
        }
        if ($0 ~ /^  connector:[ \t]+[^ \t]+[ \t]*$/) {
          if (primary == "") {
            # Extract the value after the colon.
            line = $0
            sub(/^  connector:[ \t]+/, "", line)
            sub(/[ \t]+$/, "", line)
            primary = line
          }
          next
        }
      } else {
        if ($0 ~ /^    [a-z0-9][a-z0-9_-]*:[ \t]*$/) {
          line = $0
          sub(/^    /, "", line)
          sub(/:[ \t]*$/, "", line)
          n_map++
          mapc[n_map] = line
          next
        }
      }
    }
    END {
      # Prefer the map when non-empty; fall back to the scalar.
      if (n_map > 0) {
        for (i = 1; i <= n_map; i++) {
          v = mapc[i]
          if (v == "" || v in seen) continue
          seen[v] = 1
          print v
        }
      } else if (primary != "") {
        print primary
      }
    }
  ' "${CONFIG_PATH}"
}

# classify_dropped_user NAME -> stdout: why enumerate_local_users left a
# local account out, or nothing when it looks eligible (which means the
# enumeration itself was inconsistent).
classify_dropped_user() {
  local name="$1" home
  home="$(dscl . -read "/Users/${name}" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')"
  if [[ -z "${home}" ]]; then
    printf 'home_missing\t'
    return 0
  fi
  if [[ "${home}" != /Users/* ]]; then
    printf 'home_outside_users\t%s' "${home}"
  elif [[ -L "${home}" ]]; then
    printf 'home_symlink\t%s' "${home}"
  elif [[ ! -d "${home}" ]]; then
    printf 'home_not_directory\t%s' "${home}"
  elif ! home_perms_ok "${home}"; then
    printf 'home_group_writable\t%s' "${home}"
  fi
}

# report_skips SKIPS: one defenseclaw_skip line per user and reason per
# streak. SKIPS is newline-separated `name<TAB>reason<TAB>path`. The set
# reported last run is kept in SKIP_STATE_PATH; a user is reported again
# only after a run in which it was not skipped for that reason.
report_skips() {
  local skips="$1" previous="" line name rest reason path state_tmp
  if [[ -f "${SKIP_STATE_PATH}" && ! -L "${SKIP_STATE_PATH}" ]]; then
    previous="$(cat -- "${SKIP_STATE_PATH}" 2>/dev/null || true)"
  fi
  local current=""
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    name="${line%%$'\t'*}"
    rest="${line#*$'\t'}"
    reason="${rest%%$'\t'*}"
    path="${rest#*$'\t'}"
    current+="${name}"$'\t'"${reason}"$'\n'
    if ! printf '%s\n' "${previous}" | grep -Fxq -- "${name}"$'\t'"${reason}"; then
      rt_marker defenseclaw_skip path "${path}" reason "${reason}" unit "user:${name}"
    fi
  done <<< "${skips}"
  if [[ -L "${SKIP_STATE_PATH}" || ( -e "${SKIP_STATE_PATH}" && ! -f "${SKIP_STATE_PATH}" ) ]]; then
    rt_move_aside "${SKIP_STATE_PATH}" "enumerator skip state is not a regular file" || return 0
  fi
  state_tmp="$(mktemp "${SKIP_STATE_PATH}.new.XXXXXX" 2>/dev/null)" || return 0
  printf '%s' "${current}" > "${state_tmp}" 2>/dev/null
  chown -h "${RT_OWNER}" "${state_tmp}" 2>/dev/null
  chmod -h 0600 "${state_tmp}" 2>/dev/null
  mv -f -- "${state_tmp}" "${SKIP_STATE_PATH}" 2>/dev/null || rm -f -- "${state_tmp}" 2>/dev/null
  return 0
}

connectors_lines="$(extract_connectors 2>/dev/null || true)"
if [[ -z "${connectors_lines}" ]]; then
  degraded "no connectors resolvable from the config; previous manifest kept" "${CONFIG_PATH}"
fi
connectors_csv="$(printf '%s\n' "${connectors_lines}" | paste -sd, -)"

# Tell a directory-service failure apart from "no users": the local node
# always lists system accounts, so a failed or empty listing keeps the
# previous manifest instead of publishing an empty one that would drop
# every user.
dscl_listing="$(dscl . -list /Users UniqueID 2>/dev/null)"
dscl_rc=$?
if (( dscl_rc != 0 )) || [[ -z "${dscl_listing//[[:space:]]/}" ]]; then
  degraded "opendirectory_unavailable: dscl . -list /Users failed (rc=${dscl_rc}); previous manifest kept" "${MANIFEST_PATH}"
fi

# Enumerate eligible local users right now.
user_lines="$(DC_INSTALLER_ENUMERATE_VERBOSE=0 enumerate_local_users 2>/dev/null || true)"

# Every local account the filter dropped gets a reason. A candidate that
# looks eligible but was not enumerated means the enumeration raced a
# directory-service failure: keep the previous manifest.
skips=""
inconsistent=""
while IFS= read -r row; do
  cand_name="$(printf '%s' "${row}" | awk '{print $1}')"
  cand_uid="$(printf '%s' "${row}" | awk '{print $2}')"
  [[ -n "${cand_name}" && "${cand_uid}" =~ ^[0-9]+$ ]] || continue
  case "${cand_name}" in _*|daemon|nobody|root) continue;; esac
  (( cand_uid >= 500 )) || continue
  if printf '%s\n' "${user_lines}" | cut -d: -f1 | grep -Fxq -- "${cand_name}"; then
    continue
  fi
  verdict="$(classify_dropped_user "${cand_name}")"
  if [[ -z "${verdict}" ]]; then
    inconsistent="${cand_name}"
    continue
  fi
  skips+="${cand_name}"$'\t'"${verdict}"$'\n'
done <<< "${dscl_listing}"

if [[ -n "${inconsistent}" ]]; then
  degraded "opendirectory_unavailable: eligible user ${inconsistent} was not enumerated; previous manifest kept" "${MANIFEST_PATH}"
fi

# The console user is reported when it is not in the local directory node
# (a network-only account): it runs agents but cannot be enrolled.
console_user="${DC_ENUMERATOR_CONSOLE_USER-$(stat -f '%Su' /dev/console 2>/dev/null || true)}"
case "${console_user}" in
  ""|root|_*|loginwindow) ;;
  *)
    if ! printf '%s\n' "${dscl_listing}" | awk '{print $1}' | grep -Fxq -- "${console_user}"; then
      skips+="${console_user}"$'\t'"not_local_account"$'\t'$'\n'
    fi
    ;;
esac

restamp_manifest_dir || degraded "hook-guardian folder could not be prepared" "${MANIFEST_DIR}"
report_skips "${skips}"

tmp="$(mktemp "${MANIFEST_PATH}.new.XXXXXX" 2>/dev/null)" || degraded "cannot create a temporary manifest" "${MANIFEST_DIR}"
trap 'rm -f -- "${tmp}"' EXIT

if ! render_targets_manifest "${SUPPORT_DIR}" "${connectors_csv}" "${user_lines}" > "${tmp}"; then
  degraded "manifest render failed; previous manifest kept" "${MANIFEST_PATH}"
fi

chown -h "${RT_OWNER}" "${tmp}" 2>/dev/null
chmod -h 0640 "${tmp}" 2>/dev/null

# Atomic replace via mv-if-content-differs. If the manifest is unchanged,
# leave the on-disk mtime alone so the guardian's next tick doesn't
# reconcile identical rows unnecessarily, but re-stamp its owner, mode,
# flags and ACL so drift on an unchanged file still heals.
if [[ -f "${MANIFEST_PATH}" && ! -L "${MANIFEST_PATH}" ]] && cmp -s "${tmp}" "${MANIFEST_PATH}"; then
  restamp_manifest_file
  log "targets.yaml unchanged (users=$(printf '%s\n' "${user_lines}" | grep -c . || true))"
  exit 0
fi

if [[ -L "${MANIFEST_PATH}" || ( -e "${MANIFEST_PATH}" && ! -f "${MANIFEST_PATH}" ) ]]; then
  restamp_manifest_file
fi
chflags -h nouchg,nouappnd "${MANIFEST_PATH}" 2>/dev/null
if ! mv -f -- "${tmp}" "${MANIFEST_PATH}" 2>/dev/null; then
  degraded "cannot publish targets.yaml; previous manifest kept" "${MANIFEST_PATH}"
fi
trap - EXIT
restamp_manifest_file

log "rendered targets.yaml (users=$(printf '%s\n' "${user_lines}" | grep -c . || true), connectors=${connectors_csv})"
exit 0
