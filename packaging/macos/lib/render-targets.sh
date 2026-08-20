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
#
# The hook-guardian LaunchDaemon is a long-running `enterprise hooks
# watch` process: it holds an fsnotify subscription on the manifest
# path and on every per-user hook artifact, and re-reads the file
# within ~1 s of an atomic replacement. A 60 s periodic backstop
# reconcile covers events fsnotify might miss (WAL replay after
# reboot, symlink swap, watcher errors). No signal / restart is
# needed here — atomic-swap the file and the guardian picks it up.

set -euo pipefail

SUPPORT_DIR="${SUPPORT_DIR:-/opt/cisco/secureclient/defenseclaw}"
CONFIG_PATH="${DEFENSECLAW_CONFIG:-${SUPPORT_DIR}/etc/config.yaml}"
MANIFEST_DIR="${SUPPORT_DIR}/hook-guardian"
MANIFEST_PATH="${MANIFEST_DIR}/targets.yaml"
LIB_PATH="${SUPPORT_DIR}/lib/installer_lib.sh"

log() { printf '[hook-enumerator] %s\n' "$*"; }
warn() { printf '[hook-enumerator] WARN: %s\n' "$*" >&2; }
die() { printf '[hook-enumerator] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only (uname -s != Darwin)"
[[ $EUID -eq 0 ]] || die "must run as root"

[[ -f "${LIB_PATH}" ]] || die "installer library missing: ${LIB_PATH}"
[[ -f "${CONFIG_PATH}" ]] || die "config missing: ${CONFIG_PATH}"

# shellcheck source=/dev/null
. "${LIB_PATH}"

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

connectors_lines="$(extract_connectors 2>/dev/null || true)"
if [[ -z "${connectors_lines}" ]]; then
  die "no connectors resolvable from ${CONFIG_PATH}"
fi
connectors_csv="$(printf '%s\n' "${connectors_lines}" | paste -sd, -)"

# Enumerate eligible local users right now.
user_lines="$(enumerate_local_users || true)"

# Render the manifest. Even when user_lines is empty we still produce a
# valid `version: 1` + `targets:` document so the guardian's LoadManifest
# does not error out.
mkdir -p "${MANIFEST_DIR}"
chown root:wheel "${MANIFEST_DIR}"
chmod 0755 "${MANIFEST_DIR}"

tmp="$(mktemp "${MANIFEST_PATH}.new.XXXXXX")"
trap 'rm -f -- "${tmp}"' EXIT

render_targets_manifest "${SUPPORT_DIR}" "${connectors_csv}" "${user_lines}" > "${tmp}"

chown root:wheel "${tmp}"
chmod 0640 "${tmp}"

# Atomic replace via mv-if-content-differs. If the manifest is unchanged,
# leave the on-disk mtime alone so the guardian's next tick doesn't
# reconcile identical rows unnecessarily.
if [[ -f "${MANIFEST_PATH}" ]] && cmp -s "${tmp}" "${MANIFEST_PATH}"; then
  log "targets.yaml unchanged (users=$(printf '%s\n' "${user_lines}" | grep -c . || true))"
  exit 0
fi

mv -f "${tmp}" "${MANIFEST_PATH}"
trap - EXIT

log "rendered targets.yaml (users=$(printf '%s\n' "${user_lines}" | grep -c . || true), connectors=${connectors_csv})"
