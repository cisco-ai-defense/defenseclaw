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
# The hook-guardian LaunchDaemon polls the file it writes here on every
# tick (StartInterval 300), so no signal / restart is needed.

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
        # Any line that is NOT six-space indented (map value) and
        # NOT four-space indented (a map key we already caught) ends
        # the connectors: block.
        if ($0 != "" && $0 !~ /^      / && $0 !~ /^    /) {
          in_connectors = 0
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

connectors_lines="$(extract_connectors || true)"
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
  # Self-heal ownership/mode on the retained manifest so a chown/chmod
  # drift outside our control doesn't survive a no-op render tick.
  chown root:wheel "${MANIFEST_PATH}" 2>/dev/null || true
  chmod 0640 "${MANIFEST_PATH}" 2>/dev/null || true
  exit 0
fi

mv -f "${tmp}" "${MANIFEST_PATH}"
trap - EXIT

log "rendered targets.yaml (users=$(printf '%s\n' "${user_lines}" | grep -c . || true), connectors=${connectors_csv})"

# Keep ai_discovery.home_dirs in lockstep with the manifest we just wrote.
# The discovery service under launchd/root would otherwise walk /var/root
# only and miss every user's editor extensions, MCP configs, and shell
# history. apply_ai_discovery_home_dirs is idempotent + atomic (no-op
# when the resolved home list is unchanged), so this is safe to call on
# every tick.
if apply_ai_discovery_home_dirs "${CONFIG_PATH}" "${user_lines}"; then
  log "refreshed ai_discovery.home_dirs (users=$(printf '%s\n' "${user_lines}" | grep -c . || true))"
else
  warn "failed to refresh ai_discovery.home_dirs in ${CONFIG_PATH}; discovery may miss per-user data until the next tick"
fi
