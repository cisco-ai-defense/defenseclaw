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
  # Regex-only scanner over the shape render_config emits. Deliberately
  # avoids importing PyYAML: it isn't part of macOS's system Python and
  # is often installed only in a user's Library/Python/*/site-packages,
  # invisible to a root-launched daemon. render_config's output is stable
  # and simple enough (two-space indent, keys on their own lines) that a
  # regex scan is more portable than a YAML dependency.
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
  /usr/bin/python3 - "${CONFIG_PATH}" <<'PY'
import re, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()

primary = None
connectors_map = []
in_guardrail = False
in_connectors = False
for line in text.splitlines():
    if re.match(r"^guardrail:\s*$", line):
        in_guardrail = True
        in_connectors = False
        continue
    if in_guardrail and line and not line.startswith(" "):
        # Left the guardrail: block.
        in_guardrail = False
        in_connectors = False
        continue
    if not in_guardrail:
        continue
    if not in_connectors:
        if re.match(r"^  connectors:\s*$", line):
            in_connectors = True
            continue
        m = re.match(r"^  connector:\s*(\S+)\s*$", line)
        if m and primary is None:
            primary = m.group(1)
    else:
        m = re.match(r"^    ([a-z0-9][a-z0-9_-]*):\s*$", line)
        if m:
            connectors_map.append(m.group(1))
            continue
        if line and not line.startswith("      ") and not line.startswith("    "):
            in_connectors = False

# Prefer the map when populated; fall back to the primary scalar.
result = connectors_map if connectors_map else ([primary] if primary else [])
# Dedupe preserving first-seen order (defence-in-depth against future edits
# to render_config that might list the same connector under both forms).
seen = set()
deduped = []
for c in result:
    if c and c not in seen:
        seen.add(c)
        deduped.append(c)
for c in deduped:
    print(c)
PY
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
